/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/** \file
 *
 * \brief Example plugin that hooks into the flow lifecycle and publishes
 *        a live flow snapshot over a Unix stream socket.
 *
 * The socket protocol is newline-delimited JSON. Each line is a complete
 * snapshot containing aggregate counters and all currently active flows.
 */

#include "suricata-common.h"
#include "suricata-plugin.h"

#include "flow-callbacks.h"
#include "flow-storage.h"
#include "app-layer-protos.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-proto-name.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define FLOWTOP_DEFAULT_SOCKET "/tmp/suricata-flowtop.sock"
#define FLOWTOP_SOCKET_ENV "SURICATA_FLOWTOP_SOCKET"
#define FLOWTOP_PUBLISH_INTERVAL_USEC 1000000
#define FLOWTOP_INITIAL_BUFFER_SIZE 65536

static SCFlowStorageId flowtop_storage_id = { .id = -1 };
static SCMutex flowtop_lock = SCMUTEX_INITIALIZER;

static char flowtop_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = FLOWTOP_DEFAULT_SOCKET;
static uint64_t flowtop_total_flows = 0;
static uint64_t flowtop_closed_flows = 0;
static uint64_t flowtop_active_flows = 0;
static uint64_t flowtop_total_bytes = 0;

struct FlowtopFlow {
    uint64_t id;
    char src_ip[46];
    char dest_ip[46];
    uint16_t src_port;
    uint16_t dest_port;
    char proto[8];
    char app_proto[64];
    uint8_t ip_version;

    uint64_t start_ms;
    uint64_t last_seen_ms;
    uint32_t pkts_toserver;
    uint32_t pkts_toclient;
    uint64_t bytes_toserver;
    uint64_t bytes_toclient;
    uint64_t bps;

    uint64_t rate_bytes;
    uint64_t rate_ms;

    struct FlowtopFlow *prev;
    struct FlowtopFlow *next;
};

static struct FlowtopFlow *flowtop_flows = NULL;

struct FlowtopBuffer {
    char *data;
    size_t len;
    size_t cap;
};

static uint64_t FlowtopTimeMs(const SCTime_t ts)
{
    return ((uint64_t)SCTIME_SECS(ts) * 1000) + ((uint64_t)SCTIME_USECS(ts) / 1000);
}

static uint64_t FlowtopWallTimeMs(void)
{
    return FlowtopTimeMs(TimeGet());
}

static void FlowtopListRemove(struct FlowtopFlow *ctx)
{
    if (ctx->prev != NULL)
        ctx->prev->next = ctx->next;
    else
        flowtop_flows = ctx->next;

    if (ctx->next != NULL)
        ctx->next->prev = ctx->prev;

    ctx->prev = NULL;
    ctx->next = NULL;
}

static void FlowtopFlowStorageFree(void *ptr)
{
    struct FlowtopFlow *ctx = ptr;
    if (ctx == NULL)
        return;

    SCMutexLock(&flowtop_lock);
    FlowtopListRemove(ctx);
    if (flowtop_active_flows > 0)
        flowtop_active_flows--;
    flowtop_closed_flows++;
    SCMutexUnlock(&flowtop_lock);

    SCFree(ctx);
}

static void FlowtopSetProto(char *dst, size_t dst_len, uint8_t proto)
{
    if (SCProtoNameValid(proto)) {
        strlcpy(dst, known_proto[proto], dst_len);
    } else {
        snprintf(dst, dst_len, "%" PRIu8, proto);
    }
}

static void FlowtopSetAppProto(struct FlowtopFlow *ctx, const Flow *f)
{
    const char *app_proto = AppProtoToString(f->alproto);
    if (app_proto == NULL || app_proto[0] == '\0')
        app_proto = "unknown";
    strlcpy(ctx->app_proto, app_proto, sizeof(ctx->app_proto));
}

static void FlowtopSetTuple(struct FlowtopFlow *ctx, const Flow *f)
{
    const FlowAddress *src = &f->src;
    const FlowAddress *dst = &f->dst;
    Port sp = f->sp;
    Port dp = f->dp;

    if ((f->flags & FLOW_DIR_REVERSED) != 0) {
        src = &f->dst;
        dst = &f->src;
        sp = f->dp;
        dp = f->sp;
    }

    if (FLOW_IS_IPV4(f)) {
        (void)PrintInet(AF_INET, &src->addr_data32[0], ctx->src_ip, sizeof(ctx->src_ip));
        (void)PrintInet(AF_INET, &dst->addr_data32[0], ctx->dest_ip, sizeof(ctx->dest_ip));
        ctx->ip_version = 4;
    } else if (FLOW_IS_IPV6(f)) {
        (void)PrintInetIPv6(&src->address, ctx->src_ip, sizeof(ctx->src_ip), true);
        (void)PrintInetIPv6(&dst->address, ctx->dest_ip, sizeof(ctx->dest_ip), true);
        ctx->ip_version = 6;
    } else {
        strlcpy(ctx->src_ip, "unknown", sizeof(ctx->src_ip));
        strlcpy(ctx->dest_ip, "unknown", sizeof(ctx->dest_ip));
        ctx->ip_version = 0;
    }

    switch (f->proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            ctx->src_port = sp;
            ctx->dest_port = dp;
            break;
        default:
            ctx->src_port = 0;
            ctx->dest_port = 0;
            break;
    }

    FlowtopSetProto(ctx->proto, sizeof(ctx->proto), f->proto);
    FlowtopSetAppProto(ctx, f);
}

static inline struct FlowtopFlow *FlowtopGetFlowContext(const Flow *f)
{
    if (unlikely(f == NULL || flowtop_storage_id.id < 0 || f->storage == NULL))
        return NULL;
    return SCFlowGetStorageById(f, flowtop_storage_id);
}

static void FlowtopOnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *user)
{
    (void)tv;
    (void)p;
    (void)user;

    if (unlikely(f == NULL || f->storage == NULL))
        return;

    struct FlowtopFlow *ctx = SCCalloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return;

    ctx->id = FlowGetId(f);
    ctx->start_ms = FlowtopTimeMs(f->startts);
    ctx->last_seen_ms = ctx->start_ms;
    FlowtopSetTuple(ctx, f);

    SCMutexLock(&flowtop_lock);
    ctx->next = flowtop_flows;
    if (flowtop_flows != NULL)
        flowtop_flows->prev = ctx;
    flowtop_flows = ctx;
    flowtop_total_flows++;
    flowtop_active_flows++;
    SCMutexUnlock(&flowtop_lock);

    SCFlowSetStorageById(f, flowtop_storage_id, ctx);
}

static void FlowtopOnFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *user)
{
    (void)tv;
    (void)user;

    if (unlikely(f == NULL || p == NULL))
        return;
    if (p->proto != f->proto)
        return;

    struct FlowtopFlow *ctx = FlowtopGetFlowContext(f);
    if (ctx == NULL)
        return;

    const uint64_t now_ms = FlowtopTimeMs(p->ts);
    const uint64_t bytes = f->todstbytecnt + f->tosrcbytecnt;

    SCMutexLock(&flowtop_lock);
    const uint64_t old_bytes = ctx->bytes_toserver + ctx->bytes_toclient;

    ctx->last_seen_ms = now_ms;
    ctx->pkts_toserver = f->todstpktcnt;
    ctx->pkts_toclient = f->tosrcpktcnt;
    ctx->bytes_toserver = f->todstbytecnt;
    ctx->bytes_toclient = f->tosrcbytecnt;
    FlowtopSetAppProto(ctx, f);

    if (ctx->rate_ms == 0) {
        ctx->rate_ms = now_ms;
        ctx->rate_bytes = bytes;
    } else if (now_ms > ctx->rate_ms && now_ms - ctx->rate_ms >= 500) {
        const uint64_t delta_ms = now_ms - ctx->rate_ms;
        const uint64_t delta_bytes = bytes - ctx->rate_bytes;
        ctx->bps = (delta_bytes * 8000) / delta_ms;
        ctx->rate_ms = now_ms;
        ctx->rate_bytes = bytes;
    }

    if (bytes > old_bytes)
        flowtop_total_bytes += bytes - old_bytes;
    SCMutexUnlock(&flowtop_lock);
}

static void FlowtopOnFlowFinish(ThreadVars *tv, Flow *f, void *user)
{
    (void)tv;
    (void)user;

    struct FlowtopFlow *ctx = FlowtopGetFlowContext(f);
    if (ctx == NULL)
        return;

    SCMutexLock(&flowtop_lock);
    FlowtopListRemove(ctx);
    if (flowtop_active_flows > 0)
        flowtop_active_flows--;
    flowtop_closed_flows++;
    SCMutexUnlock(&flowtop_lock);

    SCFlowSetStorageById(f, flowtop_storage_id, NULL);
    SCFree(ctx);
}

static bool FlowtopBufferInit(struct FlowtopBuffer *buf)
{
    buf->data = SCMalloc(FLOWTOP_INITIAL_BUFFER_SIZE);
    if (buf->data == NULL)
        return false;
    buf->len = 0;
    buf->cap = FLOWTOP_INITIAL_BUFFER_SIZE;
    buf->data[0] = '\0';
    return true;
}

static bool FlowtopBufferReserve(struct FlowtopBuffer *buf, size_t needed)
{
    if (needed <= buf->cap)
        return true;

    size_t new_cap = buf->cap;
    while (new_cap < needed)
        new_cap *= 2;

    char *new_data = SCRealloc(buf->data, new_cap);
    if (new_data == NULL)
        return false;

    buf->data = new_data;
    buf->cap = new_cap;
    return true;
}

static bool FlowtopBufferAppend(struct FlowtopBuffer *buf, const char *fmt, ...)
{
    while (true) {
        va_list ap;
        va_start(ap, fmt);
        const int written = vsnprintf(buf->data + buf->len, buf->cap - buf->len, fmt, ap);
        va_end(ap);

        if (written < 0)
            return false;

        const size_t needed = buf->len + (size_t)written + 1;
        if (needed <= buf->cap) {
            buf->len += (size_t)written;
            return true;
        }

        if (!FlowtopBufferReserve(buf, needed))
            return false;
    }
}

static void FlowtopBufferFree(struct FlowtopBuffer *buf)
{
    if (buf->data != NULL)
        SCFree(buf->data);
    memset(buf, 0, sizeof(*buf));
}

static struct FlowtopBuffer FlowtopBuildSnapshot(void)
{
    struct FlowtopBuffer buf = { 0 };
    if (!FlowtopBufferInit(&buf))
        return buf;

    const uint64_t now_ms = FlowtopWallTimeMs();
    uint64_t total_bps = 0;

    SCMutexLock(&flowtop_lock);
    for (const struct FlowtopFlow *ctx = flowtop_flows; ctx != NULL; ctx = ctx->next) {
        total_bps += ctx->bps;
    }

    if (!FlowtopBufferAppend(&buf,
                "{\"type\":\"flowtop\",\"version\":1,\"timestamp_ms\":%" PRIu64
                ",\"active_flows\":%" PRIu64 ",\"total_flows\":%" PRIu64
                ",\"closed_flows\":%" PRIu64 ",\"total_bytes\":%" PRIu64
                ",\"total_bps\":%" PRIu64 ",\"flows\":[",
                now_ms, flowtop_active_flows, flowtop_total_flows, flowtop_closed_flows,
                flowtop_total_bytes, total_bps)) {
        SCMutexUnlock(&flowtop_lock);
        FlowtopBufferFree(&buf);
        return buf;
    }

    bool first = true;
    for (const struct FlowtopFlow *ctx = flowtop_flows; ctx != NULL; ctx = ctx->next) {
        const uint64_t bytes = ctx->bytes_toserver + ctx->bytes_toclient;
        const uint64_t pkts = ctx->pkts_toserver + ctx->pkts_toclient;
        const uint64_t age_ms = now_ms > ctx->start_ms ? now_ms - ctx->start_ms : 0;

        if (!FlowtopBufferAppend(&buf,
                    "%s{\"id\":%" PRIu64 ",\"src_ip\":\"%s\",\"dest_ip\":\"%s\""
                    ",\"src_port\":%" PRIu16 ",\"dest_port\":%" PRIu16
                    ",\"proto\":\"%s\",\"app_proto\":\"%s\",\"ip_version\":%" PRIu8
                    ",\"pkts_toserver\":%" PRIu32 ",\"pkts_toclient\":%" PRIu32
                    ",\"packets\":%" PRIu64 ",\"bytes_toserver\":%" PRIu64
                    ",\"bytes_toclient\":%" PRIu64 ",\"bytes\":%" PRIu64
                    ",\"bps\":%" PRIu64 ",\"age_ms\":%" PRIu64
                    ",\"last_seen_ms\":%" PRIu64 "}",
                    first ? "" : ",", ctx->id, ctx->src_ip, ctx->dest_ip, ctx->src_port,
                    ctx->dest_port, ctx->proto, ctx->app_proto, ctx->ip_version, ctx->pkts_toserver,
                    ctx->pkts_toclient, pkts, ctx->bytes_toserver, ctx->bytes_toclient, bytes,
                    ctx->bps, age_ms, ctx->last_seen_ms)) {
            SCMutexUnlock(&flowtop_lock);
            FlowtopBufferFree(&buf);
            return buf;
        }
        first = false;
    }
    SCMutexUnlock(&flowtop_lock);

    if (!FlowtopBufferAppend(&buf, "]}\n"))
        FlowtopBufferFree(&buf);

    return buf;
}

static bool FlowtopSendAll(int fd, const char *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
#ifdef MSG_NOSIGNAL
        const ssize_t written = send(fd, data + offset, len - offset, MSG_NOSIGNAL);
#else
        const ssize_t written = send(fd, data + offset, len - offset, 0);
#endif
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (written == 0)
            return false;
        offset += (size_t)written;
    }
    return true;
}

static void FlowtopServeClient(int client_fd)
{
    while (true) {
        struct FlowtopBuffer snapshot = FlowtopBuildSnapshot();
        if (snapshot.data == NULL)
            break;

        const bool ok = FlowtopSendAll(client_fd, snapshot.data, snapshot.len);
        FlowtopBufferFree(&snapshot);
        if (!ok)
            break;

        usleep(FLOWTOP_PUBLISH_INTERVAL_USEC);
    }
}

static int FlowtopCreateServerSocket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        SCLogError("flowtop: failed to create Unix socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, flowtop_socket_path, sizeof(addr.sun_path));

    (void)unlink(flowtop_socket_path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        SCLogError("flowtop: bind(%s) failed: %s", flowtop_socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    (void)chmod(flowtop_socket_path, 0660);

    if (listen(fd, 8) < 0) {
        SCLogError("flowtop: listen(%s) failed: %s", flowtop_socket_path, strerror(errno));
        close(fd);
        (void)unlink(flowtop_socket_path);
        return -1;
    }

    return fd;
}

static void *FlowtopSocketThread(void *arg)
{
    (void)arg;

    const int server_fd = FlowtopCreateServerSocket();
    if (server_fd < 0)
        return NULL;

    SCLogInfo("flowtop: publishing flow snapshots on %s", flowtop_socket_path);

    while (true) {
        const int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            SCLogError("flowtop: accept failed: %s", strerror(errno));
            break;
        }

        FlowtopServeClient(client_fd);
        close(client_fd);
    }

    close(server_fd);
    (void)unlink(flowtop_socket_path);
    return NULL;
}

static void FlowtopStartSocketThread(void)
{
    pthread_t thread;
    int r = pthread_create(&thread, NULL, FlowtopSocketThread, NULL);
    if (r != 0) {
        SCLogError("flowtop: failed to start socket thread: %s", strerror(r));
        return;
    }
    pthread_detach(thread);
}

static void FlowtopConfigureSocketPath(void)
{
    const char *path = getenv(FLOWTOP_SOCKET_ENV);
    if (path == NULL || path[0] == '\0')
        return;

    if (strlcpy(flowtop_socket_path, path, sizeof(flowtop_socket_path)) >= sizeof(flowtop_socket_path)) {
        FatalError("flowtop: socket path '%s' is too long", path);
    }
}

static void FlowtopInit(void)
{
    SCLogInfo("Initializing flowtop example plugin");

    FlowtopConfigureSocketPath();

    flowtop_storage_id = SCFlowStorageRegister("flowtop", FlowtopFlowStorageFree);
    if (flowtop_storage_id.id < 0)
        FatalError("flowtop: failed to register flow storage");

    if (!SCFlowRegisterInitCallback(FlowtopOnFlowInit, NULL))
        FatalError("flowtop: failed to register flow init callback");
    if (!SCFlowRegisterUpdateCallback(FlowtopOnFlowUpdate, NULL))
        FatalError("flowtop: failed to register flow update callback");
    if (!SCFlowRegisterFinishCallback(FlowtopOnFlowFinish, NULL))
        FatalError("flowtop: failed to register flow finish callback");

    FlowtopStartSocketThread();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "flowtop",
    .plugin_version = "0.1.0",
    .author = "Open Information Security Foundation",
    .license = "GPLv2",
    .Init = FlowtopInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
