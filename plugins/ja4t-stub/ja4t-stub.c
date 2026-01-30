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

/*
 * This is a stub/example plugin demonstrating Suricata callback APIs.
 * It doesn't perform any real analysis but shows how to hook into:
 * - Thread lifecycle callbacks
 * - Flow lifecycle callbacks
 * - EVE output callbacks
 * - Detection/keyword registration
 */

#include "detect.h"
#include "suricata-common.h"
#include "suricata-plugin.h"

#include "decode-tcp.h"
#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "flow-callbacks.h"
#include "flow-storage.h"
#include "output-eve.h"
#include "util-debug.h"

static FlowStorageId flow_storage_id = { .id = -1 };
static int ja4t_stub_keyword_id = -1;

/* Per-thread context structure */
struct Ja4tThreadContext {
    uint64_t packet_count;
};

/* Per-flow context structure */
struct Ja4tFlowContext {
};

/* Detection keyword data structure */
typedef struct DetectJa4tStubData_ {
    uint32_t value;
    bool negated;
} DetectJa4tStubData;

/* Free flow storage */
static void FlowStorageFree(void *ptr)
{
    SCLogDebug("Free'ing JA4T stub flow storage");
    struct Ja4tFlowContext *ctx = ptr;
    SCFree(ctx);
}

/* Flow initialization callback - called when a new flow is created.
 * Only processes SYN-only packets (SYN set, ACK not set). */
static void OnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *_data)
{
    /* Only process TCP SYN-only packets (not SYN-ACK) */
    if (!PacketIsTCP(p)) {
        return;
    }

    const TCPHdr *tcph = PacketGetTCP(p);
    if (tcph == NULL) {
        return;
    }

    /* Only process client SYN packets (without ACK) */
    if (!TCP_ISSET_FLAG_SYN(p) || TCP_ISSET_FLAG_ACK(p)) {
        return;
    }

    /* Do we already have JA4T data? */
    if (FlowGetStorageById(f, flow_storage_id) != NULL) {
        /* We do, just return. */
        return;
    }

    struct Ja4tFlowContext *flowctx = SCCalloc(1, sizeof(*flowctx));
    if (flowctx == NULL) {
        FatalError("Failed to allocate JA4T stub flow context");
    }

    FlowSetStorageById(f, flow_storage_id, flowctx);

    SCLogDebug("JA4T stub: Flow initialized for SYN-only packet");
}

/* Detection keyword packet match callback */
static int DetectJa4tStubPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const Flow *f = p->flow;
    struct Ja4tFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
    const DetectJa4tStubData *data = (const DetectJa4tStubData *)ctx;

    SCEnter();

    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    if (flowctx == NULL) {
        SCReturnInt(0);
    }

    /* Never match... */
    bool r = false;

    if (r) {
        SCLogDebug("JA4T stub keyword match on packet_count >= %u", data->value);
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/* Setup detection keyword */
static int DetectJa4tStubSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    // JA4T only works with TCP packets, reject UDP and other protocols
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_TCP))) {
        SCLogError("ja4t.hash keyword can only be used with TCP based rules");
        return -1;
    }

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    /* TODO */

    return 0;
}

/* Free detection keyword data */
static void DetectJa4tStubFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/* EVE output callback - adds data to EVE JSON output */
static void EveCallback(ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *jb, void *data)
{
    /* EVE callback requires a flow */
    if (f == NULL) {
        return;
    }

    struct Ja4tFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);

    if (flowctx == NULL) {
        return;
    }

    SCLogDebug("JA4T stub EVE callback: tv=%p, p=%p, f=%p", tv, p, f);

    /* Open a JA4T stub object in the EVE output */
    SCJbOpenObject(jb, "ja4t_stub");

    /* Nothing added. */

    /* Close the JA4T stub object */
    SCJbClose(jb);
}

/* Initialize detection keyword */
static void Ja4tStubInitKeyword(void)
{
    ja4t_stub_keyword_id = SCDetectHelperNewKeywordId();
    SCLogDebug("Registered new ja4t-stub keyword with ID %" PRIu32, ja4t_stub_keyword_id);
    sigmatch_table[ja4t_stub_keyword_id].name = "ja4t-stub";
    sigmatch_table[ja4t_stub_keyword_id].desc = "match on JA4T stub flow statistics";
    sigmatch_table[ja4t_stub_keyword_id].url = "/rules/ja4t-stub.html";
    sigmatch_table[ja4t_stub_keyword_id].Match = DetectJa4tStubPacketMatch;
    sigmatch_table[ja4t_stub_keyword_id].Setup = DetectJa4tStubSetup;
    sigmatch_table[ja4t_stub_keyword_id].Free = DetectJa4tStubFree;
    sigmatch_table[ja4t_stub_keyword_id].flags =
            (SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER);
}

/* Plugin initialization */
static void Ja4tStubInit(void)
{
    SCLogNotice("Initializing JA4T stub plugin - example of Suricata callback APIs");

    /* Register flow storage for per-flow data */
    flow_storage_id = FlowStorageRegister("ja4t_stub", sizeof(void *), NULL, FlowStorageFree);
    if (flow_storage_id.id < 0) {
        FatalError("Failed to register JA4T stub flow storage");
    }

    /* Register flow lifecycle callbacks */
    SCFlowRegisterInitCallback(OnFlowInit, NULL);

    /* Register an EVE callback for JSON output */
    SCEveRegisterCallback(EveCallback, NULL);

    /* Register detection keyword */
    Ja4tStubInitKeyword();

    SCLogNotice("JA4T stub plugin initialized successfully");
}

/* Plugin registration structure */
const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "ja4t-stub",
    .plugin_version = "0.1.0",
    .license = "GPLv2",
    .author = "FooBar",
    .Init = Ja4tStubInit,
};

/* Entry point for plugin loading */
const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
