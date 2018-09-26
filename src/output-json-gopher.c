/* Copyright (C) 2015 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-gopher.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Gopher.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-gopher.h"
#include "output-json-gopher.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogGopherFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogGopherFileCtx;

typedef struct LogGopherLogThread_ {
    LogGopherFileCtx *gopherlog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogGopherLogThread;

static int JsonGopherLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    GopherTransaction *gophertx = tx;
    LogGopherLogThread *thread = thread_data;

    SCLogNotice("Logging gopher transaction %"PRIu64".", gophertx->tx_id);

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "gopher");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *gopherjs = json_object();
    if (unlikely(gopherjs == NULL)) {
        goto error;
    }

    /* Convert the request buffer to a string then log. */
    char *request_buffer = BytesToString(gophertx->request_buffer,
        gophertx->request_buffer_len);
    if (request_buffer != NULL) {
        json_object_set_new(gopherjs, "uri", json_string(request_buffer));
        SCFree(request_buffer);
    }
    json_object_set_new(gopherjs, "directory_listing",
            json_boolean(gophertx->directory_listing));

    /* Convert the response buffer to a string then log. */
    char *response_buffer = BytesToString(gophertx->response_buffer,
        gophertx->response_buffer_len);
    if (response_buffer != NULL) {
        json_object_set_new(gopherjs, "response",
            json_string(response_buffer));
        SCFree(response_buffer);
    }

    json_object_set_new(js, "gopher", gopherjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->gopherlog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputGopherLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogGopherFileCtx *gopherlog_ctx = (LogGopherFileCtx *)output_ctx->data;
    SCFree(gopherlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputGopherLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogGopherFileCtx *gopherlog_ctx = SCCalloc(1, sizeof(*gopherlog_ctx));
    if (unlikely(gopherlog_ctx == NULL)) {
        return result;
    }
    gopherlog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(gopherlog_ctx);
        return result;
    }
    output_ctx->data = gopherlog_ctx;
    output_ctx->DeInit = OutputGopherLogDeInitCtxSub;

    SCLogNotice("Gopher log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_GOPHER);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonGopherLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogGopherLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogGopher.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->gopherlog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonGopherLogThreadDeinit(ThreadVars *t, void *data)
{
    LogGopherLogThread *thread = (LogGopherLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonGopherLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_GOPHER, "eve-log", "JsonGopherLog",
        "eve-log.gopher", OutputGopherLogInitSub, ALPROTO_GOPHER,
        JsonGopherLogger, JsonGopherLogThreadInit,
        JsonGopherLogThreadDeinit, NULL);

    SCLogNotice("Gopher JSON logger registered.");
}

#else /* No JSON support. */

void JsonGopherLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
