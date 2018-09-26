/* Copyright (C) 2015-2018 Open Information Security Foundation
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
 * TODO: Update the \author in this file and detect-gopher-listing.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "gopher_listing" keyword to allow content
 * inspections on the decoded gopher application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-gopher.h"
#include "detect-gopher-listing.h"

static int DetectGopherListingSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectGopherListingRegisterTests(void);
#endif
static int g_gopher_listing_id = 0;

void DetectGopherListingRegister(void)
{
    sigmatch_table[DETECT_AL_GOPHER_LISTING].name = "gopher_listing";
    sigmatch_table[DETECT_AL_GOPHER_LISTING].desc =
        "Gopher content modififier to match on the gopher buffers";
    sigmatch_table[DETECT_AL_GOPHER_LISTING].Setup = DetectGopherListingSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_GOPHER_LISTING].RegisterTests =
        DetectGopherListingRegisterTests;
#endif

    sigmatch_table[DETECT_AL_GOPHER_LISTING].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
#if 0
    DetectAppLayerInspectEngineRegister2("gopher_listing",
            ALPROTO_GOPHER, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
#endif
    DetectAppLayerInspectEngineRegister2("gopher_listing",
            ALPROTO_GOPHER, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

#if 0
    /* register mpm engines - these are called in the prefilter stage */
    DetectAppLayerMpmRegister2("gopher_listing", SIG_FLAG_TOSERVER, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_GOPHER, 0);
#endif
    DetectAppLayerMpmRegister2("gopher_listing", SIG_FLAG_TOCLIENT, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_GOPHER, 0);


    g_gopher_listing_id = DetectBufferTypeGetByName("gopher_listing");

    SCLogNotice("Gopher application layer detect registered.");
}

static int DetectGopherListingSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_gopher_listing_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_GOPHER */
    if (DetectSignatureSetAppProto(s, ALPROTO_GOPHER) != 0)
        return -1;

    return 0;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    BUG_ON(det_ctx->inspect_buffers == NULL);

    InspectionBuffer *buffer = &det_ctx->inspect_buffers[list_id];
    if (buffer->inspect == NULL) {
        const GopherTransaction  *tx = (GopherTransaction *)txv;

        if (flow_flags & STREAM_TOCLIENT && tx->directory_listing) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL;
        }

#if 0
        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL; /* no buffer */
        }
#endif

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-gopher-listing.c"
#endif
