/* Copyright (C) 2007-2020 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Vadym Malakhatko <v.malakhatko@sirinsoftware.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "stream-tcp.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-hassh-server-string.h"
#include "rust.h"


#define KEYWORD_NAME "ssh.hassh.server.string"
#define KEYWORD_ALIAS "ssh-hassh-server-string"
#define KEYWORD_DOC "ssh-keywords.html#ssh.hassh.server.string"
#define BUFFER_NAME "ssh.hassh.server.string"
#define BUFFER_DESC "Ssh Client Key Exchange methods For ssh Servers"
static int g_ssh_hassh_server_string_buffer_id = 0;


static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *hassh = NULL;
        uint32_t b_len = 0;

        if (rs_ssh_tx_get_hassh_string(txv, &hassh, &b_len, flow_flags) != 1)
            return NULL;
        if (hassh == NULL || b_len == 0) {
            SCLogDebug("SSH hassh string is not set");
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, hassh, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief this function setup the ssh.hassh.server.string modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 * \retval -2 on failure that should be silent after the first
 */
static int DetectSshHasshServerStringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_ssh_hassh_server_string_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;
     
    /* try to enable Hassh */
    rs_ssh_enable_hassh();

    /* Check if Hassh is disabled */
    if (!RunmodeIsUnittests() && !rs_ssh_hassh_is_enabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_SSH_HASSH_SERVER_STRING)) {
            SCLogError(SC_WARN_HASSH_DISABLED, "hassh support is not enabled");
        }
        return -2;
    }

    return 0;

}

/**
 * \brief Registration function for hasshServer.string keyword.
 */
void DetectSshHasshServerStringRegister(void) 
{
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].alias = KEYWORD_ALIAS;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].Setup = DetectSshHasshServerStringSetup;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER_STRING].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;


    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, 
            PrefilterGenericMpmRegister, GetSshData,
            ALPROTO_SSH, SshStateBannerDone);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_SSH, 
            SIG_FLAG_TOCLIENT, SshStateBannerDone, 
            DetectEngineInspectBufferGeneric, GetSshData);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ssh_hassh_server_string_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
