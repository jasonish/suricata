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

/**
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author XXX Your Name <your@email.com>
 *
 * Decodes XXX describe the protocol
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-udplite.h"

/**
 * \brief Function to decode UDPLITE packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeUDPLITE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    /* TODO add counter for your type of packet to DecodeThreadVars,
     * and register it in DecodeRegisterPerfCounters */
    StatsIncr(tv, dtv->counter_udplite);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(UdpliteHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,UDPLITE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
    p->udpliteh = (const UdpliteHdr *)pkt;
    p->sp = SCNtohs(p->udpliteh->sport);
    p->dp = SCNtohs(p->udpliteh->dport);

    uint16_t cov = SCNtohs(p->udpliteh->coverage);

    SCLogNotice("sport: %d; dport: %d; coverage: %d",
            SCNtohs(p->udpliteh->sport),
            SCNtohs(p->udpliteh->dport),
            SCNtohs(p->udpliteh->coverage));

    /* Coverage values 1-7 and > 20 are invalid. */
    if (cov > 20 || (cov >=1 && cov <= 7)) {
        ENGINE_SET_EVENT(p, UDPLITE_INVALID_COV);
    }

    return TM_ECODE_OK;
}

/**
 * @}
 */
