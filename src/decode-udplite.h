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
 * \file
 *
 * \author XXX
 *
 */

#ifndef __DECODE_UDPLITE_H__
#define __DECODE_UDPLITE_H__

#include "decode.h"
#include "threadvars.h"

/* Header layout. Keep things like alignment and endianess in
 * mind while constructing this. */

typedef struct UdpliteHdr_ {
    uint16_t sport;
    uint16_t dport;
    uint16_t csum_coverage;
    uint16_t csum;
} __attribute__((__packed__)) UdpliteHdr;

#endif /* __DECODE_UDPLITE_H__ */
