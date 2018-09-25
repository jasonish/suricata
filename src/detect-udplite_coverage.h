/* Copyright (C) 2015-2017 Open Information Security Foundation
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
 * \author XXX Yourname <youremail@yourdomain>
 */

#ifndef __DETECT_UDPLITE_COVERAGE_H__
#define __DETECT_UDPLITE_COVERAGE_H__

/** Per keyword data. This is set up by the DetectUdplite_coverageSetup() function.
 *  Each signature will have an instance of DetectUdplite_coverageData per occurence
 *  of the keyword.
 *  The structure should be considered static/readonly after initialization.
 */
typedef struct DetectUdplite_coverageData_ {
    uint8_t arg1;
    uint8_t arg2;
    bool is_range;
} DetectUdplite_coverageData;

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectUdplite_coverageRegister(void);

#endif /* __DETECT_UDPLITE_COVERAGE_H__ */
