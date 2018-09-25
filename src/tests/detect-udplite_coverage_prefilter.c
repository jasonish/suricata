/* Copyright (C) 2007-2018 Open Information Security Foundation
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

#include "../suricata-common.h"

#include "../detect.h"
#include "../detect-parse.h"
#include "../detect-engine-prefilter-common.h"

#include "../detect-udplite_coverage_prefilter.h"

#include "../util-unittest.h"

/**
 * \test DetectUdplite_coverage_prefilterParseTest01 is a test for setting up an valid udplite_coverage_prefilter value.
 */

static int DetectUdplite_coverage_prefilterParseTest01 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse("10");

    FAIL_IF_NULL(udplite_coverage_prefilterd);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg1 == 10);
    FAIL_IF_NOT(udplite_coverage_prefilterd->mode == DETECT_UDPLITE_COVERAGE_PREFILTER_EQ);

    DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);

    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest02 is a test for setting up an valid udplite_coverage_prefilter value with
 *       "<" operator.
 */

static int DetectUdplite_coverage_prefilterParseTest02 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse("<10");

    FAIL_IF_NULL(udplite_coverage_prefilterd);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg1 == 10);
    FAIL_IF_NOT(udplite_coverage_prefilterd->mode == DETECT_UDPLITE_COVERAGE_PREFILTER_LT);

    DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);

    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest03 is a test for setting up an valid udplite_coverage_prefilter values with
 *       "-" operator.
 */

static int DetectUdplite_coverage_prefilterParseTest03 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse("1-2");

    FAIL_IF_NULL(udplite_coverage_prefilterd);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg1 == 1);
    FAIL_IF_NOT(udplite_coverage_prefilterd->mode == DETECT_UDPLITE_COVERAGE_PREFILTER_RA);

    DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);

    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest04 is a test for setting up an valid udplite_coverage_prefilter value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectUdplite_coverage_prefilterParseTest04 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse(" > 10 ");

    FAIL_IF_NULL(udplite_coverage_prefilterd);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg1 == 10);
    FAIL_IF_NOT(udplite_coverage_prefilterd->mode == DETECT_UDPLITE_COVERAGE_PREFILTER_GT);

    DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);

    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest05 is a test for setting up an valid udplite_coverage_prefilter values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectUdplite_coverage_prefilterParseTest05 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse(" 1 - 2 ");

    FAIL_IF_NULL(udplite_coverage_prefilterd);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg1 == 1);
    FAIL_IF_NOT(udplite_coverage_prefilterd->arg2 == 2);
    FAIL_IF_NOT(udplite_coverage_prefilterd->mode == DETECT_UDPLITE_COVERAGE_PREFILTER_RA);

    DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);

    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest06 is a test for setting up an valid udplite_coverage_prefilter values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectUdplite_coverage_prefilterParseTest06 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(udplite_coverage_prefilterd);
    PASS;
}

/**
 * \test DetectUdplite_coverage_prefilterParseTest07 is a test for setting up an valid udplite_coverage_prefilter values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectUdplite_coverage_prefilterParseTest07 (void)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse(" 1<>2 ");
    FAIL_IF_NOT_NULL(udplite_coverage_prefilterd);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectUdplite_coverage_prefilter
 */
void DetectUdplite_coverage_prefilterRegisterTests(void)
{
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest01", DetectUdplite_coverage_prefilterParseTest01);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest02", DetectUdplite_coverage_prefilterParseTest02);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest03", DetectUdplite_coverage_prefilterParseTest03);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest04", DetectUdplite_coverage_prefilterParseTest04);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest05", DetectUdplite_coverage_prefilterParseTest05);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest06", DetectUdplite_coverage_prefilterParseTest06);
    UtRegisterTest("DetectUdplite_coverage_prefilterParseTest07", DetectUdplite_coverage_prefilterParseTest07);
}

