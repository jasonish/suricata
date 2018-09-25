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

/**
 * \file
 *
 * \author XXX
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-udplite_coverage_prefilter.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectUdplite_coverage_prefilterMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectUdplite_coverage_prefilterSetup (DetectEngineCtx *, Signature *, const char *);
void DetectUdplite_coverage_prefilterFree (void *);
#ifdef UNITTESTS
void DetectUdplite_coverage_prefilterRegisterTests (void);
#endif
static int PrefilterSetupUdplite_coverage_prefilter(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static _Bool PrefilterUdplite_coverage_prefilterIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for udplite_coverage_prefilter: keyword
 */

void DetectUdplite_coverage_prefilterRegister(void)
{
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].name = "udplite_coverage_prefilter";
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].desc = "TODO describe the keyword";
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#udplite_coverage_prefilter";
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].Match = DetectUdplite_coverage_prefilterMatch;
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].Setup = DetectUdplite_coverage_prefilterSetup;
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].Free = DetectUdplite_coverage_prefilterFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].RegisterTests = DetectUdplite_coverage_prefilterRegisterTests;
#endif
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].SupportsPrefilter = PrefilterUdplite_coverage_prefilterIsPrefilterable;
    sigmatch_table[DETECT_UDPLITE_COVERAGE_PREFILTER].SetupPrefilter = PrefilterSetupUdplite_coverage_prefilter;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int Udplite_coverage_prefilterMatch(const uint16_t parg, const uint16_t mode,
        const uint16_t darg1, const uint16_t darg2)
{
    if (mode == DETECT_UDPLITE_COVERAGE_PREFILTER_EQ && parg == darg1)
        return 1;
    else if (mode == DETECT_UDPLITE_COVERAGE_PREFILTER_LT && parg < darg1)
        return 1;
    else if (mode == DETECT_UDPLITE_COVERAGE_PREFILTER_GT && parg > darg1)
        return 1;
    else if (mode == DETECT_UDPLITE_COVERAGE_PREFILTER_RA && (parg > darg1 && parg < darg2))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match UDPLITE_COVERAGE_PREFILTER rule option on a packet with those passed via udplite_coverage_prefilter:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectUdplite_coverage_prefilterData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectUdplite_coverage_prefilterMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->udpliteh == NULL) {
        return 0;
    }

    uint16_t coverage = ntohs(p->udpliteh->coverage);

    const DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = (const DetectUdplite_coverage_prefilterData *)ctx;
    return Udplite_coverage_prefilterMatch(coverage, udplite_coverage_prefilterd->mode, udplite_coverage_prefilterd->arg1, udplite_coverage_prefilterd->arg2);
}

/**
 * \brief This function is used to parse udplite_coverage_prefilter options passed via udplite_coverage_prefilter: keyword
 *
 * \param udplite_coverage_prefilterstr Pointer to the user provided udplite_coverage_prefilter options
 *
 * \retval udplite_coverage_prefilterd pointer to DetectUdplite_coverage_prefilterData on success
 * \retval NULL on failure
 */

static DetectUdplite_coverage_prefilterData *DetectUdplite_coverage_prefilterParse (const char *udplite_coverage_prefilterstr)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, udplite_coverage_prefilterstr, strlen(udplite_coverage_prefilterstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) udplite_coverage_prefilterstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) udplite_coverage_prefilterstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) udplite_coverage_prefilterstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    udplite_coverage_prefilterd = SCMalloc(sizeof (DetectUdplite_coverage_prefilterData));
    if (unlikely(udplite_coverage_prefilterd == NULL))
        goto error;
    udplite_coverage_prefilterd->arg1 = 0;
    udplite_coverage_prefilterd->arg2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                udplite_coverage_prefilterd->mode = DETECT_UDPLITE_COVERAGE_PREFILTER_LT;
                udplite_coverage_prefilterd->arg1 = (uint16_t) atoi(arg3);

                SCLogDebug("udplite_coverage_prefilter is %"PRIu16"",udplite_coverage_prefilterd->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                udplite_coverage_prefilterd->mode = DETECT_UDPLITE_COVERAGE_PREFILTER_GT;
                udplite_coverage_prefilterd->arg1 = (uint16_t) atoi(arg3);

                SCLogDebug("udplite_coverage_prefilter is %"PRIu16"",udplite_coverage_prefilterd->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                udplite_coverage_prefilterd->mode = DETECT_UDPLITE_COVERAGE_PREFILTER_RA;
                udplite_coverage_prefilterd->arg1 = (uint16_t) atoi(arg1);

                udplite_coverage_prefilterd->arg2 = (uint16_t) atoi(arg3);
                SCLogDebug("udplite_coverage_prefilter is %"PRIu8" to %"PRIu8"",udplite_coverage_prefilterd->arg1, udplite_coverage_prefilterd->arg2);
                if (udplite_coverage_prefilterd->arg1 >= udplite_coverage_prefilterd->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid udplite_coverage_prefilter range. ");
                    goto error;
                }
                break;
            default:
                udplite_coverage_prefilterd->mode = DETECT_UDPLITE_COVERAGE_PREFILTER_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                udplite_coverage_prefilterd->arg1 = (uint16_t) atoi(arg1);
                break;
        }
    } else {
        udplite_coverage_prefilterd->mode = DETECT_UDPLITE_COVERAGE_PREFILTER_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        udplite_coverage_prefilterd->arg1 = (uint16_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return udplite_coverage_prefilterd;

error:
    if (udplite_coverage_prefilterd)
        SCFree(udplite_coverage_prefilterd);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief this function is used to audplite_coverage_prefilterd the parsed udplite_coverage_prefilter data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param udplite_coverage_prefilterstr pointer to the user provided udplite_coverage_prefilter options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectUdplite_coverage_prefilterSetup (DetectEngineCtx *de_ctx, Signature *s, const char *udplite_coverage_prefilterstr)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = DetectUdplite_coverage_prefilterParse(udplite_coverage_prefilterstr);
    if (udplite_coverage_prefilterd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectUdplite_coverage_prefilterFree(udplite_coverage_prefilterd);
        return -1;
    }

    sm->type = DETECT_UDPLITE_COVERAGE_PREFILTER;
    sm->ctx = (SigMatchCtx *)udplite_coverage_prefilterd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectUdplite_coverage_prefilterData
 *
 * \param ptr pointer to DetectUdplite_coverage_prefilterData
 */
void DetectUdplite_coverage_prefilterFree(void *ptr)
{
    DetectUdplite_coverage_prefilterData *udplite_coverage_prefilterd = (DetectUdplite_coverage_prefilterData *)ptr;
    SCFree(udplite_coverage_prefilterd);
}

/* prefilter code */

static void
PrefilterPacketUdplite_coverage_prefilterMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    if (p->udpliteh == NULL) {
        return;
    }

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    uint16_t coverage = ntohs(p->udpliteh->coverage);

    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (Udplite_coverage_prefilterMatch(coverage, ctx->v1.u16[0], ctx->v1.u16[1], ctx->v1.u16[2]))
    {
        SCLogDebug("packet matches udplite_coverage_prefilter/hl %u", pudplite_coverage_prefilter);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketUdplite_coverage_prefilterSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectUdplite_coverage_prefilterData *a = smctx;
    v->u16[0] = a->mode;
    v->u16[1] = a->arg1;
    v->u16[2] = a->arg2;
}

static _Bool
PrefilterPacketUdplite_coverage_prefilterCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectUdplite_coverage_prefilterData *a = smctx;
    if (v.u16[0] == a->mode &&
        v.u16[1] == a->arg1 &&
        v.u16[2] == a->arg2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupUdplite_coverage_prefilter(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_UDPLITE_COVERAGE_PREFILTER,
            PrefilterPacketUdplite_coverage_prefilterSet,
            PrefilterPacketUdplite_coverage_prefilterCompare,
            PrefilterPacketUdplite_coverage_prefilterMatch);
}

static _Bool PrefilterUdplite_coverage_prefilterIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_UDPLITE_COVERAGE_PREFILTER:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "tests/detect-udplite_coverage_prefilter.c"
#endif
