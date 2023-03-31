/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-debug.h"
#include "conf.h"

#include "config.h"

static SCConfigValue *root = NULL;
static SCConfigValue *root_backup = NULL;

static void FixName(char *string)
{
    char *c;
    while ((c = strchr(string, '_')))
        *c = '-';
}

bool SCConfigLoad(const char *filename)
{
    SCConfigValue *config = SCConfigLoadFile(filename);
    if (config == NULL) {
        return false;
    }
    SCConfigValueToLegacy(ConfGetRootNode(), config);
    SCConfigValueFree(config);
    return true;
}

void SCConfigValueToLegacy(ConfNode *parent, SCConfigValue *value)
{
    if (SCConfigValueIsMapping(value)) {
        SCConfigMapIter *iter = SCConfigMapIterGet(value);
        SCConfigValue *child = NULL;
        const char *key = NULL;
        while (SCConfigMapIterNext(iter, &key, &child)) {
            /* An oddity in the legacy format that some code depends on. */
            if (parent && parent->parent && parent->parent->is_seq && parent->val == NULL) {
                parent->val = SCStrdup(key);
                BUG_ON(parent->val == NULL);
            }

            ConfNode *existing = ConfNodeLookupChild(parent, key);
            if (existing != NULL && existing->final) {
                SCConfigValueToLegacy(existing, child);
            } else {
                ConfNode *new = ConfNodeNew();
                TAILQ_INSERT_TAIL(&parent->head, new, next);
                new->name = SCStrdup(key);
                BUG_ON(new->name == NULL);

                if (!(parent->name && ((strcmp(parent->name, "address-groups") == 0) ||
                                              (strcmp(parent->name, "port-groups") == 0)))) {
                    FixName(new->name);
                }

                new->parent = parent;
                SCConfigValueToLegacy(new, child);
            }
        }
        SCConfigMapIterFree(iter);
    } else if (SCConfigValueIsArray(value)) {
        SCConfigArrayIter *iter = SCConfigArrayIterGet(value);
        SCConfigValue *child = NULL;
        int i = 0;
        while (SCConfigArrayIterNext(iter, &child)) {
            char name[32];
            snprintf(name, sizeof(name), "%d", i);

            ConfNode *node = ConfNodeLookupChild(parent, name);
            if (node == NULL) {
                node = ConfNodeNew();
                node->name = SCStrdup(name);
                BUG_ON(node->name == NULL);
                TAILQ_INSERT_TAIL(&parent->head, node, next);
            }
            parent->is_seq = 1;
            node->parent = parent;

            SCConfigValueToLegacy(node, child);
            i += 1;
        }
        SCConfigArrayIterFree(iter);
    } else if (SCConfigValueIsString(value)) {
        if (parent->final) {
            return;
        }
        if (parent->val != NULL) {
            SCFree(parent->val);
        }
        parent->val = SCStrdup(SCConfigValueAsString(value));
        BUG_ON(parent->val == NULL);
    } else if (SCConfigValueIsBool(value)) {
        if (parent->final) {
            return;
        }
        if (parent->val != NULL) {
            SCFree(parent->val);
        }
        parent->val = SCStrdup(SCConfigValueAsString(value));
        BUG_ON(parent->val == NULL);
    } else if (SCConfigValueIsNumber(value)) {
        if (parent->final) {
            return;
        }
        if (parent->val != NULL) {
            SCFree(parent->val);
        }
        parent->val = SCStrdup(SCConfigValueAsString(value));
        BUG_ON(parent->val == NULL);
    } else if (SCConfigValueIsNull(value)) {
        if (parent->final) {
            return;
        }
        if (parent->val != NULL) {
            SCFree(parent->val);
        }
        parent->val = NULL;
    }
}

#if 0
static void SCConfigDumpValue(SCConfigValue *config, char *prefix)
{
    char new_prefix[8192];
    if (SCConfigValueIsMapping(config)) {
        SCConfigMapIter *iter = SCConfigMapIterGet(config);
        SCConfigValue *value = NULL;
        const char *key = NULL;
        while (SCConfigMapIterNext(iter, &key, &value)) {
            if (prefix == NULL) {
                snprintf(new_prefix, sizeof(new_prefix), "%s", key);
            } else {
                snprintf(new_prefix, sizeof(new_prefix), "%s.%s", prefix, key);
            }
            SCConfigDumpValue(value, new_prefix);
        }
        SCConfigMapIterFree(iter);
    } else if (SCConfigValueIsArray(config)) {
        SCConfigArrayIter *iter = SCConfigArrayIterGet(config);
        SCConfigValue *value = NULL;
        int i = 0;
        while (SCConfigArrayIterNext(iter, &value)) {
            if (prefix == NULL) {
                snprintf(new_prefix, sizeof(new_prefix), "%d", i);
            } else {
                snprintf(new_prefix, sizeof(new_prefix), "%s.%d", prefix, i);
            }
            SCConfigDumpValue(value, new_prefix);
            i += 1;
        }
        SCConfigArrayIterFree(iter);
    } else if (SCConfigValueIsBool(config)) {
        printf("%s = %s (bool)\n", prefix, SCConfigValueAsBool(config) ? "true" : "false");
    } else if (SCConfigValueIsString(config)) {
        printf("%s = %s (string)\n", prefix, SCConfigValueAsString(config));
    } else if (SCConfigValueIsNumber(config)) {
        printf("%s = %s (number)\n", prefix, SCConfigValueAsString(config));
    } else if (SCConfigValueIsNull(config)) {
        printf("%s = (null)\n", prefix);
    } else {
        abort();
    }
}
#endif

SCConfigValue *SCConfigGetRoot(void)
{
    return root;
}

void SCConfigSetRoot(SCConfigValue *config)
{
    if (root != NULL) {
	SCConfigFree();
    }
    root = config;
}

void SCConfigFree(void)
{
    SCConfigValueFree(root);
    root = NULL;
}

void SCConfigBackup(void)
{
    root_backup = root;
    root = NULL;
}

void SCConfigRestore(void)
{
    root = root_backup;
    root_backup = NULL;
}
