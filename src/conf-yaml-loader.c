/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * YAML configuration loader.
 */

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-path.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "config.h"

/**
 * \brief Load configuration from a YAML string.
 */
int
ConfYamlLoadString(const char *string, size_t len)
{
    ConfNode *root = ConfGetRootNode();
    SCConfigValue *value = SCConfigLoadString(string, len);
    if (value == NULL) {
        return -1;
    }
    SCConfigValueToLegacy(root, value);
    SCConfigSetRoot(value);
    return 0;
}

/**
 * \brief Load configuration from a YAML file, insert in tree at 'prefix'
 *
 * This function will load a configuration file and insert it into the
 * config tree at 'prefix'. This means that if this is called with prefix
 * "abc" and the file contains a parameter "def", it will be loaded as
 * "abc.def".
 *
 * \param filename Filename of configuration file to load.
 * \param prefix Name prefix to use.
 *
 * \retval 0 on success, -1 on failure.
 */
int
ConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    ConfNode *root = ConfGetNode(prefix);
    if (root == NULL) {
        ConfSet(prefix, "<prefix root node>");
        root = ConfGetNode(prefix);
    }
    BUG_ON(root == NULL);

    SCConfigValue *config = SCConfigLoadFile(filename);
    if (config == NULL) {
        return -1;
    }

    SCConfigValueToLegacy(root, config);
    SCConfigValueFree(config);

    return 0;
}

#ifdef UNITTESTS

static int
ConfYamlSequenceTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
rule-files:\n\
  - netbios.rules\n\
  - x11.rules\n\
\n\
default-log-dir: /tmp\n\
";

    ConfCreateContextBackup();
    ConfInit();

    ConfYamlLoadString(input, strlen(input));

    ConfNode *node;
    node = ConfGetNode("rule-files");
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(ConfNodeIsSequence(node));
    FAIL_IF(TAILQ_EMPTY(&node->head));
    int i = 0;
    ConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            FAIL_IF(strcmp(filename->val, "netbios.rules") != 0);
            FAIL_IF(ConfNodeIsSequence(filename));
            FAIL_IF(filename->is_seq != 0);
        }
        else if (i == 1) {
            FAIL_IF(strcmp(filename->val, "x11.rules") != 0);
            FAIL_IF(ConfNodeIsSequence(filename));
        }
        FAIL_IF(i > 1);
        i++;
    }

    ConfDeInit();
    ConfRestoreContextBackup();
    PASS;
}

static int
ConfYamlLoggingOutputTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
logging:\n\
  output:\n\
    - interface: console\n\
      log-level: error\n\
    - interface: syslog\n\
      facility: local4\n\
      log-level: info\n\
";

    ConfCreateContextBackup();
    ConfInit();

    ConfYamlLoadString(input, strlen(input));

    ConfNode *outputs;
    outputs = ConfGetNode("logging.output");
    FAIL_IF_NULL(outputs);

    ConfNode *output;
    ConfNode *output_param;

    output = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(output);
    FAIL_IF(strcmp(output->name, "0") != 0);

    output_param = TAILQ_FIRST(&output->head);
    FAIL_IF_NULL(output_param);
    FAIL_IF(strcmp(output_param->name, "interface") != 0);
    FAIL_IF(strcmp(output_param->val, "console") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "log-level") != 0);
    FAIL_IF(strcmp(output_param->val, "error") != 0);

    output = TAILQ_NEXT(output, next);
    FAIL_IF_NULL(output);
    FAIL_IF(strcmp(output->name, "1") != 0);

    output_param = TAILQ_FIRST(&output->head);
    FAIL_IF_NULL(output_param);
    FAIL_IF(strcmp(output_param->name, "interface") != 0);
    FAIL_IF(strcmp(output_param->val, "syslog") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "facility") != 0);
    FAIL_IF(strcmp(output_param->val, "local4") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "log-level") != 0);
    FAIL_IF(strcmp(output_param->val, "info") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/**
 * Try to load something that is not a valid YAML file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
#if 0
    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadFile("/etc/passwd") != -1);

    ConfDeInit();
    ConfRestoreContextBackup();
#endif
    PASS;
}

static int
ConfYamlBadYamlVersionTest(void)
{
    char input[] = "\
%YAML 9.9\n\
---\n\
logging:\n\
  output:\n\
    - interface: console\n\
      log-level: error\n\
    - interface: syslog\n\
      facility: local4\n\
      log-level: info\n\
";

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(input, strlen(input)) != -1);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

static int
ConfYamlSecondLevelSequenceTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
  server-config:\n\
    - apache-php:\n\
        address: [\"192.168.1.0/24\"]\n\
        personality: [\"Apache_2_2\", \"PHP_5_3\"]\n\
        path-parsing: [\"compress_separators\", \"lowercase\"]\n\
    - iis-php:\n\
        address:\n\
          - 192.168.0.0/24\n\
\n\
        personality:\n\
          - IIS_7_0\n\
          - PHP_5_3\n\
\n\
        path-parsing:\n\
          - compress_separators\n\
";

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(input, strlen(input)) != 0);

    ConfNode *outputs;
    outputs = ConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);

    ConfNode *node;

    node = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "apache-php") != 0);

    node = ConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);
    FAIL_IF(strcmp(node->val, "192.168.1.0/24") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/**
 * Test that a configuration section is overridden but subsequent
 * occurrences.
 */
static int
ConfYamlOverrideTest(void)
{
    char config[] = "%YAML 1.1\n"
                    "---\n"
#if 0 /* serde_yaml does not allow duplicate keys */
                    "some-log-dir: /var/log\n"
#endif
                    "some-log-dir: /tmp\n"
                    "\n"
#if 0 /* serde_yaml does not allow duplicate keys */
                    "parent:\n"
                    "  child0:\n"
                    "    key: value\n"
#endif
                    "parent:\n"
                    "  child1:\n"
                    "    key: value\n"
                    "vars:\n"
                    "  address-groups:\n"
                    "    HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]\"\n"
                    "    EXTERNAL_NET: any\n"
                    "vars.address-groups.HOME_NET: \"10.10.10.10/32\"\n";
    const char *value;

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);
    FAIL_IF_NOT(ConfGet("some-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    /* Test that parent.child0 does not exist, but child1 does. */
    FAIL_IF_NOT_NULL(ConfGetNode("parent.child0"));
    FAIL_IF_NOT(ConfGet("parent.child1.key", &value));
    FAIL_IF(strcmp(value, "value") != 0);

    /* First check that vars.address-groups.EXTERNAL_NET has the
     * expected parent of vars.address-groups and save this
     * pointer. We want to make sure that the overrided value has the
     * same parent later on. */
    ConfNode *vars_address_groups = ConfGetNode("vars.address-groups");
    FAIL_IF_NULL(vars_address_groups);
    ConfNode *vars_address_groups_external_net = ConfGetNode("vars.address-groups.EXTERNAL_NET");
    FAIL_IF_NULL(vars_address_groups_external_net);
    FAIL_IF_NOT(vars_address_groups_external_net->parent == vars_address_groups);

    /* Now check that HOME_NET has the overrided value. */
    ConfNode *vars_address_groups_home_net = ConfGetNode("vars.address-groups.HOME_NET");
    FAIL_IF_NULL(vars_address_groups_home_net);
    FAIL_IF(strcmp(vars_address_groups_home_net->val, "10.10.10.10/32") != 0);

    /* And check that it has the correct parent. */
    FAIL_IF_NOT(vars_address_groups_home_net->parent == vars_address_groups);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/**
 * Test that a configuration parameter loaded from YAML doesn't
 * override a 'final' value that may be set on the command line.
 */
static int
ConfYamlOverrideFinalTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    char config[] =
        "%YAML 1.1\n"
        "---\n"
        "default-log-dir: /var/log\n";

    /* Set the log directory as if it was set on the command line. */
    FAIL_IF_NOT(ConfSetFinal("default-log-dir", "/tmp"));
    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);

    const char *default_log_dir;

    FAIL_IF_NOT(ConfGet("default-log-dir", &default_log_dir));
    FAIL_IF(strcmp(default_log_dir, "/tmp") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

static int ConfYamlNull(void)
{
    ConfCreateContextBackup();
    ConfInit();

    char config[] = "%YAML 1.1\n"
                    "---\n"
                    "quoted-tilde: \"~\"\n"
                    "unquoted-tilde: ~\n"
                    "quoted-null: \"null\"\n"
                    "unquoted-null: null\n"
                    "quoted-Null: \"Null\"\n"
                    "unquoted-Null: Null\n"
                    "quoted-NULL: \"NULL\"\n"
                    "unquoted-NULL: NULL\n"
                    "empty-quoted: \"\"\n"
                    "empty-unquoted: \n"
                    "list: [\"null\", null, \"Null\", Null, \"NULL\", NULL, \"~\", ~]\n";
    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);

    const char *val;

    FAIL_IF_NOT(ConfGet("quoted-tilde", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-tilde", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-Null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-Null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-NULL", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-NULL", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("empty-quoted", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("empty-unquoted", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.0", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.1", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.2", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.3", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.4", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.5", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.6", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.7", &val));
    FAIL_IF_NOT_NULL(val);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

#endif /* UNITTESTS */

void
ConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlSequenceTest", ConfYamlSequenceTest);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest);
    UtRegisterTest("ConfYamlNonYamlFileTest", ConfYamlNonYamlFileTest);
    UtRegisterTest("ConfYamlBadYamlVersionTest", ConfYamlBadYamlVersionTest);
    UtRegisterTest("ConfYamlSecondLevelSequenceTest", ConfYamlSecondLevelSequenceTest);
    UtRegisterTest("ConfYamlOverrideTest", ConfYamlOverrideTest);
    UtRegisterTest("ConfYamlOverrideFinalTest", ConfYamlOverrideFinalTest);
    UtRegisterTest("ConfYamlNull", ConfYamlNull);
#endif /* UNITTESTS */
}
