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

/* Rust helpers. */
extern int SCRustConfigLoadIntoConfFromFile(SCConfNode *parent, const char *filename);
extern int SCRustConfigLoadIntoConfFromString(SCConfNode *parent, const char *string, size_t len);

static char *conf_dirname = NULL;

/**
 * \brief Set the directory name of the configuration file.
 *
 * \param filename The configuration filename.
 */
static void
ConfYamlSetConfDirname(const char *filename)
{
    const char *ep;

    ep = strrchr(filename, '\\');
    if (ep == NULL)
        ep = strrchr(filename, '/');

    if (ep == NULL) {
        conf_dirname = SCStrdup(".");
        if (conf_dirname == NULL) {
            FatalError("ERROR: Failed to allocate memory while loading configuration.");
        }
    }
    else {
        conf_dirname = SCStrdup(filename);
        if (conf_dirname == NULL) {
            FatalError("ERROR: Failed to allocate memory while loading configuration.");
        }
        conf_dirname[ep - filename] = '\0';
    }
}

static int ConfYamlValidateFilePath(const char *filename)
{
    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (S_ISDIR(stat_buf.st_mode)) {
            SCLogError("yaml argument is not a file but a directory: %s. "
                       "Please specify the yaml file in your -c option.",
                    filename);
            return -1;
        }
    }
    return 0;
}

/**
 * \brief Include a file in the configuration.
 *
 * \param parent The configuration node the included configuration will be
 *          placed at.
 * \param filename The filename to include.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCConfYamlHandleInclude(SCConfNode *parent, const char *filename)
{
    if (parent == NULL || filename == NULL) {
        return -1;
    }

    char include_filename[PATH_MAX] = "";
    if (PathIsAbsolute(filename)) {
        strlcpy(include_filename, filename, sizeof(include_filename));
    } else {
        const char *base = conf_dirname != NULL ? conf_dirname : ".";
        if (PathMerge(include_filename, sizeof(include_filename), base, filename) != 0) {
            SCLogError("Failed to build include path from '%s' and '%s'", base, filename);
            return -1;
        }
    }

    if (SCRustConfigLoadIntoConfFromFile(parent, include_filename) != 0) {
        SCLogError("Failed to include configuration file %s", include_filename);
        return -1;
    }

    return 0;
}

/**
 * \brief Load configuration from a YAML file.
 */
int SCConfYamlLoadFile(const char *filename)
{
    if (filename == NULL) {
        return -1;
    }

    if (ConfYamlValidateFilePath(filename) != 0) {
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    SCConfNode *root = SCConfGetRootNode();
    if (root == NULL) {
        return -1;
    }

    if (SCRustConfigLoadIntoConfFromFile(root, filename) != 0) {
        SCLogError("failed to load yaml %s", filename);
        return -1;
    }

    return 0;
}

/**
 * \brief Load configuration from a YAML string.
 */
int SCConfYamlLoadString(const char *string, size_t len)
{
    if (string == NULL) {
        return -1;
    }

    SCConfNode *root = SCConfGetRootNode();
    if (root == NULL) {
        return -1;
    }

    if (SCRustConfigLoadIntoConfFromString(root, string, len) != 0) {
        SCLogError("failed to load yaml string");
        return -1;
    }

    return 0;
}

/**
 * \brief Load configuration from a YAML file, insert in tree at 'prefix'
 */
int SCConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    if (filename == NULL || prefix == NULL) {
        return -1;
    }

    if (ConfYamlValidateFilePath(filename) != 0) {
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    SCConfNode *root = SCConfGetNode(prefix);
    if (root == NULL) {
        SCConfSet(prefix, "<prefix root node>");
        root = SCConfGetNode(prefix);
        if (root == NULL) {
            return -1;
        }
    }

    if (SCRustConfigLoadIntoConfFromFile(root, filename) != 0) {
        SCLogError("failed to load yaml %s", filename);
        return -1;
    }

    return 0;
}

#ifdef UNITTESTS

static int ConfYamlSequenceTest(void)
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

    SCConfCreateContextBackup();
    SCConfInit();

    SCConfYamlLoadString(input, strlen(input));

    SCConfNode *node;
    node = SCConfGetNode("rule-files");
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfNodeIsSequence(node));
    FAIL_IF(TAILQ_EMPTY(&node->head));
    int i = 0;
    SCConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            FAIL_IF(strcmp(filename->val, "netbios.rules") != 0);
            FAIL_IF(SCConfNodeIsSequence(filename));
            FAIL_IF(filename->is_seq != 0);
        }
        else if (i == 1) {
            FAIL_IF(strcmp(filename->val, "x11.rules") != 0);
            FAIL_IF(SCConfNodeIsSequence(filename));
        }
        FAIL_IF(i > 1);
        i++;
    }

    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    SCConfCreateContextBackup();
    SCConfInit();

    SCConfYamlLoadString(input, strlen(input));

    SCConfNode *outputs;
    outputs = SCConfGetNode("logging.output");
    FAIL_IF_NULL(outputs);

    SCConfNode *output;
    SCConfNode *output_param;

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

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Try to load something that is not a valid YAML file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadFile("/etc/passwd") != -1);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfYamlSecondLevelSequenceTest(void)
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

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(input, strlen(input)) != 0);

    SCConfNode *outputs;
    outputs = SCConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);

    SCConfNode *node;

    node = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "apache-php") != 0);

    node = SCConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);
    FAIL_IF(strcmp(node->val, "192.168.1.0/24") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Test file inclusion support.
 */
static int
ConfYamlFileIncludeTest(void)
{
    FILE *config_file;

    const char config_filename[] = "ConfYamlFileIncludeTest-config.yaml";
    const char config_file_contents[] =
        "%YAML 1.1\n"
        "---\n"
        "# Include something at the root level.\n"
        "include: ConfYamlFileIncludeTest-include.yaml\n"
        "# Test including under a mapping.\n"
        "mapping: !include ConfYamlFileIncludeTest-include.yaml\n";

    const char include_filename[] = "ConfYamlFileIncludeTest-include.yaml";
    const char include_file_contents[] =
        "%YAML 1.1\n"
        "---\n"
        "host-mode: auto\n"
        "unix-command:\n"
        "  enabled: no\n";

    SCConfCreateContextBackup();
    SCConfInit();

    /* Write out the test files. */
    FAIL_IF_NULL((config_file = fopen(config_filename, "w")));
    FAIL_IF(fwrite(config_file_contents, strlen(config_file_contents), 1, config_file) != 1);
    fclose(config_file);

    FAIL_IF_NULL((config_file = fopen(include_filename, "w")));
    FAIL_IF(fwrite(include_file_contents, strlen(include_file_contents), 1, config_file) != 1);
    fclose(config_file);

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    FAIL_IF(SCConfYamlLoadFile("ConfYamlFileIncludeTest-config.yaml") != 0);

    /* Check values that should have been loaded into the root of the
     * configuration. */
    SCConfNode *node;
    node = SCConfGetNode("host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = SCConfGetNode("unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    /* Check for values that were included under a mapping. */
    node = SCConfGetNode("mapping.host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = SCConfGetNode("mapping.unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    unlink(config_filename);
    unlink(include_filename);

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
                    "some-log-dir: /var/log\n"
                    "some-log-dir: /tmp\n"
                    "\n"
                    "parent:\n"
                    "  child0:\n"
                    "    key: value\n"
                    "parent:\n"
                    "  child1:\n"
                    "    key: value\n"
                    "vars:\n"
                    "  address-groups:\n"
                    "    HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]\"\n"
                    "    EXTERNAL_NET: any\n"
                    "vars.address-groups.HOME_NET: \"10.10.10.10/32\"\n";
    const char *value;

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);
    FAIL_IF_NOT(SCConfGet("some-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    /* Test that parent.child0 does not exist, but child1 does. */
    FAIL_IF_NOT_NULL(SCConfGetNode("parent.child0"));
    FAIL_IF_NOT(SCConfGet("parent.child1.key", &value));
    FAIL_IF(strcmp(value, "value") != 0);

    /* First check that vars.address-groups.EXTERNAL_NET has the
     * expected parent of vars.address-groups and save this
     * pointer. We want to make sure that the overrided value has the
     * same parent later on. */
    SCConfNode *vars_address_groups = SCConfGetNode("vars.address-groups");
    FAIL_IF_NULL(vars_address_groups);
    SCConfNode *vars_address_groups_external_net =
            SCConfGetNode("vars.address-groups.EXTERNAL_NET");
    FAIL_IF_NULL(vars_address_groups_external_net);
    FAIL_IF_NOT(vars_address_groups_external_net->parent == vars_address_groups);

    /* Now check that HOME_NET has the overrided value. */
    SCConfNode *vars_address_groups_home_net = SCConfGetNode("vars.address-groups.HOME_NET");
    FAIL_IF_NULL(vars_address_groups_home_net);
    FAIL_IF(strcmp(vars_address_groups_home_net->val, "10.10.10.10/32") != 0);

    /* And check that it has the correct parent. */
    FAIL_IF_NOT(vars_address_groups_home_net->parent == vars_address_groups);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Test that a configuration parameter loaded from YAML doesn't
 * override a 'final' value that may be set on the command line.
 */
static int
ConfYamlOverrideFinalTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    char config[] =
        "%YAML 1.1\n"
        "---\n"
        "default-log-dir: /var/log\n";

    /* Set the log directory as if it was set on the command line. */
    FAIL_IF_NOT(SCConfSetFinal("default-log-dir", "/tmp"));
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *default_log_dir;

    FAIL_IF_NOT(SCConfGet("default-log-dir", &default_log_dir));
    FAIL_IF(strcmp(default_log_dir, "/tmp") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfYamlNull(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

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
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *val;

    FAIL_IF_NOT(SCConfGet("quoted-tilde", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-tilde", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-Null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-Null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-NULL", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-NULL", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("empty-quoted", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("empty-unquoted", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.0", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.1", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.2", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.3", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.4", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.5", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.6", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.7", &val));
    FAIL_IF_NOT_NULL(val);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

#endif /* UNITTESTS */

void SCConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlSequenceTest", ConfYamlSequenceTest);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest);
    UtRegisterTest("ConfYamlNonYamlFileTest", ConfYamlNonYamlFileTest);
    UtRegisterTest("ConfYamlSecondLevelSequenceTest", ConfYamlSecondLevelSequenceTest);
    UtRegisterTest("ConfYamlFileIncludeTest", ConfYamlFileIncludeTest);
    UtRegisterTest("ConfYamlOverrideTest", ConfYamlOverrideTest);
    UtRegisterTest("ConfYamlOverrideFinalTest", ConfYamlOverrideFinalTest);
    UtRegisterTest("ConfYamlNull", ConfYamlNull);
#endif /* UNITTESTS */
}
