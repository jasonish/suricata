#! /usr/bin/env python3
#
# Utility script for generating new Suricata subsystems.

import sys
import os
import os.path
import argparse
import io
import re

generators = {}

def register(cls):
    generators[cls._name] = {
        "name": cls._name,
        "description": cls._description,
        "class": cls,
    }

class SetupError(Exception):
    """Functions in this script can raise this error which will cause the
    application to abort displaying the provided error message, but
    without a stack trace.
    """
    pass

@register
class Parser:

    _name = "parser"
    _description = "Generate app-layer parser (C)"

    def __init__(self, args):
        self.args = args
        self.name = self.args.name

    @classmethod
    def register(cls, parser):
        parser.add_argument("name", help="Name of protocol")

    def run(self):
        if not self.name:
            raise SetupError("The protocol name cannot be empty.")
        if self.name[0] != self.name.upper()[0]:
            raise SetupError(
                "The protocol name must begin with an upper case letter.")
        if proto_exists(self.name):
            raise SetupError("Protocol already exists.")
        self.copy_templates()
        self.patch_makefile_am()
        self.patch_app_layer_protos_h()
        self.patch_app_layer_protos_c()
        self.patch_app_layer_detect_proto_c()
        self.patch_app_layer_parser_c()
        self.patch_suricata_yaml_in()

    def copy_templates(self):
        lower = self.name.lower()
        pairs = (
            ("src/app-layer-template.c",
             "src/app-layer-%s.c" % (lower)),
            ("src/app-layer-template.h",
             "src/app-layer-%s.h" % (lower)),
        )
        copy_templates(self.name, pairs)

    def patch_makefile_am(self):
        print("Patching src/Makefile.am.")
        output = io.StringIO()
        with open("src/Makefile.am") as infile:
            for line in infile:
                if line.startswith("app-layer-template.c"):
                    output.write(line.replace("template", self.name.lower()))
                output.write(line)
        open("src/Makefile.am", "w").write(output.getvalue())

    def patch_app_layer_protos_h(self):
        filename = "src/app-layer-protos.h"
        print("Patching %s." % (filename))
        output = io.StringIO()
        with open(filename) as infile:
            for line in infile:
                if line.find("ALPROTO_TEMPLATE,") > -1:
                    output.write(line.replace("TEMPLATE", self.name.upper()))
                output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_app_layer_protos_c(self):
        filename = "src/app-layer-protos.c"
        print("Patching %s." % (filename))
        output = io.StringIO()

        # Read in all the lines as we'll be doing some multi-line
        # duplications.
        inlines = open(filename).readlines()
        for i, line in enumerate(inlines):

            if line.find("case ALPROTO_TEMPLATE:") > -1:
                # Duplicate the section starting an this line and
                # including the following 2 lines.
                for j in range(i, i + 3):
                    temp = inlines[j]
                    temp = temp.replace("TEMPLATE", self.name.upper())
                    temp = temp.replace("template", self.name.lower())
                    output.write(temp)

            if line.find("return ALPROTO_TEMPLATE;") > -1:
                output.write(
                    line.replace("TEMPLATE", self.name.upper()).replace(
                        "template", self.name.lower()))

            output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_app_layer_detect_proto_c(self):
        upper = self.name.upper()
        filename = "src/app-layer-detect-proto.c"
        print("Patching %s." % (filename))
        output = io.StringIO()
        inlines = open(filename).readlines()
        for i, line in enumerate(inlines):
            if line.find("== ALPROTO_TEMPLATE)") > -1:
                output.write(inlines[i].replace("TEMPLATE", upper))
                output.write(inlines[i+1].replace("TEMPLATE", upper))
            output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_app_layer_parser_c(self):
        filename = "src/app-layer-parser.c"
        print("Patching %s." % (filename))
        output = io.StringIO()
        inlines = open(filename).readlines()
        for line in inlines:
            if line.find("app-layer-template.h") > -1:
                output.write(line.replace("template", self.name.lower()))
            if line.find("RegisterTemplateParsers()") > -1:
                output.write(line.replace("Template", self.name))
            output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_suricata_yaml_in(self):
        filename = "suricata.yaml.in"
        print("Patching %s." % (filename))
        output = io.StringIO()
        inlines = open(filename).readlines()
        for i, line in enumerate(inlines):
            if line.find("protocols:") > -1:
                if inlines[i-1].find("app-layer:") > -1:
                    output.write(line)
                    output.write("""    %s:
          enabled: yes
""" % (self.name.lower()))
                    # Skip writing out the current line, already done.
                    continue

            output.write(line)
        open(filename, "w").write(output.getvalue())

@register
class PacketLogger:

    _name = "packet-logger"
    _description = "Generate a JSON packet logger"

    def __init__(self, args):
        self.args = args
        self.name = args.name

    @classmethod
    def register(cls, parser):
        parser.add_argument("name", help="Name of packet logger")

    def run(self):
        # Make sure a logger with this name doesn't already exists.
        dst_filename_c = "src/output-json-%s.c" % (self.name.lower())
        if os.path.exists(dst_filename_c):
            raise SetupError("A logger with this name already exists.")
        self.copy_templates()
        self.patch_makefile_am()
        self.patch_suricata_common_h()
        self.patch_util_profiling_c()
        self.patch_output_c()

    def copy_templates(self):
        files = (
            ("src/output-json-template-packet.h",
             "src/output-json-%s.h" % (self.name.lower())),
            ("src/output-json-template-packet.c",
             "src/output-json-%s.c" % (self.name.lower())),
        )
        replacements = (
            ("template-packet", self.name.lower()),
            ("TemplatePacket", self.name),
            ("TEMPLATE_PACKET", self.name.upper()),
        )
        copy_templates(self.name, files, replacements)

    def patch_makefile_am(self):
        filename = "src/Makefile.am"
        print("Patching %s." % (filename))
        output = io.StringIO()
        with open(filename) as infile:
            for line in infile:
                if line.startswith("output-json-template-packet.c"):
                    output.write(
                        line.replace("template-packet",self.name.lower()))
                output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_suricata_common_h(self):
        filename = "src/suricata-common.h"
        print("Patching %s." % (filename))
        output = io.StringIO()
        with open(filename) as infile:
            for line in infile:
                if line.find("LOGGER_JSON_TEMPLATE_PACKET") > -1:
                    output.write(
                        line.replace("TEMPLATE_PACKET", self.name.upper()))
                output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_util_profiling_c(self):
        filename = "src/util-profiling.c"
        print("Patching %s." % (filename))
        output = io.StringIO()
        with open(filename) as infile:
            for line in infile:
                if line.find("LOGGER_JSON_TEMPLATE_PACKET") > -1:
                    output.write(
                        line.replace("TEMPLATE_PACKET", self.name.upper()))
                output.write(line)
        open(filename, "w").write(output.getvalue())

    def patch_output_c(self):
        filename = "src/output.c"
        print("Patching %s." % (filename))
        output = io.StringIO()
        with open(filename) as infile:
            for line in infile:
                if line.find("output-json-template-packet.h") > -1:
                    output.write(line.replace(
                        "template-packet", self.name.lower()))
                if line.find("Template JSON packet logger") > -1:
                    output.write("    /* %s packet logger. */\n" % (
                        self.name))
                    output.write("    Json%sLogRegister();\n" % (
                        self.name))
                output.write(line)
        open(filename, "w").write(output.getvalue())

def copy_templates(proto, pairs, replacements=()):
    upper = proto.upper()
    lower = proto.lower()

    for (src, dst) in pairs:
        fail_if_exists(dst)

    for (src, dst) in pairs:
        dstdir = os.path.dirname(dst)
        if not os.path.exists(dstdir):
            print("Creating directory %s." % (dstdir))
            os.makedirs(dstdir)
        print("Generating %s." % (dst))
        output = open(dst, "w")
        with open(src) as template_in:
            skip = False
            for line in template_in:
                if line.find("TEMPLATE_START_REMOVE") > -1:
                    skip = True
                    continue
                elif line.find("TEMPLATE_END_REMOVE") > -1:
                    skip = False
                    continue
                if skip:
                    continue

                for (old, new) in replacements:
                    line = line.replace(old, new)

                line = re.sub("TEMPLATE(_RUST)?", upper, line)
                line = re.sub("template(-rust)?", lower, line)
                line = re.sub("Template(Rust)?", proto, line)

                output.write(line)
        output.close()

def fail_if_exists(filename):
    if os.path.exists(filename):
        raise SetupError("%s already exists" % (filename))

def proto_exists(proto):
    upper = proto.upper()
    for line in open("src/app-layer-protos.h"):
        if line.find("ALPROTO_%s," % (upper)) > -1:
            return True
    return False

def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(generator=None)

    subparsers = parser.add_subparsers(title="commands")

    for generator in generators.values():
        sub = subparsers.add_parser(generator["name"])
        sub.set_defaults(generator=generator["name"])
        generator["class"].register(sub)

    args = parser.parse_args()
    if args.generator:
        generators[args.generator]["class"](args).run()
    else:
        max_name = max(
            [len(generator["name"]) for generator in generators.values()])
        print("""No generator provided.

Usage: generator.py <GENERATOR> [arguments...]

Generators:""")
        for generator in generators.values():
            print("    %s - %s" % (generator["name"].ljust(max_name),
                                   generator["description"]))

if __name__ == "__main__":
    try:
        sys.exit(main())
    except SetupError as err:
        print("error: %s" % (err))
        sys.exit(1)
