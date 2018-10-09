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

def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)

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
