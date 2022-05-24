#! /usr/bin/env python3

import yaml
import sys

class IncludeTag(yaml.YAMLObject):
    yaml_tag = u'!include'

    @classmethod
    def from_yaml(cls, loader, node):
        return "<would include {}>".format(node.value)

yaml.SafeLoader.add_constructor('!include', IncludeTag.from_yaml)

print(yaml.load(open(sys.argv[1]).read(), Loader=yaml.SafeLoader))
