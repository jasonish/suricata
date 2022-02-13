#! /usr/bin/env python3

import yaml
import sys

print(yaml.load(open(sys.argv[1]).read(), Loader=yaml.SafeLoader))
