# Example Flow Logging Plugin

This is an example of a low level flow logging plugin.

## Building

In in the Suricata source code and you did not use the
`--disable-shared` `./configure` option, you should be able to just
run `make` to build the plugin.

Note that due to Automake and friends, the plugin will be compiled to
`.libs/flowlogger.so.0.0.0`.

### Standalone Building

The file `Makefile.example` is an example of how you might build a
plugin that is distributed separately from the Suricata source code.
It has the following dependencies:

- Suricata is installed
- The Suricata library is installed: `make install-library`
- The Suricata development headers are installed: `make install-headers`
- The program `libsuricata-config` is in your path (installed with `make install-library`)

Then run: `make -f Makefile.example`
