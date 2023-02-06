#! /usr/bin/env bash
#
# Helper script for Fedora build as a non-root user.
#
# We break the build up into parts that need to be called individually
# to avoid outputting too much data in a single step so we can see the
# output in the UI.

set -e
set -x

export PATH="$HOME/.cargo/bin:$PATH"

case "$1" in
    cbindgen)
        # Setup cbindgen.
        mkdir -p $HOME/.cargo/bin
        cp prep/cbindgen $HOME/.cargo/bin
        chmod 755 $HOME/.cargo/bin/cbindgen
        ;;
    autogen)
        ./autogen.sh
        ;;
    configure)
            ./configure \
            --enable-debug \
            --enable-unittests \
            --disable-shared \
            --enable-rust-strict \
            --enable-hiredis \
            --enable-nfqueue
        ;;
    make)
        make -j2
        ;;
    unit-test)
        ASAN_OPTIONS="detect_leaks=0" make check
        ;;
    verify)
        python3 ./suricata-verify/run.py -q
        ;;
esac
