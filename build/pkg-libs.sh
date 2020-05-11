#!/bin/bash

set -e

# Shard directory passed as first argument when called from lib_sodium.cr
[ ! -z "$1" ] && cd "$1"

./build/libsodium_install.sh > libsodium_install.out 2>&1 || (cat libsodium_install.out >&2 ; exit 2)

. ./build/env.sh

pkg-config libsodium --libs
