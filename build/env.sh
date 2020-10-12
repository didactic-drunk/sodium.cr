#!/bin/bash

# Overridable.
[ -z "$LIBSODIUM_BUILD_DIR" ] && LIBSODIUM_BUILD_DIR=`pwd`/build


# Upgraded from time to time.
export MIN_LIBSODIUM_VERSION=1.0.18
export LIBSODIUM_SHA256=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1


[ ! -z "$SODIUM_BUILD_DEBUG" ] && export SODIUM_BUILD_VERBOSE=1

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

if `pkg-config libsodium --exists`; then
	PKG_VER=`pkg-config libsodium --modversion`

	if [ $(version "$PKG_VER") -ge $(version "$MIN_LIBSODIUM_VERSION") ]; then
		[ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Using packaged libsodium."
	else
		[ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "System packaged libsodium is too old."
		export LIBSODIUM_INSTALL=1
	fi
else
	[ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Missing libsodium system package."
	export LIBSODIUM_INSTALL=1
fi


if [ "$LIBSODIUM_INSTALL" = "1" ]; then
	export LIBSODIUM_INSTALL_PATH="$LIBSODIUM_BUILD_DIR"/libsodium
	export PKG_CONFIG_PATH="$LIBSODIUM_INSTALL_PATH"/lib/pkgconfig
fi
