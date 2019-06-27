#!/bin/bash
# The purpose of this file is to install libsodium when:
# 1. No packaged version is found.
# 2. The packaged version is older than the version specified in this repository.
# pkg-config is used to find the library and determine it's version.
# You may replace the libsodium library with your own installed version by setting PKG_CONFIG_PATH before compiling.

set -e

# Always use bash.  `dash` doesn't work properly with . includes.  I'm not sure why.
. ./build/env.sh

#export LIBSODIUM_INSTALL=1
if [ "$LIBSODIUM_INSTALL" != "1" ]; then
	[ ! -z "$COX_BUILD_VERBOSE" ] echo "Skipping libsodium build."
	exit
fi


mkdir -p "$LIBSODIUM_BUILD_DIR"
cd "$LIBSODIUM_BUILD_DIR"


if [ ! -f "$LIBSODIUM_INSTALL_PATH/include/sodium.h" ]; then
	[ ! -z "$COX_BUILD_DEBUG" ] && set -x

	DIRNAME=libsodium-"$MIN_LIBSODIUM_VERSION"
	TGZ_FILENAME="$DIRNAME".tar.gz

	if [ ! -f "$TGZ_FILENAME" ]; then
		wget https://download.libsodium.org/libsodium/releases/"$TGZ_FILENAME"
#		wget https://download.libsodium.org/libsodium/releases/"$TGZ_FILENAME".minisign
	fi

	SHA=`openssl sha256 -hex < "$TGZ_FILENAME" | sed 's/^.* //'`
	if [ "$SHA" != "$LIBSODIUM_SHA256" ]; then
		echo "SHA256 sum doesn't match."
		echo "$SHA" != "$LIBSODIUM_SHA256"
		exit 1
	fi

	if [ ! -d "$DIRNAME" ]; then
		tar xfz "$TGZ_FILENAME"
	fi


	cd "$DIRNAME"
	if [ ! -f ".configure.done" ]; then
		./configure --prefix="$LIBSODIUM_INSTALL_PATH" --disable-shared
		touch .configure.done
	fi
	if [ ! -f ".make.done" ]; then
		make
		touch .make.done
	fi
	if [ ! -f ".make.install.done" ]; then
		make install
		touch .make.install.done
	fi

	[ ! -z "$COX_BUILD_VERBOSE" ] && echo "Finished building libsodium."
else
#	find "$LIBSODIUM_INSTALL_PATH"

	[ ! -z "$COX_BUILD_VERBOSE" ] && echo "Using already built libsodium."
fi

exit 0
