#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. We recommend using a
# package manager.

set -e

LIBSODIUM_INSTALL_PATH=`pwd`/sodium

if [ ! -f "sodium/include/sodium.h" ]; then
	set -x

	mkdir -p "$LIBSODIUM_INSTALL_PATH"
	find "$LIBSODIUM_INSTALL_PATH"

	wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	tar xfz LATEST.tar.gz
	cd libsodium-stable
	./configure --prefix="$LIBSODIUM_INSTALL_PATH"
	make
	make install
else
	echo "using cached libsodium build"
	find "$LIBSODIUM_INSTALL_PATH"
fi
