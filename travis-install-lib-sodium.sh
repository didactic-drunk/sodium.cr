#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. Outside this environment,
# you would probably not want to install it like this.
#
# from: google/hat-backup

set -e

wget https://download.libsodium.org/libsodium/releases/libsodium-stable-2018-02-14.tar.gz
tar xvfz libsodium-stable-2018-02-14.tar.gz
cd libsodium-stable
sudo ./configure
sudo make
sudo make install
