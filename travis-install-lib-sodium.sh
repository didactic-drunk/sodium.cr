#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. We recommend using a
# package manager.

set -e

wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar xvfz LATEST.tar.gz
cd libsodium-stable
sudo ./configure
sudo make
sudo make install
