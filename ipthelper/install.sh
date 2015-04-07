#!/bin/bash

CONFIG="Release" CFLAGS="$CFLAGS" make
cp Release/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"