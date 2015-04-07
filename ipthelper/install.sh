#!/bin/bash

CONFIG="Release" make
cp Release/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"