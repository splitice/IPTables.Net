#!/bin/bash

make ADDITIONAL_CFLAGS=$(printenv ADDITIONAL_CFLAGS) CXX=$(printenv CXX) CONFIG="Release" 
cp Release/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"