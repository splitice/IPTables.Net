#!/bin/bash

CONFIG="Release" make ADDITIONAL_CFLAGS=$(printenv ADDITIONAL_CFLAGS)
cp Release/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"