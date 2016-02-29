#!/bin/bash

CONFIG=$(printenv CONFIG)
if [[ -z "$CONFIG" ]]; then
	CONFIG="Release"
fi

make ADDITIONAL_CFLAGS=$(printenv ADDITIONAL_CFLAGS) CXX=$(printenv CXX) CONFIG="$CONFIG" 
cp Release/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"