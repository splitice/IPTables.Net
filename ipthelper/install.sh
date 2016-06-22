#!/bin/bash

CONFIG=$(printenv CONFIG)
if [[ -z "$CONFIG" ]]; then
	CONFIG="Release"
fi
CXX=$(printenv CXX)
if [[ -z "$CXX" ]]; then
	CXX="g++"
fi

make ADDITIONAL_CFLAGS=$(printenv ADDITIONAL_CFLAGS) CXX="$CXX" CONFIG="$CONFIG" 
cp $CONFIG/libipthelper.so /usr/lib/
ldconfig -n /usr/lib

echo "Installation Complete"