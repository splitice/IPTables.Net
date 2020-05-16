#!/bin/sh

set -e

ldconfig -p | grep ipt

bash ./ipthelper/test/build.sh
# ./ipthelper/test/main

sudo mono --debug /usr/lib/nunit/nunit-console.exe -framework=4.0 -config=Debug ./IPTables.Net.Tests/bin/Debug/IPTables.Net.Tests.dll -exclude Integration,NotWorkingOnMono,NotWorkingOnTravis

set +e

n=0
until [ "$n" -ge 5 ]
do
    bash travis-ci/nuget-upload.sh IPTables.Net
    if [[ $? == "0" ]]; then
        exit 0
    fi
done
exit 1