#!/bin/sh

set -e

ldconfig -p | grep ipt

bash ./ipthelper/test/build.sh

sudo nunit-console -framework=4.0 ./IPTables.Net.Tests/bin/Debug/IPTables.Net.Tests.dll -exclude Integration,NotWorkingOnMono,NotWorkingOnTravis
travis_retry bash travis-ci/nuget-upload.sh IPTables.Net