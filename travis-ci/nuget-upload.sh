#!/bin/bash

set -e

DIR=$(realpath $(dirname "$0"))

cd $DIR/../IPTables.Net

ls bin/Release
mono --runtime=v4.0 ../travis-ci/nuget/NuGet.exe pack IPTables.Net.nuspec -Prop Configuration=Release -BasePath $DIR/../IPTables.Net/

mono --runtime=v4.0 ../travis-ci/nuget/NuGet.exe push *.nupkg -ApiKey $NUGET_API