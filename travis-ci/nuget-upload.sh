#!/bin/bash

set -x
set -e

DIR=$(dirname "$0")

cd $DIR/../IPTables.Net

mono --runtime=v4.0 ../travis-ci/nuget/NuGet.exe pack IPTables.Net.nuspec -Prop Configuration=Release -BasePath ./

mono --runtime=v4.0 ../travis-ci/nuget/NuGet.exe setApiKey $NUGET_API

mono --runtime=v4.0 ../travis-ci/nuget/NuGet.exe push *.nupkg