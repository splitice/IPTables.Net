#!/bin/bash

set -e

DIR=$(realpath $(dirname "$0"))
P=$DIR/../$1

cd $P

ls bin/Release
mono --runtime=v4.0 ../.nuget/NuGet.exe pack IPTables.Net.nuspec -Prop Configuration=Release -BasePath $P

mono --runtime=v4.0 ../.nuget/NuGet.exe push *.nupkg -ApiKey $NUGET_API