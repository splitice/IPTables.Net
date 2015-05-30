#!/bin/bash

set -e

DIR=$(dirname "$0")

cd $DIR/../IPTables.Net

mono --runtime=v4.0 ../.nuget/NuGet.exe pack IPTables.Net.csproj -Prop Configuration=Release

mono --runtime=v4.0 ../.nuget/NuGet.exe setApiKey $NUGET_API

mono --runtime=v4.0 ../.nuget/NuGet.exe push *.nupkg