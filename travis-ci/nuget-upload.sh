#!/bin/bash

set -e

DIR=$(dirname "$0")

cd $DIR/../IPTables.Net

mono ../.nuget/NuGet.exe pack IPTables.Net.csproj -Prop Configuration=Release

mono ../.nuget/NuGet.exe setApiKey $NUGET_API

mono ../.nuget/NuGet.exe push *.nupkg