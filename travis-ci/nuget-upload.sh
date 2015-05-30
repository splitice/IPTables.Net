#!/bin/bash

set -e

DIR=$(dirname "$0")

cd $DIR/../IPTables.Net

mono ../.nuget/nuget pack IPTables.Net.csproj -Prop Configuration=Release

mono ../.nuget/nuget setApiKey $NUGET_API

mono ../.nuget/nuget push *.nupkg