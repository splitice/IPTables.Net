#!/bin/bash

set -e

DIR=$(realpath $(dirname "$0"))
P=$DIR/../$1

cd $P

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
	mono --runtime=v4.0 ../.nuget/NuGet.exe pack *.nuspec -Prop Configuration=Release -BasePath $P

	mono --runtime=v4.0 ../.nuget/NuGet.exe push *.nupkg -ApiKey $NUGET_API
fi