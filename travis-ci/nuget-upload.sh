#!/bin/bash

set -e

DIR=$(realpath $(dirname "$0"))
P=$DIR/../$1

cd $P

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
	nuget pack *.nuspec -Prop Configuration=Release -BasePath $P

	nuget push *.nupkg -ApiKey $NUGET_API
fi