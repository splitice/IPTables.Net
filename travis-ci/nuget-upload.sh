#!/bin/bash

set -e

DIR=$(realpath $(dirname "$0"))
P=$DIR/../$1

cd $P

sudo nuget update -self
sudo chmod 0777 /tmp/NuGetScratch -R

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
	nuget pack *.nuspec -Prop Configuration=Release -BasePath $P

	nuget push *.nupkg -ApiKey $NUGET_API -Verbosity detailed
fi