#!/bin/bash

DIR=$(dirname "$0")

cd $DIR/../IPTables.net

mono ../.nuget/nuget pack IPTables.Net.csproj -Prop Configuration=Release