#!/bin/bash

DIR=$(dirname "$0")
VERSION=$(git describe --abbrev=0 --tags)
REVISION=$(git log "$VERSION..HEAD" --oneline | wc -l)

function update_ai {
	f="$1"
	lead='^\/\/ TRAVIS\-CI: START REMOVE$'
	tail='^\/\/ TRAVIS\-CI: END REMOVE$'
	C=$(sed -e "/$lead/,/$tail/{ /$lead/{p; r insert_file
        }; /$tail/p; d }" $f/Properties/AssemblyInfo.cs)
	echo "$C" > $f/Properties/AssemblyInfo.cs
	echo "[assembly: AssemblyVersion(\"$VERSION_STR\")]" >> $f/Properties/AssemblyInfo.cs
	echo "[assembly: AssemblyFileVersion(\"$VERSION_STR\")]" >> $f/Properties/AssemblyInfo.cs
	
	nuspec="$f/*.nuspec"
	echo "$nuspec"
	
	if [[ -f $nuspec ]]; then
		echo "Processing nuspec file: $nuspec"
		sed -i.bak "s/\$version\$/$VERSION_STR/g" $nuspec
	fi
}

re="([0-9]+\.[0-9]+\.[0-9]+)"
if [[ $VERSION =~ $re ]]; then
	VERSION_STR="${BASH_REMATCH[1]}.$REVISION"
	echo "Version is now: $VERSION_STR"
	update_ai $DIR/../IPTables.Net
	update_ai $DIR/../IPTables.Net.Tests
	update_ai $DIR/../IPTables.Net.TestFramework
fi