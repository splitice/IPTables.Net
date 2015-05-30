#!/bin/bash

DIR=$(dirname "$0")
VERSION=$(git describe --abbrev=0 --tags)
REVISION=$(git log "$VERSION..HEAD" --oneline | wc -l)

function update_ai {
	lead='^\/\/ TRAVIS\-CI: START REMOVE$'
	tail='^\/\/ TRAVIS\-CI: END REMOVE$'
	C=$(sed -e "/$lead/,/$tail/{ /$lead/{p; r insert_file
        }; /$tail/p; d }" $f)
	echo "$C" > $f
	echo "[assembly: AssemblyVersion(\"$VERSION_STR\")]" >> $f
	echo "[assembly: AssemblyFileVersion(\"$VERSION_STR\")]" >> $f
	cat $f
}

re="([0-9]+\.[0-9]+\.[0-9]+)"
if [[ $VERSION =~ $re ]]; then
	VERSION_STR="${BASH_REMATCH[1]}.$REVISION"
	echo "Version is now: $VERSION_STR"
	update_ai $DIR/../IPTables.Net/Properties/AssemblyInfo.cs
	update_ai $DIR/../IPTables.Net.Tests/Properties/AssemblyInfo.cs
	update_ai $DIR/../IPTables.Net.TestFramework/Properties/AssemblyInfo.cs
fi