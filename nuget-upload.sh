set -e

DIR=~/repo
P=$DIR/$1

cd $P


VERSION=$(git describe --abbrev=0 --tags)
REVISION=$(git log "$VERSION..HEAD" --oneline | wc -l)

re="([0-9]+\.[0-9]+\.[0-9]+)"
if [[ $VERSION =~ $re ]]; then
    VERSION_STR="${BASH_REMATCH[1]}"

    padded=$(printf "%04d" $REVISION)
    if [[ "$REVISION" != "0" ]]; then
        LAST_PART=$(echo "$VERSION_STR" | sed 's/.\+\([0-9]\+\)$/\1/')
        let LAST_PART=$LAST_PART+1
        VERSION_STR=$(echo "$VERSION_STR" | sed 's/\.\([0-9]\+\)$/.'$LAST_PART'/')

        VERSION_STR="$VERSION_STR-cibuild$padded"
    fi

    echo "Version of $1 is now: $VERSION_STR"
fi

if [ "${CIRCLE_PULL_REQUEST}" = "" ]; then
    dotnet pack --configuration Release /p:Version=$VERSION_STR
    dotnet nuget push bin/Release/*.nupkg --api-key $NUGET_API -s https://www.nuget.org/api/v2/package
fi