#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_BRANCH="${RELEASE_BRANCH:-master}"

sanitize_version_identifier() {
    local raw="${1:-}"
    local fallback="${2:-build}"
    local max_length="${3:-32}"
    local sanitized

    sanitized=$(printf "%s" "$raw" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^0-9a-z-]+/-/g; s/-+/-/g; s/^-+//; s/-+$//')

    if [[ -z "$sanitized" ]]; then
        sanitized="$fallback"
    fi

    if [[ "$sanitized" =~ ^[0-9]+$ ]]; then
        sanitized="${fallback}-${sanitized}"
    fi

    sanitized="${sanitized:0:max_length}"
    sanitized=$(printf "%s" "$sanitized" | sed -E 's/^-+//; s/-+$//')

    if [[ -z "$sanitized" ]]; then
        sanitized="$fallback"
    fi

    printf "%s" "$sanitized"
}

current_branch_name() {
    local branch_name

    if [[ -n "${GITHUB_HEAD_REF:-}" ]]; then
        branch_name="$GITHUB_HEAD_REF"
    elif [[ -n "${GITHUB_REF_NAME:-}" ]]; then
        branch_name="$GITHUB_REF_NAME"
    else
        branch_name=$(git branch --show-current 2>/dev/null || true)
        if [[ -z "$branch_name" ]]; then
            branch_name=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
        fi
    fi

    if [[ -z "$branch_name" || "$branch_name" == "HEAD" ]]; then
        branch_name="branch"
    fi

    printf "%s" "$branch_name"
}

build_identifier() {
    if [[ -n "${NUGET_VERSION_IDENTIFIER:-}" ]]; then
        printf "%s" "$NUGET_VERSION_IDENTIFIER"
    elif [[ -n "${GITHUB_RUN_NUMBER:-}" ]]; then
        printf "run-%s-%s" "$GITHUB_RUN_NUMBER" "${GITHUB_RUN_ATTEMPT:-1}"
    elif [[ -n "${GITHUB_RUN_ID:-}" ]]; then
        printf "run-%s-%s" "$GITHUB_RUN_ID" "${GITHUB_RUN_ATTEMPT:-1}"
    else
        git rev-parse --short=12 HEAD
    fi
}

dev_version_suffix() {
    local revision="$1"
    local branch_name="$2"
    local padded

    padded=$(printf "%04d" "$revision")
    if [[ "$branch_name" == "$RELEASE_BRANCH" ]]; then
        printf "cibuild%s" "$padded"
        return
    fi

    printf "%s.%s" \
        "$(sanitize_version_identifier "$branch_name" "branch" 32)" \
        "$(sanitize_version_identifier "$(build_identifier)" "build" 24)"
}

VERSION=$(git describe --abbrev=0 --tags)
REVISION=$(git rev-list --count "$VERSION..HEAD")

re="([0-9]+\.[0-9]+\.[0-9]+)"
if [[ $VERSION =~ $re ]]; then
    VERSION_STR="${BASH_REMATCH[1]}"

    if [[ "$REVISION" != "0" ]]; then
        LAST_PART="${VERSION_STR##*.}"
        LAST_PART=$((LAST_PART + 1))
        VERSION_STR="${VERSION_STR%.*}.${LAST_PART}"

        VERSION_STR="$VERSION_STR-$(dev_version_suffix "$REVISION" "$(current_branch_name)")"
    fi

    echo "Version is now: $VERSION_STR"
else
    echo "Unable to derive a NuGet version from tag '$VERSION'." >&2
    exit 1
fi

PACKAGE_PATH="${SCRIPT_DIR}/IPTables.Net/bin/Release/IPTables.Net.${VERSION_STR}.nupkg"

dotnet pack "${SCRIPT_DIR}/IPTables.Net/IPTables.Net.csproj" --configuration Release /p:Version="$VERSION_STR"
dotnet nuget push "$PACKAGE_PATH" --api-key "$NUGET_API_KEY" --source https://www.nuget.org/api/v2/package
