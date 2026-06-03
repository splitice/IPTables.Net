#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "${SCRIPT_DIR}/scripts/common.sh"

CONFIGURATION="$(normalize_configuration "${CONFIGURATION:-Release}")"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: ./build.sh [dotnet build arguments...]

Environment:
  CONFIGURATION            Build configuration to use for dotnet and libipthelper. Default: Release
  DOTNET_CHANNEL           .NET SDK channel to install when dotnet is absent. Default: highest
                           target framework detected from the repository's csproj files
  IPTHELPER_ADDITIONAL_CFLAGS
                           Extra C compiler flags passed to the native helper build.
  BUILD_JOBS               Parallel make job count. Default: detected CPU count
EOF
    exit 0
fi

info "Preparing build environment"
ensure_dotnet

if is_linux; then
    build_ipthelper "$CONFIGURATION"
fi

info "Restoring NuGet packages"
dotnet_restore "${REPO_ROOT}/IPTables.Net.sln"

info "Building solution (${CONFIGURATION})"
dotnet_build "${REPO_ROOT}/IPTables.Net.sln" "$CONFIGURATION" "$@"

info "Build completed successfully."
