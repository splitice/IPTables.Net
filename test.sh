#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "${SCRIPT_DIR}/scripts/common.sh"

CONFIGURATION="$(normalize_configuration "${CONFIGURATION:-Release}")"
TEST_MODE="${TEST_MODE:-auto}"
DOTNET_TEST_ARGS=()
ORIGINAL_IPTABLES_TARGET=""
ORIGINAL_IP6TABLES_TARGET=""
IPTABLES_BACKEND="${IPTABLES_BACKEND:-legacy}"
RUN_UNSTABLE_SYSTEM_TESTS="${RUN_UNSTABLE_SYSTEM_TESTS:-0}"

has_explicit_test_filter() {
    local arg
    for arg in "${DOTNET_TEST_ARGS[@]}"; do
        if [[ "$arg" == "--filter" || "$arg" == --filter=* ]]; then
            return 0
        fi
    done

    return 1
}

normalize_iptables_backend() {
    local value="${1:-legacy}"

    case "${value,,}" in
        legacy|nft|current)
            printf '%s\n' "${value,,}"
            ;;
        *)
            die "Unsupported iptables backend '${value}'. Expected one of: legacy, nft, current."
            ;;
    esac
}

resolve_command_path() {
    local command_path

    command_path="$(command -v "$1" 2>/dev/null)" || return 1

    if command_exists readlink; then
        readlink -f "$command_path" 2>/dev/null || printf '%s\n' "$command_path"
        return
    fi

    printf '%s\n' "$command_path"
}

restore_iptables_backend() {
    if [[ -n "$ORIGINAL_IPTABLES_TARGET" ]]; then
        run_as_root update-alternatives --set iptables "$ORIGINAL_IPTABLES_TARGET" >/dev/null 2>&1 || true
    fi

    if [[ -n "$ORIGINAL_IP6TABLES_TARGET" ]]; then
        run_as_root update-alternatives --set ip6tables "$ORIGINAL_IP6TABLES_TARGET" >/dev/null 2>&1 || true
    fi
}

switch_to_selected_backend() {
    local backend="$1"
    local current_v4
    local current_v6
    local desired_v4
    local desired_v6
    local resolved_current_v4
    local resolved_current_v6
    local resolved_desired_v4
    local resolved_desired_v6

    if [[ "$backend" == "current" ]]; then
        info "Using the current iptables backend for full-system tests"
        return
    fi

    desired_v4="$(command -v "iptables-${backend}" 2>/dev/null)" || die "The iptables-${backend} binary is required for --iptables-backend ${backend}."
    desired_v6="$(command -v "ip6tables-${backend}" 2>/dev/null)" || die "The ip6tables-${backend} binary is required for --iptables-backend ${backend}."
    resolved_current_v4="$(resolve_command_path iptables)" || die "The iptables binary is required for full system tests."
    resolved_current_v6="$(resolve_command_path ip6tables)" || die "The ip6tables binary is required for full system tests."
    resolved_desired_v4="$(resolve_command_path "iptables-${backend}")"
    resolved_desired_v6="$(resolve_command_path "ip6tables-${backend}")"

    if [[ "$resolved_current_v4" == "$resolved_desired_v4" && "$resolved_current_v6" == "$resolved_desired_v6" ]]; then
        info "Using iptables-${backend} for full-system tests"
        return
    fi

    if ! command_exists update-alternatives; then
        die "Cannot switch to the ${backend} backend because update-alternatives is unavailable. Use --iptables-backend current to keep the existing backend."
    fi

    current_v4="$(update-alternatives --query iptables 2>/dev/null | awk '/^Value: / { print $2 }')"
    current_v6="$(update-alternatives --query ip6tables 2>/dev/null | awk '/^Value: / { print $2 }')"
    if [[ -z "$current_v4" || -z "$current_v6" ]]; then
        die "Unable to determine the current iptables alternatives."
    fi

    if [[ "$resolved_current_v4" != "$resolved_desired_v4" ]]; then
        ORIGINAL_IPTABLES_TARGET="$current_v4"
        info "Switching iptables to the ${backend} backend for full-system tests"
        run_as_root update-alternatives --set iptables "$desired_v4"
    fi

    if [[ "$resolved_current_v6" != "$resolved_desired_v6" ]]; then
        ORIGINAL_IP6TABLES_TARGET="$current_v6"
        info "Switching ip6tables to the ${backend} backend for full-system tests"
        run_as_root update-alternatives --set ip6tables "$desired_v6"
    fi
}

load_kernel_modules() {
    if ! command_exists modprobe; then
        return
    fi

    local module
    for module in ip_tables iptable_filter iptable_mangle ip6_tables ip6table_filter ip6table_mangle nf_conntrack; do
        run_as_root modprobe "$module" >/dev/null 2>&1 || true
    done
}

cleanup_test_chains_for_binary() {
    local binary="$1"
    local chain

    if ! command_exists "$binary"; then
        return
    fi

    for chain in test test2 test3; do
        run_as_root "$binary" -F "$chain" >/dev/null 2>&1 || true
        run_as_root "$binary" -X "$chain" >/dev/null 2>&1 || true
    done
}

cleanup_test_chains() {
    local binary
    local -a binaries=(
        iptables
        iptables-legacy
        iptables-nft
        ip6tables
        ip6tables-legacy
        ip6tables-nft
    )

    for binary in "${binaries[@]}"; do
        cleanup_test_chains_for_binary "$binary"
    done
}

run_full_tests() {
    local results_dir
    local trap_command
    local -a effective_test_args=("${DOTNET_TEST_ARGS[@]}")
    results_dir="$(mktemp -d)"
    trap_command="$(printf 'rm -rf -- %q; cleanup_test_chains; restore_iptables_backend' "$results_dir")"
    trap "$trap_command" EXIT

    switch_to_selected_backend "$IPTABLES_BACKEND"
    load_kernel_modules

    command_exists iptables || die "The iptables binary is required for full system tests."
    command_exists ip6tables || die "The ip6tables binary is required for full system tests."
    cleanup_test_chains

    if [[ "$RUN_UNSTABLE_SYSTEM_TESTS" != "1" ]] && ! has_explicit_test_filter; then
        effective_test_args+=("--filter" "Category!=NotWorkingOnTravis")
    fi

    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        dotnet_test "${REPO_ROOT}/IPTables.Net.Tests/IPTables.Net.Tests.csproj" "$CONFIGURATION" \
            --results-directory "$results_dir" "${effective_test_args[@]}"
        return
    fi

    run_and_check_core_dumps run_as_root env \
        "PATH=$PATH" \
        "DOTNET_ROOT=${DOTNET_ROOT}" \
        "DOTNET_CLI_HOME=/root/.dotnet-cli" \
        "NUGET_PACKAGES=${NUGET_PACKAGES}" \
        "DOTNET_CLI_TELEMETRY_OPTOUT=${DOTNET_CLI_TELEMETRY_OPTOUT}" \
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=${DOTNET_SKIP_FIRST_TIME_EXPERIENCE}" \
        "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
        "HOME=/root" \
        dotnet test "${REPO_ROOT}/IPTables.Net.Tests/IPTables.Net.Tests.csproj" \
        --configuration "$CONFIGURATION" \
        --no-build \
        --no-restore \
        --nologo \
        -m:1 \
        -p:UseSharedCompilation=false \
        --results-directory "$results_dir" \
        "${effective_test_args[@]}"
}

while (($# > 0)); do
    case "$1" in
        --fast)
            TEST_MODE="fast"
            ;;
        --full)
            TEST_MODE="full"
            ;;
        --configuration)
            shift
            [[ $# -gt 0 ]] || die "--configuration requires a value"
            CONFIGURATION="$(normalize_configuration "$1")"
            ;;
        --iptables-backend)
            shift
            [[ $# -gt 0 ]] || die "--iptables-backend requires a value"
            IPTABLES_BACKEND="$(normalize_iptables_backend "$1")"
            ;;
        --iptables-backend=*)
            IPTABLES_BACKEND="$(normalize_iptables_backend "${1#*=}")"
            ;;
        --help|-h)
            cat <<'EOF'
Usage: ./test.sh [--fast|--full] [--iptables-backend <legacy|nft|current>] [--configuration <Debug|Release>] [dotnet test arguments...]

Modes:
  --fast   Skip privileged/system iptables tests by setting SKIP_SYSTEM_TESTS=1.
  --full   Run the full xUnit suite, including native helper and system iptables tests.

Backend selection:
  --iptables-backend legacy   Use iptables-legacy/ip6tables-legacy for full-system tests. This is the default.
  --iptables-backend nft      Use iptables-nft/ip6tables-nft for full-system tests.
  --iptables-backend current  Keep the host's current iptables/ip6tables backend.

Default behavior:
  TEST_MODE=auto chooses --full on Linux when passwordless sudo/root is available,
  otherwise it falls back to --fast.

Environment:
  IPTABLES_BACKEND=legacy|nft|current sets the default full-test backend.
  RUN_UNSTABLE_SYSTEM_TESTS=1 includes tests marked NotWorkingOnTravis, such as
  the conntrack coverage that can crash on some containerized hosts.
EOF
            exit 0
            ;;
        *)
            DOTNET_TEST_ARGS+=("$1")
            ;;
    esac
    shift
done

IPTABLES_BACKEND="$(normalize_iptables_backend "$IPTABLES_BACKEND")"

if [[ "$TEST_MODE" == "auto" ]]; then
    if is_linux && can_run_privileged; then
        TEST_MODE="full"
    else
        TEST_MODE="fast"
    fi
fi

info "Preparing test environment (${TEST_MODE})"
ensure_dotnet

if is_linux; then
    if [[ "$TEST_MODE" == "full" ]]; then
        build_ipthelper "$CONFIGURATION"
    else
        if helper_build_requirements_present; then
            build_ipthelper "$CONFIGURATION"
        else
            warn "Skipping libipthelper build in fast mode because native dependencies are not installed."
        fi
    fi
fi

info "Restoring NuGet packages"
dotnet_restore "${REPO_ROOT}/IPTables.Net.sln"

info "Building solution (${CONFIGURATION})"
dotnet_build "${REPO_ROOT}/IPTables.Net.sln" "$CONFIGURATION"

if [[ "$TEST_MODE" == "fast" ]]; then
    info "Running tests with SKIP_SYSTEM_TESTS=1"
    SKIP_SYSTEM_TESTS=1 dotnet_test "${REPO_ROOT}/IPTables.Net.Tests/IPTables.Net.Tests.csproj" "$CONFIGURATION" "${DOTNET_TEST_ARGS[@]}"
else
    info "Running the full test suite"
    run_full_tests
fi

info "Tests completed successfully."
