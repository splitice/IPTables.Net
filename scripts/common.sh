#!/usr/bin/env bash

COMMON_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$COMMON_DIR/.." && pwd)"
readonly CORE_DUMP_EXIT_CODE=86

log() {
    printf '[%s] %s\n' "$1" "$2"
}

info() {
    log INFO "$*"
}

warn() {
    log WARN "$*" >&2
}

die() {
    log ERROR "$*" >&2
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

list_core_dumps() {
    find "$REPO_ROOT" -maxdepth 1 -type f \( -name 'core' -o -name 'core.*' \) -printf '%f\n' | LC_ALL=C sort
}

run_and_check_core_dumps() {
    local before_file
    local after_file
    local status
    local new_core_dumps

    before_file="$(mktemp)"
    after_file="$(mktemp)"

    list_core_dumps >"$before_file"

    if "$@"; then
        status=0
    else
        status=$?
    fi

    list_core_dumps >"$after_file"
    new_core_dumps="$(comm -13 "$before_file" "$after_file" || true)"
    rm -f -- "$before_file" "$after_file"

    if [[ -n "$new_core_dumps" ]]; then
        warn "Core dumps were produced while running: $*"
        while IFS= read -r core_dump; do
            [[ -n "$core_dump" ]] || continue
            warn "  ${REPO_ROOT}/${core_dump}"
        done <<< "$new_core_dumps"
        return "$CORE_DUMP_EXIT_CODE"
    fi

    return "$status"
}

detect_required_dotnet_channel() {
    local token
    local version
    local major
    local minor
    local best_major=0
    local best_minor=0

    while IFS= read -r token; do
        version="${token#net}"
        major="${version%%.*}"
        minor="${version#*.}"

        [[ "$major" =~ ^[0-9]+$ ]] || continue
        [[ "$minor" =~ ^[0-9]+$ ]] || continue

        if (( major > best_major || (major == best_major && minor > best_minor) )); then
            best_major="$major"
            best_minor="$minor"
        fi
    done < <(grep -RhoE 'net[0-9]+\.[0-9]+' "$REPO_ROOT" --include='*.csproj' 2>/dev/null || true)

    if (( best_major == 0 )); then
        printf '8.0\n'
        return
    fi

    printf '%s.%s\n' "$best_major" "$best_minor"
}

normalize_configuration() {
    local value="${1:-Release}"

    case "${value,,}" in
        debug)
            printf 'Debug\n'
            ;;
        release)
            printf 'Release\n'
            ;;
        *)
            printf '%s\n' "$value"
            ;;
    esac
}

is_linux() {
    [[ "$(uname -s)" == "Linux" ]]
}

cpu_count() {
    if command_exists nproc; then
        nproc
        return
    fi

    getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
}

can_use_passwordless_sudo() {
    command_exists sudo && sudo -n true >/dev/null 2>&1
}

can_run_privileged() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || can_use_passwordless_sudo
}

run_as_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
        return
    fi

    if ! command_exists sudo; then
        return 1
    fi

    sudo "$@"
}

download_file() {
    local url="$1"
    local destination="$2"

    if command_exists curl; then
        curl -fsSL "$url" -o "$destination"
        return
    fi

    if command_exists wget; then
        wget -qO "$destination" "$url"
        return
    fi

    die "Neither curl nor wget is available to download $url"
}

setup_dotnet_env() {
    export DOTNET_CHANNEL="${DOTNET_CHANNEL:-$(detect_required_dotnet_channel)}"
    export DOTNET_INSTALL_DIR="${DOTNET_INSTALL_DIR:-$HOME/.dotnet}"
    export DOTNET_ROOT="$DOTNET_INSTALL_DIR"
    export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$HOME/.dotnet-cli}"
    export NUGET_PACKAGES="${NUGET_PACKAGES:-$HOME/.nuget/packages}"
    export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    export DOTNET_CLI_TELEMETRY_OPTOUT=1

    mkdir -p "$DOTNET_INSTALL_DIR" "$DOTNET_CLI_HOME" "$NUGET_PACKAGES"

    case ":$PATH:" in
        *":$DOTNET_INSTALL_DIR:"*) ;;
        *) export PATH="$DOTNET_INSTALL_DIR:$PATH" ;;
    esac
}

dotnet_sdk_available() {
    setup_dotnet_env
    local expected_major="${DOTNET_CHANNEL%%.*}"

    if ! command_exists dotnet; then
        return 1
    fi

    if [[ ! "$expected_major" =~ ^[0-9]+$ ]]; then
        expected_major=8
    fi

    dotnet --list-sdks 2>/dev/null | awk -F'[ .]' -v major="$expected_major" '{ if (($1 + 0) == major) found = 1 } END { exit(found ? 0 : 1) }'
}

ensure_dotnet() {
    setup_dotnet_env

    if dotnet_sdk_available; then
        return
    fi

    if ! command_exists curl && ! command_exists wget && is_linux; then
        local manager
        manager="$(detect_package_manager || true)"

        case "$manager" in
            apt-get)
                run_as_root apt-get update
                run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl
                ;;
            dnf)
                run_as_root dnf install -y curl
                ;;
            yum)
                run_as_root yum install -y curl
                ;;
            apk)
                run_as_root apk add --no-cache curl
                ;;
            zypper)
                run_as_root zypper --non-interactive install curl
                ;;
        esac
    fi

    info "Installing .NET SDK ${DOTNET_CHANNEL} into ${DOTNET_INSTALL_DIR}"
    local installer="${DOTNET_INSTALL_DIR}/dotnet-install.sh"
    download_file "https://dot.net/v1/dotnet-install.sh" "$installer"
    chmod +x "$installer"
    "$installer" --channel "$DOTNET_CHANNEL" --install-dir "$DOTNET_INSTALL_DIR" --quality ga

    dotnet_sdk_available || die "Unable to find a usable .NET SDK after installation."
}

detect_package_manager() {
    local manager
    for manager in apt-get dnf yum apk zypper; do
        if command_exists "$manager"; then
            printf '%s\n' "$manager"
            return 0
        fi
    done

    return 1
}

helper_build_requirements_present() {
    if ! is_linux; then
        return 1
    fi

    command_exists make || return 1
    command_exists gcc || return 1
    command_exists g++ || return 1
    command_exists iptables || return 1
    [[ -e /usr/include/xtables.h ]] || return 1
    [[ -e /usr/include/libiptc/libiptc.h ]] || return 1

    if [[ ! -e /usr/include/libnl3/netlink/msg.h && ! -e /usr/include/libnl3/libnl3/netlink/msg.h ]]; then
        return 1
    fi

    if [[ ! -e /usr/include/pcap/pcap.h && ! -e /usr/include/pcap.h ]]; then
        return 1
    fi

    return 0
}

ensure_linux_build_dependencies() {
    if ! is_linux; then
        return
    fi

    if helper_build_requirements_present; then
        return
    fi

    local manager
    manager="$(detect_package_manager)" || die "No supported package manager was found. Install the iptables development dependencies manually."

    info "Installing Linux dependencies required for libipthelper via ${manager}"

    case "$manager" in
        apt-get)
            run_as_root apt-get update
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                build-essential ca-certificates curl iptables kmod libip4tc-dev libip6tc-dev \
                libiptc-dev libnl-3-dev libpcap0.8-dev libxtables-dev make pkg-config
            ;;
        dnf)
            run_as_root dnf install -y \
                ca-certificates curl gcc gcc-c++ iptables iptables-devel kmod libnl3-devel \
                libpcap-devel make pkgconf-pkg-config
            ;;
        yum)
            run_as_root yum install -y \
                ca-certificates curl gcc gcc-c++ iptables iptables-devel kmod libnl3-devel \
                libpcap-devel make pkgconfig
            ;;
        apk)
            run_as_root apk add --no-cache \
                bash build-base curl iptables iptables-dev kmod libnl3-dev libpcap-dev make pkgconf
            ;;
        zypper)
            run_as_root zypper --non-interactive install \
                ca-certificates curl gcc gcc-c++ iptables iptables-devel kmod libnl3-devel \
                libpcap-devel make pkg-config
            ;;
        *)
            die "Unsupported package manager: ${manager}"
            ;;
    esac

    helper_build_requirements_present || die "libipthelper dependencies are still missing after package installation."
}

export_ipthelper_path() {
    local config="$1"
    local helper_dir="${REPO_ROOT}/ipthelper/${config}"

    if [[ ! -d "$helper_dir" ]]; then
        return
    fi

    case ":${LD_LIBRARY_PATH:-}:" in
        *":${helper_dir}:"*) ;;
        *) export LD_LIBRARY_PATH="${helper_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" ;;
    esac
}

build_ipthelper() {
    local config="${1:-Release}"

    if ! is_linux; then
        warn "Skipping libipthelper build because the native helper is Linux-only."
        return
    fi

    ensure_linux_build_dependencies

    local helper_dir="${REPO_ROOT}/ipthelper"
    local extra_cflags="${IPTHELPER_ADDITIONAL_CFLAGS:-${ADDITIONAL_CFLAGS:-}}"
    local jobs="${BUILD_JOBS:-$(cpu_count)}"
    local compat_cflags

    info "Building libipthelper (${config})"

    local build_status
    if run_and_check_core_dumps make -C "$helper_dir" -j"$jobs" CONFIG="$config" ADDITIONAL_CFLAGS="$extra_cflags"; then
        build_status=0
    else
        build_status=$?
    fi

    if (( build_status != 0 )); then
        if (( build_status == CORE_DUMP_EXIT_CODE )); then
            die "libipthelper build produced a core dump."
        fi

        if [[ "$extra_cflags" == *"-DOLD_IPTABLES"* ]]; then
            die "libipthelper build failed even with OLD_IPTABLES enabled."
        fi

        warn "Retrying libipthelper build with OLD_IPTABLES compatibility enabled."
        make -C "$helper_dir" clean CONFIG="$config" >/dev/null 2>&1 || true
        compat_cflags="${extra_cflags:+${extra_cflags} }-DOLD_IPTABLES"
        if run_and_check_core_dumps make -C "$helper_dir" -j"$jobs" CONFIG="$config" ADDITIONAL_CFLAGS="$compat_cflags"; then
            build_status=0
        else
            build_status=$?
        fi

        if (( build_status == CORE_DUMP_EXIT_CODE )); then
            die "libipthelper build produced a core dump."
        fi

        (( build_status == 0 )) || die "libipthelper build failed with OLD_IPTABLES compatibility enabled."
    fi

    [[ -f "${helper_dir}/${config}/libipthelper.so" ]] || die "Expected ${helper_dir}/${config}/libipthelper.so to be produced."
    export_ipthelper_path "$config"
}

dotnet_restore() {
    local target="${1:-${REPO_ROOT}/IPTables.Net.sln}"
    shift || true

    (
        cd "$REPO_ROOT"
        run_and_check_core_dumps dotnet restore "$target" --nologo -m:1 "$@"
    )
}

dotnet_build() {
    local target="${1:-${REPO_ROOT}/IPTables.Net.sln}"
    local configuration="${2:-Release}"
    shift 2 || true

    (
        cd "$REPO_ROOT"
        run_and_check_core_dumps dotnet build "$target" --configuration "$configuration" --no-restore --nologo \
            -m:1 -p:UseSharedCompilation=false "$@"
    )
}

dotnet_test() {
    local target="$1"
    local configuration="${2:-Release}"
    shift 2 || true

    (
        cd "$REPO_ROOT"
        run_and_check_core_dumps dotnet test "$target" --configuration "$configuration" --no-build --no-restore --nologo \
            -m:1 -p:UseSharedCompilation=false "$@"
    )
}
