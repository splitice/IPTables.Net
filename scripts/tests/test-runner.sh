#!/usr/bin/env bash
# Exercises the real entry points with fake process/build boundaries. No sudo or firewall access.
set -euo pipefail
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/scripts" "$scratch/bin"
cp "$repo/test.sh" "$repo/build.sh" "$scratch/"
cp "$repo/scripts/common.sh" "$scratch/scripts/common.sh"
cat >> "$scratch/scripts/common.sh" <<'STUB'
is_linux() { [[ "${FAKE_LINUX:-1}" == 1 ]]; }
can_run_privileged() { [[ "${FAKE_PRIVILEGED:-1}" == 1 ]]; }
ensure_dotnet() {
    echo ensure >> "$FAKE_LOG"
    export DOTNET_ROOT=/fake NUGET_PACKAGES=/fake DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
}
helper_build_requirements_present() { return 1; }
build_ipthelper() { echo helper >> "$FAKE_LOG"; }
run_as_root() {
    echo "root $*" >> "$FAKE_LOG"
    case "$1" in
        env|update-alternatives|modprobe|iptables*|ip6tables*) "$@" ;;
        *) echo "Unexpected privileged command: $*" >&2; exit 99 ;;
    esac
}
STUB
cat > "$scratch/bin/dotnet" <<'STUB'
#!/usr/bin/env bash
printf 'dotnet %s\n' "$*" >> "$FAKE_LOG"
if [[ "$1" == test ]]; then
    echo "skip=${SKIP_SYSTEM_TESTS:-unset} cpu=${DOTNET_PROCESSOR_COUNT:-unset} heap=${DOTNET_GCHeapHardLimit:-unset}" >> "$FAKE_LOG"
    exit "${FAKE_TEST_STATUS:-0}"
fi
STUB
cat > "$scratch/bin/update-alternatives" <<'STUB'
#!/usr/bin/env bash
printf 'alternatives %s\n' "$*" >> "$FAKE_LOG"
if [[ "$1" == --query ]]; then echo "Value: /original/$2"; fi
if [[ "${FAKE_SWITCH_FAIL:-0}" == 1 && "$*" == *'--set ip6tables '*legacy ]]; then exit 9; fi
STUB
for binary in iptables ip6tables iptables-legacy ip6tables-legacy iptables-nft ip6tables-nft modprobe; do
    cat > "$scratch/bin/$binary" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$FAKE_LOG"
STUB
done
chmod +x "$scratch/bin/"*
export PATH="$scratch/bin:$PATH" FAKE_LOG="$scratch/commands"
export DOTNET_PROCESSOR_COUNT=2 DOTNET_GCHeapHardLimit=0x40000000
cases=0
run() {
    local expected="$1"; shift
    : > "$FAKE_LOG"
    local status=0
    "$@" > "$scratch/output" 2>&1 || status=$?
    if [[ "$status" != "$expected" ]]; then cat "$scratch/output"; echo "Expected $expected, got $status: $*" >&2; exit 1; fi
    cases=$((cases + 1))
}
has() { grep -Fq -- "$1" "$FAKE_LOG" || { cat "$FAKE_LOG"; echo "Missing: $1" >&2; exit 1; }; }
lacks() { if grep -Fq -- "$1" "$FAKE_LOG"; then cat "$FAKE_LOG"; echo "Unexpected: $1" >&2; exit 1; fi; }
run 0 "$scratch/test.sh" --help
lacks ensure
run 0 "$scratch/build.sh" --help
lacks ensure
run 1 "$scratch/test.sh" --configuration
run 1 "$scratch/test.sh" --iptables-backend
run 1 "$scratch/test.sh" --iptables-backend bogus
run 1 env TEST_MODE=bogus "$scratch/test.sh"
lacks ensure
run 0 env SKIP_SYSTEM_TESTS=0 "$scratch/test.sh" --fast --filter 'Name=managed'
has 'skip=1'; has 'Name=managed'; lacks 'root '; lacks 'Category!='
run 0 env TEST_MODE=auto FAKE_PRIVILEGED=0 "$scratch/test.sh"
has 'skip=1'; lacks 'root '
run 0 env TEST_MODE=auto FAKE_LINUX=0 "$scratch/test.sh"
has 'skip=1'; lacks helper
run 0 env TEST_MODE=auto SKIP_SYSTEM_TESTS=1 "$scratch/test.sh"
has 'skip=unset'; has 'Category!=NotWorkingOnTravis'; has 'cpu=2 heap=0x40000000'
has 'alternatives --set iptables /original/iptables'; has 'alternatives --set ip6tables /original/ip6tables'
run 0 "$scratch/test.sh" --full --iptables-backend current
lacks 'alternatives '; has 'iptables -X test3'
run 0 env RUN_UNSTABLE_SYSTEM_TESTS=1 "$scratch/test.sh" --full --iptables-backend=current
lacks 'Category!='
run 0 "$scratch/test.sh" --full --filter 'Name=native'
has 'Name=native'; lacks 'Category!='
run 0 "$scratch/test.sh" --full --filter=Name=native --iptables-backend=nft
has '--filter=Name=native'; has 'ip6tables-nft'; lacks 'Category!='
run 7 env FAKE_TEST_STATUS=7 "$scratch/test.sh" --full
has 'alternatives --set iptables /original/iptables'; has 'alternatives --set ip6tables /original/ip6tables'; has 'ip6tables-nft -X test3'
run 9 env FAKE_SWITCH_FAIL=1 "$scratch/test.sh" --full
has 'alternatives --set iptables /original/iptables'; has 'alternatives --set ip6tables /original/ip6tables'; has 'iptables -X test3'; lacks 'dotnet test'
run 0 "$scratch/build.sh" -p:Example=true
has 'dotnet build'; has '-p:Example=true'; has helper
printf 'Runner contracts: %s cases passed.\n' "$cases"
