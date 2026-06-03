# AGENTS.md

## Overview

This repository contains a .NET 10 solution for working with Linux iptables from C#. The managed code lives under `IPTables.Net/`, the xUnit tests live under `IPTables.Net.Tests/`, and the native helper library used by the libiptc-based adapter lives under `ipthelper/`.

## Build And Test

- Use `./build.sh` for a full solution build.
- Use `./test.sh` to build and run tests.
- Use `./test.sh --fast` for the managed-heavy test pass that sets `SKIP_SYSTEM_TESTS=1`.
- Use `./test.sh --full` on Linux when root or passwordless `sudo` is available to run the stable native and system iptables tests.
- Use `./test.sh --full --iptables-backend legacy|nft|current` to choose the iptables backend explicitly. Full mode defaults to `legacy`.
- Set `RUN_UNSTABLE_SYSTEM_TESTS=1` with `./test.sh --full` to include tests marked `NotWorkingOnTravis`, including the conntrack coverage that can crash on some containerized hosts.

Both scripts will bootstrap a usable .NET SDK if `dotnet` is missing. By default they infer the needed SDK channel from the highest `TargetFramework` declared in the repo's `.csproj` files. On Linux they also build `libipthelper` and install missing native build dependencies through a supported package manager when needed.

## Native Helper Notes

- `ipthelper/` builds `libipthelper.so`, which is required for `IPTablesLibAdapter`, `IptcInterface`, and the conntrack/native tests.
- The helper links against the system iptables development libraries, `libnl3`, and `libpcap`.
- The scripts first try a normal helper build and then retry with `-DOLD_IPTABLES` if the local iptables headers are older.
- `test.sh --full` defaults to the `iptables-legacy` / `ip6tables-legacy` alternatives because that matches the native test expectations more closely.
- Pass `--iptables-backend current` if you need to keep the host's existing backend, or `--iptables-backend nft` to exercise the nft variants explicitly.

## Testing Guidance

- Fast mode is the safest default when you only need parser, model, or mocked adapter coverage.
- Full mode touches the real machine state. The system tests create and mutate chains like `test`, `test2`, and `test3`, and the opt-in conntrack tests hit kernel networking APIs directly.
- If full mode fails because the host lacks privileges, kernel modules, or compatible iptables backends, rerun with `./test.sh --fast` unless you are specifically changing native or system behavior.

## Development Guidance

- Keep changes narrow and add or update xUnit coverage in `IPTables.Net.Tests/` when behavior changes.
- Prefer following the existing project layout instead of introducing new abstractions unless the current design is clearly blocking the work.
- When changing native interop behavior, verify both the managed call sites in `IPTables.Net/Iptables/NativeLibrary/` and the corresponding code in `ipthelper/`.
- The tests project is also the best source of usage examples for the public API.
