# Gap 14: IPv6 native helper integration

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IptablesSystemTestSupport.IpVersion](../IPTables.Net.Tests/IptablesSystemTestSupport.cs) is constant 4. [IptcInterfaceTest](../IPTables.Net.Tests/IptcInterfaceTest.cs) contains alternate IPv6 strings, but its fixture never selects them. [IptcInterface](../IPTables.Net/Iptables/NativeLibrary/IptcInterface.cs) and [ipthelper](../ipthelper/ipthelper.c) expose separate IPv4/IPv6 entry points, so IPv4 success cannot validate IPv6 layout, serialization, or commit behavior.

## Tests to add

- Run independent IPv4 and IPv6 fixtures for chain discovery, rule output/input, add/insert/replace/delete, commit, and readback.
- Assert IPv6 source/destination prefixes, protocol/options, rule ordering, and counters using an independent `ip6tables-save` observation.
- Add IPv6-specific failed-commit diagnostics and verify no unintended installation. Do not reuse the IPv4 native entry layout from the incompatible-match test.
- Verify family switching after all handles are disposed; serialize fixtures around native global initialization.

## Completion

Use disposable Linux networking with root/capabilities, libipthelper, and compatible legacy binaries. Run the stable full suite for both families with explicit assertions that IPv6 tests executed; report unavailable prerequisites as skips. Do not merely change the shared constant and assume both families ran.

## Implementation record

Add separately parameterized IPv4/IPv6 native edit-and-commit tests with independent save/counter readback and an IPv6 ABI-specific incompatible-revision test. Probe family prerequisites and report missing kernel tables explicitly rather than entering unsupported native paths.

Validation: Fast suite passed. Isolated full run: IPv4 passed; two IPv6 cases skipped because this host lacks ip6_tables. An initial constructor-failure crash is addressed in plan 15.
