# Gap 23: Version parsing and SYNPROXY capability detection

Priority: P2. Status: implemented; see implementation record below.

## Evidence

No tests call [SynProxyHelper](../IPTables.Net/Iptables/Helpers/SynProxyHelper.cs) or adapter `GetIptablesVersion`. The [binary client's](../IPTables.Net/Iptables/Adapter/Client/IPTablesBinaryAdapterClient.cs) version regex and the helper's kernel-release regex control feature availability. The kernel regex requires a numeric component after a hyphen, excluding other release shapes regardless of their numeric version.

## Tests to add

- Parse representative iptables version output with legacy/nf_tables suffixes, whitespace, malformed text, and command failures.
- Assert the iptables support boundary immediately below, at, and above 1.4.21 using a fake adapter.
- Feed kernel releases below/at/above 3.12, plain semantic versions, distro suffixes, custom suffixes, malformed output, and nonzero exits.
- Define whether unrecognized version formats mean unsupported or an error; distinguish version-based eligibility from proof that a kernel target/module is available.

## Completion

Add `CapabilityDetectionTests.cs` using fixed strings and process fakes. Run the fast suite; results must be independent of the test host's installed binaries and kernel.

## Implementation record

Cover iptables and SYNPROXY version thresholds with fixed process responses. Parse IPv4/IPv6 binary banners and plain, distro and custom kernel releases; report process failures and reject malformed or overflowing versions. Document that version eligibility does not establish module availability.

Validation: Fast suite: 627 passed, 27 skipped, zero failures.
