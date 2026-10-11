# Gap 13: Managed IPv6 parsing and adapter selection

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[RuleParseAssert](../IPTables.Net.Tests/RuleParseAssert.cs) defaults to IPv4, and current round-trip callers do not exercise version 6. The suite's IPv6 address equality and route smoke examples do not validate IPv6 iptables models. Production [IpCidr](../IPTables.Net/Iptables/DataTypes/IpCidr.cs), [IPPortOrRange](../IPTables.Net/Iptables/DataTypes/IPPortOrRange.cs), and adapter factories expose IPv6 behavior.

## Tests to add

- Parameterize representative core/TCP/UDP rules and save dumps for version 6, including `::`, `::1`, compressed addresses, `/0`, `/64`, and `/128`.
- Check IPv6 NAT address/range serialization with and without bracketed ports where supported; assert parsed fields independently of rendering.
- Test family mismatch handling and ensure chain/rule version is preserved through parsing and generation.
- Record binary/save/restore executable selection for `GetTableAdapter(6)`.
- Parse and synchronize `family inet6` sets with IPv6 and two-address tuple entries, preserving address and protocol identity.

## Completion

Add `IPv6ManagedTests.cs` and extend existing parameterized suites. All cases run with the fast suite and no native libraries. Native family coverage is gap 14.

## Implementation record

Add IPv6 core/TCP/UDP and NAT round trips with independent address assertions, IPv6 save parsing, executable selection and inet6 tuple synchronization. Reject mismatched core address families. Fix CIDR lookup losing the second tuple address, which caused identical sets to delete and re-add entries.

Validation: Fast suite passed; no native dependency required.
