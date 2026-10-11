# Gap 20: CIDR and address/port boundary contracts

Priority: P2. Status: implemented; see implementation record below.

## Evidence

[IpSetCidrTests](../IPTables.Net.Tests/IpSetCidrTests.cs) covers several IPv4 synchronization examples, and [PortRangeHelpersTests](../IPTables.Net.Tests/PortRangeHelpersTests.cs) covers compression/counting. These do not directly validate all contracts of [IpCidr](../IPTables.Net/Iptables/DataTypes/IpCidr.cs), [PortOrRange](../IPTables.Net/Iptables/DataTypes/PortOrRange.cs), [IpPort](../IPTables.Net/Iptables/DataTypes/IpPort.cs), and [IPPortOrRange](../IPTables.Net/Iptables/DataTypes/IPPortOrRange.cs).

## Tests to add

- Check CIDR `/0`, host prefixes, exact network/broadcast endpoints, adjacent networks, rebasing, address counts, ordering, and mixed-family containment.
- Specify behavior for invalid/negative/overflow prefixes and extra slash components, including `0.0.0.0` with an explicit nonzero prefix.
- Cover port 0, 65535, 65536, reversed ranges, missing endpoints, extra separators, and numeric overflow. Distinguish port-specific validation from generic numeric range usage.
- Validate IPv4 and bracketed IPv6 address ranges, omitted ports, invalid addresses, and parse/render stability; define the legacy `IpPort` fallback contract separately.

## Completion

Add focused data-type theories with independently calculated results. Run the fast suite. Boundary expectations must be explicit before changing permissive parsing behavior.

## Implementation record

Establish CIDR containment/count/rebase boundaries for both families, reject malformed prefixes and ranges, and preserve explicit zero-address prefixes. Keep generic uint ranges distinct from endpoint port limits; support bracketed IPv6 single endpoints while preserving the legacy invalid-input fallback.

Validation: Fast suite: 596 passed, 27 skipped, zero failures.
