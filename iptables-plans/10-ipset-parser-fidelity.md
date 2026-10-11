# Gap 10: IpSet parser fidelity and invalid input

Priority: P2. Status: implemented; see implementation record below.

## Evidence

[IpSetParseTest](../IPTables.Net.Tests/IpSetParseTest.cs) checks a limited set of positive inputs, often only selected fields. [IpSetSetParser](../IPTables.Net/IpSet/Parser/IpSetSetParser.cs) parses bucket size and initval; [IpSetEntryParser](../IPTables.Net/IpSet/Parser/IpSetEntryParser.cs) handles tuple components, timeout, and ignored counters. Invalid arity, missing values, and complete rendered entry fidelity lack direct assertions.

## Tests to add

- Verify parse/render/reparse for nondefault bucket size, initval, create options, entry timeout, MAC tuples, and two-address tuples; define intentionally omitted fields explicitly.
- Assert that ignored packet/byte counters do not alter the entry key, while timeout survives APIs that promise a full entry command.
- Cover unknown set references, missing set type, missing option values, too few/many tuple components, invalid numeric values, and extra tokens.
- After rejected entries, assert that the containing set has no partially initialized member.

## Completion

Extend `IpSetParseTest.cs` or add focused parser tests. Each positive case checks all relevant fields and output; negative cases check error context and unchanged collection state. Run the fast suite. IPv6 tuple cases are tracked in gap 13.

## Implementation record

Add set and entry round-trip metadata tests and invalid-input atomicity tests. Validate tuple arity, required option values and counter text; reject extra entry tokens, preserve initval and timeout serialization, and explicitly test rejection of unsupported MAC set types rather than adding unsupported type flags.

Validation: Fast suite passed. Packet/byte counters remain intentionally observational and are not serialized as key data.
