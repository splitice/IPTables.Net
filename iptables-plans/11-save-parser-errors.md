# Gap 11: Save parser framing, counters, and recovery

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IpTablesSaveReadingTests](../IPTables.Net.Tests/IpTablesSaveReadingTests.cs) covers valid IPv4 filter/nat dumps and one rule-counter ordering case. [IPTablesSaveParser](../IPTables.Net/Iptables/Adapter/Client/Helper/IPTablesSaveParser.cs) has untested behavior for incomplete dumps, wrong table commits, malformed counters, and `ignoreErrors`, whose catch currently surrounds only counter-prefixed rule parsing.

## Tests to add

- Cover empty output, CRLF, comments, blank lines, missing `COMMIT`, wrong requested table, and multiple table blocks. Define the accepted input framing before asserting selection behavior.
- Test missing counter delimiters, wrong field counts, nonnumeric and overflowing counters, and large valid values.
- Supply the same invalid rule with and without counter prefixes under both `ignoreErrors` settings; specify consistent recovery and preserve subsequent valid rules.
- Verify chain association, complete rule order, and model fields rather than only chain counts. Document whether chain policy/counters are intentionally outside the model.

## Completion

Extend `IpTablesSaveReadingTests.cs`; fast tests distinguish malformed/incomplete dumps from valid empty tables and prevent silent loss of later rules.

## Implementation record

Validate save framing and counter syntax, distinguish incomplete dumps from valid empty tables, select the requested table from multi-table input, and apply ignoreErrors consistently to counter-prefixed and plain rules. Assert CRLF handling, exact rule order, large counters, and recovery of later valid rules.

Validation: Fast suite passed. Chain policy/counters remain outside the existing model.
