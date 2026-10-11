# Gap 21: Rule generator limits and semantic preservation

Priority: P2. Status: implemented; see implementation record below.

## Evidence

[RuleBuilderMultiportTests](../IPTables.Net.Tests/RuleBuilderMultiportTests.cs) covers two examples; splitter/nested tests cover one each. [MultiportAggregator](../IPTables.Net/Iptables/RuleGenerator/MultiportAggregator.cs) has range-slot boundaries, optional callbacks, an ipset mode, and target propagation. [FeatureSplitter](../IPTables.Net/Iptables/RuleGenerator/FeatureSplitter.cs) has duplicate-chain and nested-output behavior not covered by those examples.

## Tests to add

- Exercise 14/15/16 slots, a range after 14 single ports, overlapping/adjacent ranges, duplicates, and empty groups. Assert every ordinary multiport rule respects the slot limit and preserves the intended port set.
- Cover source/destination ports, TCP/UDP, jump/goto targets, custom base rules, non-filter tables, and ipset mode.
- Verify generated chain references resolve, empty generated chains are handled, and preexisting/repeated generated names follow the duplicate policy.
- Exercise missing extractors/callback combinations and nested empty output with intentional errors rather than incidental null dereferences.

## Completion

Extend builder tests and run fast validation. Assert output semantics and complete generated rule sets in addition to representative command strings; do not merely duplicate the generator algorithm in test code.

## Implementation record

Cover multiport boundaries, TCP/UDP source/destination ports, goto targets, custom mangle base rules, ipset output and empty nested generators. Merge overlapping/duplicate ranges correctly, validate callbacks, support omitted jump setters and remove empty nested chains without dangling jumps; fix empty-group logging.

Validation: Fast suite: 603 passed, 27 skipped, zero failures.
