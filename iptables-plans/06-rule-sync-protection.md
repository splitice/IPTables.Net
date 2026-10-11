# Gap 06: Deletion predicates and custom equality during rule sync

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[DefaultRuleSync](../IPTables.Net/Iptables/TableSync/DefaultRuleSync.cs) accepts `ShouldDelete`, `RuleComparerForUpdate`, and an equality comparer. [Binary](../IPTables.Net.Tests/IpTablesBinarySyncChainTests.cs) and [restore](../IPTables.Net.Tests/IpTablesRestoreSyncTests.cs) tests cover basic edits and comment-based updates, but do not supply a deletion predicate or custom equality comparer. Equal-length lists can trigger replacement independently of `ShouldDelete`.

## Tests to add

- Keep protected rules at the beginning, middle, and end while desired managed rules grow, shrink, reorder, or become empty.
- Explicitly define whether deletion protection also protects against replacement; test equal-length mismatches against that decision.
- Cover duplicate rules and duplicate update keys, plus a custom comparer that ignores selected metadata.
- Assert exact final order, preserved protected rules, valid evolving positions, and a second synchronization that emits no further commands where convergence is expected.

## Completion

Extend both adapter synchronization suites with a shared scenario matrix. Fast tests must detect unintended deletion/replacement and must not rely solely on rule counts.

## Implementation record

Protect rules against replacement as well as deletion, materialize desired sequences once, and replace at the actual current-chain position with model rollback on command failure. Test protected rules at every position through both binary and restore clients, convergence, empty desired rules, duplicate rules, and custom equality.

Validation: Fast suite passed.
