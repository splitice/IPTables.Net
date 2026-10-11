# Gap 22: Deep clone fidelity and independence

Priority: P2. Status: implemented; see implementation record below.

## Evidence

[IpTablesRuleSet.DeepClone](../IPTables.Net/Iptables/IpTablesRuleSet.cs) reconstructs rules through `GetActionCommand()` without requesting counters. [IPTablesRuleTests](../IPTables.Net.Tests/IPTablesRuleTests.cs) explicitly checks counter preservation only for `ShallowClone`. Restore tests call deep clone on zero-counter examples and do not mutate module state to verify independence.

## Tests to add

- Clone a ruleset with multiple tables, empty/custom chains, duplicate ordered rules, IPv6 rules, comments, and nonzero counters.
- Specify which metadata `DeepClone` promises to preserve, then assert it field by field; nonzero counters distinguish intentional reset from accidental loss.
- Change a cloned module, add/remove/reorder cloned rules, and alter counters; assert the source remains unchanged.
- Check that cloned rules reference cloned chains while retaining the intended system and IP version.
- Verify original/clone equality immediately after cloning under the chosen metadata contract, and inequality after a semantic mutation.

## Completion

Add `RuleSetCloneTests.cs` and run the fast suite. Keep existing shallow-clone coverage; these tests specifically establish the deeper ownership and fidelity guarantee.

## Implementation record

Preserve counters when deep-cloning rulesets, including disabled counter values. Verify IPv4/IPv6 clone equality, ordered duplicates, multiple tables, empty chains, comments, system references and independent module/rule/chain mutations.

Validation: Fast suite: 605 passed, 27 skipped, zero failures.
