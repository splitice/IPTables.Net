# Gap 05: Whole-ruleset synchronization and retry recovery

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IpTablesRuleSet.Sync](../IPTables.Net/Iptables/IpTablesRuleSet.cs) coordinates chain discovery/creation, transactions, cleanup, errno-11 retries, and a native-adapter special case. [MockIptablesSystemFactory.TestSync](../IPTables.Net.TestFramework/MockIptablesSystemFactory.cs) synchronizes only the first chain. [IpTablesRuleSetTests](../IPTables.Net.Tests/IpTablesRuleSetTests.cs) tests construction rather than this orchestration.

## Tests to add

- Exercise `IpTablesRuleSet.Sync` directly with recording adapters across multiple chains and tables, including references to newly created chains.
- Inject errno 11 once and repeatedly; assert fresh discovery, bounded attempts, rollback, eventual success, and exhaustion. Cover `maxRetries = 0` and define rejection of negative values.
- Inject nonretryable errors and errors during chain creation, rule updates, commit, and deletion. Assert no accidental duplicate creation or masked original exception.
- Cover absent/false/selective `canDeleteChain`, preservation of unrelated chains, empty desired rulesets, and a second no-op synchronization.
- Verify the native adapter's separate chain-creation commit and configured deletion-table order using a suitable seam or isolated integration fixture.

## Completion

Add `RuleSetSyncTests.cs`; deterministic orchestration cases run fast. Native-specific commit behavior runs in the native suite. Assertions cover the complete operation sequence and resulting state, not just the first chain.

## Implementation record

Add direct whole-ruleset orchestration tests for multi-table creation, references, selective deletion, no-op updates, bounded retries, and original error preservation. Rebuild pending chain state on every attempt, reject negative retry budgets, and roll back commit failures without masking errors.

Validation: Fast suite passed. Native ordered-commit ownership is validated in plan 15.
