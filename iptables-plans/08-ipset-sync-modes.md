# Gap 08: Set synchronization modes, deletion filters, and replacement

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IpSetSets.Sync](../IPTables.Net/IpSet/IpSetSets.cs) supports three synchronization modes, selective deletion, and replacement through a temporary `_S` set. [IpSetSyncTests](../IPTables.Net.Tests/IpSetSyncTests.cs) covers ordinary entries, some `SetOnly` cases, and a hash-size change. It does not cover `SetAndEntriesOnCreate` or selective/default deletion policy. [IpSetSet.SetEquals](../IPTables.Net/IpSet/IpSetSet.cs) does not compare `Family`.

## Tests to add

- Cross all synchronization modes with absent, unchanged, and replaced sets; assert when entries are preserved or populated.
- Test no deletion predicate, always-false, and selective predicates with unrelated existing sets.
- Change family, type, timeout, bucket size, bitmap range, and create options individually; specify which require replacement and assert the decision.
- Inject failures at create/swap/destroy/populate stages and cover an existing temporary-name collision. Assert the reported failure and observed state without promising transactional rollback from ipset.
- Reconcile an already-converged state and assert no commands.

## Completion

Extend `IpSetSyncTests.cs` using stateful fakes. Run fast tests for policy and command order; validate actual swap restrictions separately in a disposable Linux namespace.

## Implementation record

Cover all ipset sync modes with existing/missing sets and explicit deletion policies. Preserve entries during SetOnly replacement, carry bucket/init metadata, detect temporary-name collisions, reject incompatible family/type swaps before mutation, and discard queued transactions on failure.

Validation: Fast suite passed. Kernel swap compatibility is exercised only on a disposable Linux host.
