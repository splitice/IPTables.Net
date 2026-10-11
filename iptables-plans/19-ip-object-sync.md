# Gap 19: Route/rule reconciliation and object identity

Priority: P1. Status: implemented; see implementation record below.

## Evidence

No existing tests reference [DefaultIpuSync](../IPTables.Net/IpUtils/Sync/DefaultIpuSync.cs). Its set-difference algorithm depends on [IpObject](../IPTables.Net/IpUtils/Utils/IpObject.cs) equality and hashing; those implementations order entries by hash and expose mutable collections. Parser tests do not establish reconciliation correctness.

## Tests to add

- Record adds/deletes for empty, identical, disjoint, and partially overlapping current/desired objects.
- Cover duplicate desired/current objects, reordered dictionary insertion, different flag order, and second-run idempotency.
- Verify equal objects produce equal hashes and work in a `HashSet`; different pair values or flags must remain distinguishable, including a controlled collision case if practical.
- Verify cloning copies both collections independently.
- Inject getter/add/delete failures and assert propagation and the operations completed before failure; do not assume rollback support.

## Completion

Add `DefaultIpuSyncTests.cs` and `IpObjectTests.cs` using a recording controller. Run the fast suite with exact operation/state assertions and no actual `ip` commands.

## Implementation record

Add reconciliation set-difference, duplicate, idempotency and failure-order tests plus object identity and clone ownership coverage. Snapshot and deduplicate current objects before mutation; compare and hash object fields independently of dictionary insertion order.

Validation: Fast suite: 562 passed, 27 skipped, zero failures.
