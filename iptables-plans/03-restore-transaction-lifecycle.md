# Gap 03: Restore transaction reuse and binary fallback

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IPTablesRestoreAdapterClient](../IPTables.Net/Iptables/Adapter/Client/IPTablesRestoreAdapterClient.cs) maintains a persistent builder and transaction flag. Commit does not explicitly clear the builder. Nontransactional `ReplaceRule` and `AddChain` fall through after binary execution, and the raw-string `AddRule` always queues. Existing restore tests use a fresh client for one successful synchronization.

## Tests to add

- Commit transaction A, then B on the same client; independently assert that B contains only its own commands.
- Roll back queued work, then commit new work; assert no rolled-back commands execute.
- Cover nested start, empty transaction, commit/rollback without start, and explicit disposal while active.
- After a failed commit, roll back and reuse the client; establish its recovery contract without assuming kernel changes were undone.
- Compare each rule/chain operation inside and outside a transaction, including raw-string add and `DeleteChain(flush: true)`. Follow an immediate operation with a transaction to detect unintended queued work.

## Completion

Add `RestoreAdapterLifecycleTests.cs` using production methods and process fakes. Assert external command logs and transaction outcomes in the fast suite. Treat the observations above as regression candidates, not verified failures.

## Implementation record

Clear successful restore transactions, prevent immediate replace/add-chain/raw-add commands from being queued, preserve flush-before-delete, and remove the throwing managed finalizer. Add reuse, rollback, failure recovery, nested-start, disposal, and IPv6 fallback tests.

Validation: Fast suite: 410 passed, 15 skipped.
