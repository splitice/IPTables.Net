# Gap 02: Real restore commit execution

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[MockIpTablesRestoreAdapterClient.EndTransactionCommit](../IPTables.Net.TestFramework/IpTablesRestore/MockIpTablesRestoreAdapterClient.cs) replaces production commit with serialization to memory. Consequently, [restore synchronization tests](../IPTables.Net.Tests/IpTablesRestoreSyncTests.cs) miss process startup, stdin completion, exit-code handling, and diagnostics in [IPTablesRestoreAdapterClient](../IPTables.Net/Iptables/Adapter/Client/IPTablesRestoreAdapterClient.cs).

## Tests to add

- Use the production client through `IPTablesRestoreAdapter` with an injectable `ISystemFactory` fake; do not override commit.
- Assert selected executable, `--noflush --noclear`, exact stdin content, closing stdin before waiting, and process disposal.
- Cover exits 0, 1 with and without `line N failed`, 2, and unexpected codes. Verify the reported rule for first/last/out-of-range line numbers.
- Preserve meaningful stderr in command-line failures; the implementation currently reads stderr again after `ReadToEnd` has consumed it.
- Exercise `CheckBinary` with and without the required patched option, and process start/read failures.

## Completion

Add `RestoreAdapterCommitTests.cs`. Fast tests execute the production commit body and prove both successful delivery and useful failures. Real patched-restore compatibility remains a separate optional integration check.

## Implementation record

Exercise the production restore commit with configurable process responses, exact input and disposal assertions. Preserve stderr for every exit code, attach failed-rule context, reject failed save output, and accept patched help on stdout or stderr.

Validation: Fast suite: 407 passed, 15 skipped.
