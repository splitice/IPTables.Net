# Gap 15: Native handle and transaction cleanup

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IptcInterfaceTest](../IPTables.Net.Tests/IptcInterfaceTest.cs) checks normal refcounts and one incompatible-match commit error. It does not cover failed construction, multiple live handles, family conflicts, or rollback/reuse. [IptcInterface](../IPTables.Net/Iptables/NativeLibrary/IptcInterface.cs) increments global initialization counts before opening a table. [IPTablesLibAdapterClient](../IPTables.Net/Iptables/Adapter/Client/IPTablesLibAdapterClient.cs) owns multiple interfaces and accepts an explicit commit order.

## Tests to add

- Fail table opening and verify a subsequent valid construction and disposal restore the initial refcount.
- Test simultaneous same-family handles, rejected mixed-family initialization, repeated dispose, and family switching after cleanup.
- Exercise rollback, commit then reuse, failed commit then recovery, and operations with no open handle.
- Cover multi-table commit orders containing missing, duplicate, or omitted tables; specify ownership/cleanup for every opened interface and preserve errno diagnostics.
- Cover `BpfCompile` success, invalid filter/link type, and insufficient output buffer in a separate native-only fixture; current BPF parsing tests do not compile programs.

## Completion

Extend native tests and inspect corresponding [helper allocation/commit code](../ipthelper/ipthelper.c). Use fault injection where kernel failures cannot be produced reliably. Run in disposable Linux environments, asserting resource/state recovery in addition to exceptions.

## Implementation record

Fix native table-init errors long-jumping without an active recovery frame, constructor/refcount cleanup, rejected-family finalization, and duplicate/omitted ordered commits. Bound BPF formatting and release allocations on all failures. Add native construction, disposal, rollback/reuse, commit-order and BPF buffer tests.

Validation: Fast suite passed. Isolated native lifecycle/family tests passed where supported; IPv6 kernel-dependent cases skip because ip6_tables is absent.
