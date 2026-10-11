# Gap 16: Conntrack data integrity and failure cleanup

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[ConntrackLibraryTests](../IPTables.Net.Tests/ConntrackLibraryTests.cs) asserts struct size; its two dump tests collect records without checking them. The class is categorized `NotWorkingOnTravis`. [ConntrackSystem](../IPTables.Net/Conntrack/ConntrackSystem.cs) additionally implements restore, mark overrides, extraction, caching, and cleanup against [ct.cpp](../ipthelper/ct.cpp). Dump reuses an equal-sized buffer, and restore-mark cleanup follows a possible throw.

## Tests to add

- Seed known flows and assert dump count/content, matching and nonmatching filters, family selection, and expectation-table behavior.
- Specify callback buffer ownership; retain multiple equal-sized records to detect unintended aliasing.
- Verify valid/unknown constants, successful/missing field extraction, and malformed record handling using controlled native inputs or a test shim.
- Test restore success, remaining-byte results, native errors, mark/mask application, and cleanup after failure.
- Throw from a dump callback, then repeat the operation to prove resources and filter state were released. Cover multiple instances if native state is shared.

## Completion

Keep deterministic marshaling/shim cases separate from unstable kernel tests. Run actual conntrack operations only in a disposable capable Linux environment with `RUN_UNSTABLE_SYSTEM_TESTS=1 bash ./test.sh --full`; use timeouts and assert contents, not just absence of exceptions.

## Implementation record

Correct conntrack native cleanup signatures, Linux family mapping, independent dump buffers, shared-state locking, and failure cleanup. Reject malformed extraction/restore lengths. Add deterministic native-boundary tests and seeded UDP filter assertions.

Validation: Fast suite: 526 passed, 26 skipped. Isolated Linux conntrack selection: 18 passed, including seeded flow and native dump/extraction.
