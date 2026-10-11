# Gap 07: Real ipset restore and transaction execution

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[MockIpsetSystemFactory.TestSync](../IPTables.Net.TestFramework/MockIpsetSystemFactory.cs) explicitly calls `Sync(..., false)`. Existing synchronization coverage therefore bypasses the default transactional path in [IpSetBinaryAdapter](../IPTables.Net/IpSet/Adapter/IpSetBinaryAdapter.cs). `RestoreSets` currently returns true on a nonzero exit, making its success contract a specific regression candidate.

## Tests to add

- Drive the production adapter with configurable stdin/stdout/stderr and exit codes. Verify successful and failed `RestoreSets` results, complete create/add command syntax, and stream closure.
- Cover nonempty and empty transactions, successful commit, nonzero exit with and without stderr, and a broken stdin stream.
- Specify nested-start and post-failure reuse behavior; assert queued commands cannot disappear or leak into a later commit unnoticed.
- Cover immediate create, destroy, add, delete, and swap failures, plus failed/partial `SaveSets` output.

## Completion

Add `IpSetAdapterTests.cs`; production restore/commit methods execute in fast tests. Confirm the intended boolean meaning before changing behavior. Reuse the process fake from gap 01 and assert disposal on all paths.

## Implementation record

Execute real ipset restore and transaction methods with process fakes. Correct inverted restore success and missing create/timeout serialization, reject failed save output, add explicit rollback and nested-start protection, and clear transaction buffers even after failure. Cover immediate operation errors and recovery.

Validation: Fast suite passed.
