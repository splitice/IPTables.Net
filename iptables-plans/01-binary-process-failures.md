# Gap 01: Binary adapter process failures

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[ExecutionHelper](../IPTables.Net/Iptables/Helpers/ExecutionHelper.cs) maps exit codes 1, 2, and other failures to exceptions. [IPTablesBinaryAdapterClient](../IPTables.Net/Iptables/Adapter/Client/IPTablesBinaryAdapterClient.cs) also handles listing errors and catches exceptions in `HasChain`. [MockIptablesSystemProcess](../IPTables.Net.TestFramework/MockIptablesSystemProcess.cs) leaves `ExitCode` at zero with a private setter. Existing [binary synchronization tests](../IPTables.Net.Tests/IpTablesBinarySyncChainTests.cs) therefore do not exercise these branches. The system suite's invalid-table test provides limited real failure coverage, not this matrix.

## Tests to add

- Extend a process fake to configure exit codes, stdout/stderr, start failures, and disposal observation.
- Exercise add, replace, delete, and flush-before-delete with exit codes 0, 1, 2, and an unexpected value; assert exception context and command ordering.
- Test listing with empty output, stderr, nonzero exit, and partial output. Define whether unsuccessful partial dumps must be rejected.
- Distinguish missing-chain behavior from permission/tool failures in `HasChain`; decide the intended contract before encoding current broad exception suppression.

## Completion

Add `BinaryAdapterFailureTests.cs` under `IPTables.Net.Tests/`. Every configured failure must produce the intended caller-visible result, and processes must be disposed. Run the fast suite without invoking real iptables.

## Implementation record

Added configurable process responses and disposal assertions; covered mutation/listing failures and flush ordering. Preserve stderr and reject failed partial dumps. HasChain now suppresses only recognizable missing-chain errors.

Validation: Fast suite: 395 passed, 15 skipped; compiler required DOTNET_PROCESSOR_COUNT=2 and a 1 GiB GC limit on this host.
