# Gap 17: Accounting XML and command execution

Priority: P1. Status: implemented; see implementation record below.

## Evidence

No tests instantiate [NfAcct](../IPTables.Net/NfAcct/NfAcct.cs). [SingleNfacctRuleParseTests](../IPTables.Net.Tests/SingleNfacctRuleParseTests.cs) covers the iptables match module only. `FromXml` supplies packets then bytes to [NfAcctUsage](../IPTables.Net/NfAcct/NfAcctUsage.cs), whose constructor expects bytes then packets; `List` uses the opposite order. This is a concrete source-level inconsistency needing regression coverage.

## Tests to add

- Feed identical XML to `Get` and `List` with distinct counts such as 7 packets and 900 bytes; assert named properties and consistency.
- Cover multiple names, unknown names, empty output, malformed XML, missing fields, large unsigned counters, and invalid counter text.
- Record `Get`/`List` reset arguments, `Exist`, add/delete commands, and handling of names requiring escaping.
- Configure nonzero exits and stderr; establish an explicit command-failure contract rather than accepting silent failures by default.

## Completion

Add `NfAcctTests.cs` using `ISystemFactory` fakes. Fast tests validate counter semantics and commands without requiring nfacct installation. Reproduce the count-order mismatch before fixing it.

## Implementation record

Unify accounting XML parsing and correct swapped byte/packet counters. Preserve unsigned counters, escape object names, and report malformed records and command failures consistently. Add Get/List/reset/existence and process-disposal coverage.

Validation: Fast suite: 537 passed, 27 skipped, zero failures.
