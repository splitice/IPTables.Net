# Gap 04: Restore stream failures and quoted payloads

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IPTablesRestoreTableBuilder](../IPTables.Net/Iptables/Adapter/Client/Helper/IPTablesRestoreTableBuilder.cs) replaces every apostrophe with a double quote and returns `true` from several failed-write paths. The [existing quote test](../IPTables.Net.Tests/IpTablesRestoreSyncTests.cs) only covers a space-containing comment. It cannot detect payload corruption or truncated restore input reported as successful output.

## Tests to add

- Preserve comment payloads containing apostrophes, literal double quotes, backslashes, empty text, and Unicode. Assert literal expected output and recovered payload separately.
- Inject nonwritable streams and write/flush exceptions at the table header, chain declaration, rule, and `COMMIT` boundaries.
- Assert that incomplete serialization is surfaced to the caller and cannot be reported as a successful commit; resolve the ambiguous boolean contract before adding assertions.
- Cover multiple tables, per-table `COMMIT`, built-in versus custom-chain declarations, duplicate chain rejection, and clear/rebuild behavior.

## Completion

Add `RestoreTableBuilderTests.cs` and connect stream failure coverage to gap 02. Run the fast suite. A deliberately truncated stream or changed comment must fail a meaningful assertion.

## Implementation record

Normalize syntactic single quotes without corrupting apostrophes inside double-quoted payloads. Reject unterminated quotes and propagate restore stream failures. Cover Unicode, escaped quotes, backslashes, empty arguments, per-table framing, duplicate chains, and writes failing at each boundary.

Validation: Fast suite passed; native restore syntax compatibility remains covered by the separate integration work.
