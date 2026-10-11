# Gap 12: Invalid commands and argument tokenization

Priority: P2. Status: implemented; see implementation record below.

## Evidence

The numerous `Single*ParseTests` mostly cover successful rendering. [CommandParser](../IPTables.Net/Iptables/Modules/CommandParser.cs) indexes following arguments directly and converts command offsets. [ArgumentHelper.SplitArguments](../IPTables.Net/Supporting/ArgumentHelper.cs) implements quote/space handling without focused edge-case tests. [EscapeHelperTests](../IPTables.Net.Tests/EscapeHelperTests.cs) tests output escaping, not the complete input-tokenization contract.

## Tests to add

- Cover empty/whitespace input, trailing `-A`, `-m`, `-j`, `-t`, and module options missing values; assert intentional errors with useful context.
- Exercise `-I`, `-R`, and `-D` at position 1, omitted positions where allowed, zero, negative, overflow, and missing rule bodies.
- Test unknown modules/options, duplicate module loading, standalone/repeated negation, and invalid numeric option values.
- Add tokenizer cases for empty quoted arguments, mixed quotes, literal apostrophes, escaped quotes/backslashes, tabs, and unmatched quotes. Define accepted syntax rather than silently treating accidental behavior as a contract.
- Rejected parsing must not leave a supplied chain collection partly mutated.

## Completion

Add `CommandParserErrorTests.cs` and `ArgumentHelperTests.cs`. Run fast tests with independent expected tokens and exception/state assertions.

## Implementation record

Add deterministic tokenization and invalid-command theories, preserving empty quoted arguments, whitespace and escaped payloads. Report missing option values, reject malformed offsets and dangling/repeated negation, accept optional insert positions, and retain the deliberate unknown-module polyfill contract.

Validation: Fast suite passed.
