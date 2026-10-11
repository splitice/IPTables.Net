# Gap 09: IpSet entry equality and collection membership

Priority: P1. Status: implemented; see implementation record below.

## Evidence

[IpSetEntryKeyComparer](../IPTables.Net/IpSet/IpSetEntryKeyComparer.cs) hashes timeout, while [IpSetEntry.KeyEquals](../IPTables.Net/IpSet/IpSetEntry.cs) ignores it. The entry parser [inserts entries before populating their fields](../IPTables.Net/IpSet/Parser/IpSetEntryParser.cs), and parsed/programmatically constructed sets use different collection initialization paths in [IpSetSet](../IPTables.Net/IpSet/IpSetSet.cs). Existing tests inspect parsed fields or command lists, not hash-set invariants.

## Tests to add

- For key-equal entries with different timeouts, assert equal comparer hashes and working `Contains`, `Remove`, deduplication, and dictionary lookup.
- Compare entries that differ only in the second address, protocol, port, or MAC; each must remain distinct when it changes the key.
- Parse duplicate entries and query/remove a fully populated equivalent entry after parsing.
- Compare parsed and programmatically constructed sets under the same operations; include entries whose metadata changes.
- Feed these cases into synchronization and assert no unnecessary additions/deletions and no silently merged distinct entries.

## Completion

Add `IpSetEntryIdentityTests.cs`. Fast tests cover collection behavior, not a prescribed hash formula. Reproduce the equality/hash inconsistency before fixing it.

## Implementation record

Make entry-key hashing agree with equality by excluding timeout and including the second address. Use the key comparer for parsed sets, add entries only after parsing completes, and implement full entry hashing. Test hash-set/dictionary lookup, deduplication, timeout updates, tuple distinctions, and constructor/parser parity.

Validation: Fast suite passed.
