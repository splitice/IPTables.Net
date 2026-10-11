# Gap 18: Route/rule controller assertions and command errors

Priority: P1. Status: implemented; see implementation record below.

## Evidence

All three [IpUtilsRouteTests](../IPTables.Net.Tests/IpUtilsRouteTests.cs) lack assertions. Rule tests cover basic successful commands, but [IpController](../IPTables.Net/IpUtils/Utils/IpController.cs), [IpRouteController](../IPTables.Net/IpUtils/Utils/IpRouteController.cs), and [IpRuleController](../IPTables.Net/IpUtils/Utils/IpRuleController.cs) contain untested listing, error, and malformed-output paths. `Command` discards exit status.

## Tests to add

- Replace route smoke checks with exact destination, gateway, device, flags, table, and exported-argument assertions, including local/multicast/anycast routes.
- Cover route `GetAll` with null, named, `default`, and `all` tables; include output already containing a table and empty/multiple lines.
- Exercise missing key values, flag-only input, duplicate keys, malformed priorities, and line-context wrapping for both controllers.
- Test add/delete/show failures with stderr, stdout, and nonzero exit with empty streams; specify a consistent failure contract.

## Completion

Extend route/rule tests with process fakes and run the fast suite. Tests must fail when destination/table data or an execution error is silently lost; no host routes should be modified.

## Implementation record

Replace route smoke checks with field/export assertions; cover table selection, empty and malformed listings, flags and command failures. Preserve existing table output, avoid null table injection, validate rule priorities, and reject nonzero command exits.

Validation: Fast suite: 551 passed, 27 skipped, zero failures.
