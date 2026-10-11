# Testing gap plans

Reviewed the managed implementation, xUnit suite, test doubles, native integration boundaries, and test runner on 2026-10-11. Each numbered document describes one actionable coverage gap. These are source-review findings, not a measured line/branch coverage report or a claim that every missing case has been enumerated. Suspected defects are identified as review observations until reproduced.

Baseline: `bash ./test.sh --fast` from the repository root passed with **386 passed, 15 skipped, 0 failed (401 total)**. Native dependencies were absent, so the helper build was skipped. Full/system tests were not run. Direct `./test.sh --fast` failed with permission denied; the tracked script mode is `100644` (see gap 24).

All plans are open. P1 means prioritize because the gap can conceal incorrect firewall changes, state loss, or native resource problems; P2 means important correctness or compatibility coverage. Existing happy-path tests should remain. Add assertions against independently specified results rather than simply replaying output through the same parser.

| Gap | Priority | Scope |
| --- | --- | --- |
| [01](01-binary-process-failures.md) | P1 | Binary adapter process failures |
| [02](02-restore-commit-process.md) | P1 | Real restore commit execution |
| [03](03-restore-transaction-lifecycle.md) | P1 | Restore transaction reuse and fallback |
| [04](04-restore-output-integrity.md) | P1 | Restore stream failures and quoted payloads |
| [05](05-ruleset-sync-retries.md) | P1 | Whole-ruleset synchronization and retries |
| [06](06-rule-sync-protection.md) | P1 | Deletion predicates and custom equality |
| [07](07-ipset-process-transactions.md) | P1 | Real ipset restore and transaction execution |
| [08](08-ipset-sync-modes.md) | P1 | Set modes, deletion filters, and replacement |
| [09](09-ipset-entry-identity.md) | P1 | Entry equality, hashing, and collection membership |
| [10](10-ipset-parser-fidelity.md) | P2 | Set/entry parser fidelity and invalid input |
| [11](11-save-parser-errors.md) | P1 | Save parser framing and recovery |
| [12](12-rule-parser-invalid-input.md) | P2 | Invalid commands and argument tokenization |
| [13](13-managed-ipv6.md) | P1 | Managed IPv6 parsing and adapter selection |
| [14](14-native-ipv6.md) | P1 | IPv6 native helper integration |
| [15](15-native-handle-lifecycle.md) | P1 | Native handle and transaction cleanup |
| [16](16-conntrack-behavior.md) | P1 | Conntrack data integrity and failure cleanup |
| [17](17-nfacct-client.md) | P1 | Accounting XML and commands |
| [18](18-route-rule-controllers.md) | P1 | Route/rule assertions and command errors |
| [19](19-ip-object-sync.md) | P1 | Route/rule reconciliation and object identity |
| [20](20-address-port-boundaries.md) | P2 | CIDR and address/port boundaries |
| [21](21-rule-generator-boundaries.md) | P2 | Generator limits and semantic preservation |
| [22](22-ruleset-clone-isolation.md) | P2 | Deep clone fidelity and independence |
| [23](23-capability-detection.md) | P2 | Version parsing and SYNPROXY detection |
| [24](24-test-runner-contracts.md) | P2 | Runner modes, cleanup, and CI parity |

For managed plans, validate with `bash ./test.sh --fast`; once executable permissions are corrected, use the documented `./test.sh --fast`. Native plans specify separate Linux prerequisites. Use disposable hosts or isolated network namespaces for tests that mutate networking. Do not assume libiptc supports the nft backend. Shared process-fake improvements in gaps 01, 02, and 07 can be implemented once and reused.
