# Gap 24: Runner modes, cleanup, and CI parity

Priority: P2. Status: implemented; see implementation record below.

## Evidence

[test.sh](../test.sh) chooses modes/backends, filters unstable tests, mutates alternatives, and restores state with an EXIT trap. [The CI workflow](../.github/workflows/main.yml) duplicates setup and invokes `sudo dotnet test` directly, bypassing the script's default unstable-test exclusion. No shell regression tests exercise this control flow. Both build/test scripts are tracked as mode `100644`; direct test-script invocation failed during this review.

## Tests to add

- Use a temporary PATH containing command stubs to cover fast/full/auto selection, invalid options, backend `current` no-switch behavior, and partial backend-switch failure.
- Fail test execution and verify both original alternatives are restored and cleanup is attempted; run stubs only, not real host firewall cleanup.
- Test default unstable exclusion, opt-in inclusion, and explicit filter forwarding. Check required environment propagation into privileged execution.
- Verify documented script entry points execute in a clean checkout and agree with CI's intended test modes.
- Add a CI check that expected native tests actually execute when prerequisites are provisioned; track skips explicitly rather than treating any green run as native coverage.

## Completion

Add a small shell test harness and align CI with a documented stable/unstable policy. Run the harness without privileges, then fast tests; validate full mode separately on a disposable Linux runner. Keep executable-bit repair and workflow changes in the later implementation, not this documentation-only review.

## Implementation record

Add a stubbed runner harness for modes, filters, backend restoration, failures and runtime environment propagation. Reject invalid modes, clear inherited system-test skips in full mode and preserve runtime limits through sudo. Restore executable entry points, align CI with stable/opt-in kernel policy, and require native TRX coverage with explicit skip reporting. Update the plan index with final validation.

Validation: Runner harness: 17 cases passed; native-report checker: 4 tests passed; fast: 627 passed/27 skipped; isolated stable full: 645 passed/5 skipped. Two full skips are unavailable IPv6 kernel tests; three are preexisting disabled tests. CI checker correctly rejects the missing IPv6 coverage. Shell syntax, YAML parsing and whitespace checks passed.
