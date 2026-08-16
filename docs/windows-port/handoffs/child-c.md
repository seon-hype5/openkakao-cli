# Child C Wave 1 handoff

## Status

- Complete on `agent/cli-surface-w1`.
- Frozen contract ancestor: `d974c0597528e079919d4c45ee0893fa61d4335d`.
- Atomic commit SHA: the single commit containing this handoff; its immutable
  SHA is reported immediately after commit creation because a commit cannot
  contain its own final SHA.

## Changed files

- `src/cli/windows/mod.rs`
- `src/output/windows/mod.rs`
- `tests/windows_cli/mod.rs`
- `docs/windows-port/handoffs/child-c.md`

## Delivered surface

- Clap-derived Windows UI doctor and local-send options with stdin and
  opened-only required, dry-run as the default mode, and no second positional
  input value.
- Parse-time and runtime conflict checks; reserved stage/commit modes require
  explicit confirmation and fail before input or backend calls in Wave 1.
- Generic `PlatformProbe` orchestration only. No concrete backend is created,
  and dry-run has no mutation-trait bound.
- Abstract reader input capped at 4,001 raw bytes, with rejection above 4,000
  before UTF-8 construction, static invalid-input errors, and explicit buffer
  zeroization on read, overflow, and UTF-8 failure paths.
- Schema-version-1 human/JSON reports built only from fixed codes and snapshot
  state, plus separated stdout/stderr rendering and frozen exit-code mapping.
- Render-time allowlists prevent arbitrary public report action, profile, or
  evidence strings from reaching either output mode.
- Observable absent, ambiguous, and unknown-profile states remain representable
  as redacted doctor evidence; backend/native failures remain structured errors.

## Verification

- `cargo fmt --check`: passed.
- `cargo test --lib cli::windows::tests`: passed, 18 passed, 0 failed,
  54 filtered out.
- `cargo clippy --lib --tests -- -D warnings`: passed.
- Build artifacts were isolated under `.target/child-c`.

## Skipped tests

- No live desktop UI, real backend, stage, commit, or submit test was run.
- No account data, local data store, credentials, tokens, private fixtures,
  screenshots, or network service was accessed.
- The full repository and root-owned binary dispatch suites were not run;
  verification was focused on the owned library surface and synthetic fakes.

## Assumptions and residual risks

- Root will compose the generic inspection result with the safety policy and
  concrete read-only backend, then pass the resulting report/error to the
  renderer.
- The local 4,000-byte reader constant matches the policy constant and should
  be deduplicated against the policy export after integration.
- Root will add success-path drop zeroization to the frozen secret-message
  contract; this branch wipes every temporary input buffer on error paths.
- Root-owned command dispatch and combined Child A/Child B APIs are not present
  on this frozen branch, so integrated compilation remains a root verification
  step.
- Known Windows and fake UI profile identifiers are emitted from fixed local
  constants; snapshot-supplied identifier strings are never copied to output.

## RFCs

- Approved integration RFC: root will replace raw Windows parsing failure
  output with `try_parse` handling. Help/version remain supported, while a
  rejected legacy second positional value produces only a generic redacted
  usage diagnostic and exit code 2. Other platforms remain unchanged.
- Integration cleanup: root will deduplicate the local input byte limit against
  the safety module's exported constant.
- No dependency or frozen-contract change is requested.
