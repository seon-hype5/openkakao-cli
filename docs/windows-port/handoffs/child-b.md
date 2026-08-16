# Child B Wave 1 handoff

## Status

- Status: implementation complete; verification passed.
- Assigned branch: `agent/safety-policy-w1`.
- Frozen contract ancestor: `d974c0597528e079919d4c45ee0893fa61d4335d`.
- Atomic commit: the commit containing this handoff. Its exact SHA is reported
  to root immediately after commit creation because a commit cannot contain
  its own content-derived SHA.

## Changed files

- `src/safety/mod.rs`: exports the Windows safety-policy API while preserving
  the private `ApprovalToken` constructor boundary.
- `src/safety/policy.rs`: deny-by-default policy, dry-run plan, exact allowlist,
  snapshot validation, message/nonce validation, clock seam, replay guard, and
  process-local approval lease.
- `tests/windows_policy/main.rs`: synthetic integration coverage for refusal,
  privacy, dry-run, replay, and concurrency behavior.
- `docs/windows-port/handoffs/child-b.md`: this handoff.

No manifest, lockfile, flat configuration, common platform contract, backend,
CLI, output, or shared contract documentation file was changed.

## Policy surface and limits

- `WindowsPolicyConfig::new` rejects an empty allowlist, empty/control-bearing
  entries, and byte-for-byte duplicate entries.
- Both `WindowsSafetyPolicy::dry_run` and `authorize` receive the requested
  target label explicitly and match it transiently with the frozen common
  `exact_unique_match` function. Labels are not stored in plans or approvals.
- Matching performs no substring, glob, regex, case folding, trimming, Unicode
  normalization, or confusable mapping.
- Only `SelfChat` is accepted.
- The only accepted app version is `26.7.0.5255` with `known_ui_profile=true`.
- Snapshot validity is `observed_at <= now < expires_at`; zero, inverted, or
  greater-than-5,000 ms TTLs are refused.
- Message length is at most 1,000 Unicode scalar values and 4,000 UTF-8 bytes.
  Empty values and every Rust `char::is_control` value, including NUL, CR, and
  LF, are refused.
- Nonces are 1 through 128 bytes of ASCII alphanumeric, hyphen, underscore,
  dot, or colon. A domain-separated SHA-256 digest is retained only inside the
  private replay set. Raw nonces and nonce digests are not formatted or
  serialized; the nonce embedded in `ApprovedSend` is replaced by a redaction
  marker.
- `DryRunPlan` is serializable but always records `attempted=false`,
  `approval_issued=false`, `outcome=dry_run`, and `retry_safe=true`. Dry-run
  accepts only `PlatformProbe`, never acquires the write lease, and never
  consumes a nonce.
- `StageOnly` and `Commit` require `explicit_yes=true`. They may be represented
  as an `ApprovedOperation` only when the probe advertises
  `send_open_chat=true`, but the policy performs no stage or commit call.
- `ApprovedOperation` owns a private standard-library `MutexGuard`, is non-Send
  by construction, and lends only `&ApprovedSend`. The successful nonce is
  consumed permanently for the policy instance, and the guard serializes all
  approvals until the lease drops.

## Deterministic refusal mapping

All operations are fixed static `policy_*` codes and contain no caller data.

| Unsafe observation | `UiErrorKind` |
|---|---|
| Probe cannot inspect, authorization lacks send capability, or snapshot platform is not Windows | `UnsupportedCapability` |
| App not running, missing/zero process, or zero top-level windows | `ProcessNotFound` |
| Multiple top-level windows, even with untrusted/absent running and process fields | `AmbiguousTarget` |
| Missing process session or interactive-session mismatch | `SessionMismatch` |
| Incompatible integrity | `IntegrityMismatch` |
| Missing executable fingerprint, unsupported/missing version, or unknown UI profile | `UnknownUiProfile` |
| Modal present | `ModalPresent` |
| Zero/inverted/overlong TTL, snapshot from the future, or expired snapshot | `StaleSnapshot` |
| Requested/snapshot target is not verified self-chat | `TargetNotSelf` |
| Non-exact target or missing target fingerprint | `TargetNotFound` |
| Non-unique target | `AmbiguousTarget` |
| Missing target composer fingerprint or composer not present | `ComposerNotFound` |
| Non-unique composer | `AmbiguousComposer` |
| Disabled or non-writable composer | `PermissionDenied` |
| Non-empty draft | `ExistingDraft` |
| Focused composer | `UserActive` |
| Missing selector-profile fingerprint | `UnknownUiProfile` |
| Empty/duplicate allowlist, unmatched label, invalid message/nonce/mode/confirmation, or nonce replay | frozen target kind or `InvalidInput` as exercised in tests |

## Verification

- `cargo test --lib safety::`: 3 passed, 0 failed, 54 filtered out.
- `cargo test --test windows_policy`: 16 passed, 0 failed.
- `cargo clippy --lib -- -D warnings`: passed with no diagnostics.
- Final `cargo fmt --check`: recorded after this handoff is formatted.
- `git diff --check`: passed before handoff creation and rerun before commit.

All build artifacts used the assigned ignored target directory
`.target/child-b`.

## Skipped and prohibited tests

- No live KakaoTalk/UI Automation test, Windows API call, stage, commit, focus,
  input, clipboard, database, credential, process-memory, or network operation
  was run.
- No full cross-platform test matrix was run; the owned unit/integration tests,
  formatting check, and requested library clippy gate were used for Wave 1.

## Assumptions and residual risks

- `focused=true` is treated as active user interaction and refused.
- A disabled or non-writable composer maps to `PermissionDenied`; a missing
  composer maps to `ComposerNotFound`.
- Multiple top-level app windows map to `AmbiguousTarget` before evaluating
  untrusted running/process fields because the read-only backend cannot choose
  safely. A zero count remains `ProcessNotFound`.
- Dry-run requires only inspection capability. Authorization additionally
  requires `send_open_chat=true` and refuses before inspection or nonce
  consumption when that capability is absent.
- Replay and mutual exclusion are process-local and reset on process exit.
  Cross-process exclusion and durable replay prevention remain required before
  any future live mutation is enabled.
- The replay set is intentionally fail-closed after mutex poisoning and grows
  for the lifetime of the policy instance. The Wave 1 CLI is expected to be
  short-lived.
- System clock adjustment can invalidate a snapshot; the policy fails closed
  outside its narrow TTL window.

## Root wiring RFC

Root should feed the existing `SafetyConfig.allowed_send_chats` strings into
`WindowsPolicyConfig::new` without trimming, normalization, case folding, or
deduplication. An empty list remains deny-by-default, and duplicates must
surface as configuration refusal. This wiring belongs in root/CLI-owned files
because the existing `src/config.rs` is flat and was explicitly outside Child
B ownership.

The Windows stdin reader should cap acquisition at 4,001 bytes, refuse when
more than 4,000 bytes are observed, validate UTF-8, and then pass the resulting
value to policy for the independent 1,000-scalar and control-character checks.
