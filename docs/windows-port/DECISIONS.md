# Windows port decisions

## ADR-001: Official desktop UI, not login or local data

Use the already-authenticated official desktop application's accessibility
surface. Do not add LOCO login, credential extraction, KakaoTalk DB access, or
process-memory techniques to the Windows MVP.

## ADR-002: Self-chat and opened-only

The Windows MVP recognizes only an already-open, exact-and-unique self-chat.
It does not search for or open rooms. Ambiguity fails closed.

## ADR-003: Read-only probe and sealed mutation capability

Inspection and mutation are separate traits. Dry-run depends only on the
inspection trait. Mutation is implemented only by sealed crate backends and
is dispatched through a consumed `ApprovedOperation`; the internal
`ApprovedSend` also carries an atomic one-shot execution claim.

## ADR-004: Target-scoped SQLite features

Keep `bundled-sqlcipher` on macOS, where legacy KakaoTalk DB code exists. Use
plain `bundled` SQLite elsewhere for openkakao's own cache. Do not install an
OpenSSL workaround that would accidentally imply Windows KakaoTalk DB support.

## ADR-005: windows-rs 0.62.2 with explicit features

Use Microsoft's `windows` crate only on Windows with the minimum namespaces
needed for process/session/file-version/window/UIA discovery. Dependency or
feature expansion requires a root RFC with an official API reference.

## ADR-006: Preserve the macOS implementation

Do not move or rewrite the existing AX module in the contract commit. Replace
its unsafe substring fast-path decision with the common exact-and-unique
matcher and retain the public facade.

## ADR-007: Integration by cherry-pick

Children produce clean atomic commits on branches rooted at the frozen
contract. Root verifies ownership and cherry-picks policy, backend, then CLI.
No force operations, push, or PR creation are permitted in this session.

## ADR-008: Metadata-only Wave 1 fails closed on identity and draft state

Do not read window titles, UIA Name/Value properties, room/profile names, or
draft text merely to make a production dry-run pass. The Windows probe leaves
target-identity and draft-empty evidence false, and the safety policy refuses
that real snapshot. Redacted UI status remains useful; successful send planning
is covered only with synthetic fakes until a later privacy-preserving design is
explicitly approved.

## ADR-009: Reuse the policy-validated dry-run snapshot

Inspect once inside the safety policy and retain the exact redacted snapshot in
the non-approved `DryRunPlan`. Root output consumes that value instead of
probing again, avoiding a time-of-check/time-of-use race. Serialization and
Debug omit the retained snapshot.

## ADR-010: Default-off Windows native write feature

Compile native ValuePattern/InvokePattern call sites only with the additive
`windows-ui-write` Cargo feature, whose default is off. A feature-enabled build
does not itself grant authority; runtime config, capability, policy, and fresh
native validation remain mandatory.

## ADR-011: Synchronous consumed transaction with outcome normalization

Keep the policy lease for one synchronous sealed sender call. Validate the
approved mode in both dispatcher and backend. Accept only
`StagedAndRestored` from stage and commit-attempt outcomes from commit; map any
sender-result mismatch to non-retryable submission uncertainty.

## ADR-012: Bind freshness to a process instance and cross-process mutex

Include process creation time in a run-local executable-instance fingerprint
and requery it with PID, HWND, path, session, and UIA identity immediately
before mutation. Hold a zero-wait named Windows mutex through final validation,
write, readback, restore, or Invoke. Contention, abandonment, and wait failure
are non-retryable uncertainty, never permission to continue.

## ADR-013: Treat every post-SetValue failure as uncertain

After entering the first `SetValue`, a provider error or panic cannot prove
that no draft mutation occurred. Normalize every later failure—including
readback, invariant change, clear, restore, and commit preflight—to
`SubmissionUncertain`. Clear only after exact owned-value proof, at most once.
Invoke remains a single-attempt boundary with the same non-retry rule.

## ADR-014: Separate macOS and Windows runtime write authorization

Retain `safety.allow_ax_send` for macOS compatibility and add the default-false
`safety.allow_windows_ui_write` flag. Neither platform's opt-in authorizes the
other. Both continue to require their own target allowlist and safety checks.

## ADR-015: Compile all features in non-live Windows CI

Pin third-party actions to reviewed full commit SHAs. Build both default and
all-feature artifacts, but execute only explicit synthetic unit/contract test
selections. Never infer live UI permission from an all-feature CI pass.

## ADR-016: Keep production writes disabled pending measured selectors

Do not infer self-chat identity from process/window/composer metadata and do
not guess a send button. Until privacy-safe target evidence and an exact unique
Invoke selector are measured and reviewed, advertise `send_open_chat=false`
even in a feature-enabled build. A durable privacy-safe replay ledger is also
required before automatic commit activation.
