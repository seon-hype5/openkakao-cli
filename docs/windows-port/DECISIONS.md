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

## ADR-017: Narrow shared-class windows only in read-only discovery

KakaoTalk may expose several top-level windows with the same exact class. For
read-only doctor discovery, inspect at most eight candidates and select one
only when exactly one candidate contains one exact known-profile composer and
all others contain none. A duplicate composer, an internally ambiguous
composer, an inspection error, or an over-limit candidate set fails closed.

This selector uses only non-content metadata and does not establish self-chat
identity. The mutation path deliberately does not reuse the narrowing rule: it
continues to require exactly one raw top-level window before any value read or
write boundary.

## ADR-018: Keep read-only UIA probes process-wide single-flight

An in-process COM provider call cannot be safely cancelled after entry. Hold a
process-wide atomic lease for the lifetime of each detached read-only worker,
including after the caller's eight-second receive deadline. While that lease
is held, every backend instance refuses a new probe without creating a thread.
Timeouts are non-retryable. The lease is released only when the native call
returns or unwinds; thread-creation failure also clears it.

This bounds a provider hang to one retained read-only worker per process. It
does not claim to cancel the provider and does not change the synchronous,
joined mutation-worker rule.

## ADR-019: Compile a pure replay state machine but fail closed without storage

Represent replay state with a strict fixed-size, content-free inner record and
put all durable I/O behind a narrow compare-and-replace store trait. Persist a
ledger-clear preflight before UI observation, then a stage marker before the
final SetValue preflight and one-shot execution claim. Advance to a commit
marker before final Invoke preflight, and retain an indeterminate marker after
every Invoke result. Only an exact restored stage may be removed automatically.

Until the reviewed current-user DPAPI, ACL/reparse, LocalAppData, and atomic
write-through store exists, production uses `UnavailableLedger`. This keeps
the transition code compiled and synthetically testable while adding an
independent refusal before claim or UI mutation. Policy supplies the record
correlation through a separate non-Clone, non-serializing, zeroizing token that
the backend can consume exactly once.

## ADR-020: Model executable trust without observing the current installation

Keep raw executable paths, file IDs, certificate material, and signer/root
values out of the platform contract. A pure verifier accepts only
content-free facts derived from an opened process-image handle: canonical
local fixed-volume path, no reparse point, process-creation binding, exact
file-identity agreement, no-UI/cache-only trusted Authenticode, one exact
signer digest, and one exact canonical-root digest.

Do not guess signer or root values from the current machine. Until reviewed
release provenance supplies them and a separately reviewed native observer is
implemented, production uses `UnavailableExecutableTrust` and refuses before
ledger or UI observation. The seam adds no Windows API feature or live probe.

## ADR-021: Freeze native activation APIs before adding bindings

Use the exact `windows` 0.62.2 namespace delta and ownership rules in
`NATIVE_ACTIVATION_BOUNDARIES.md`. The ledger boundary uses current-user,
UI-forbidden DPAPI, handle-verified protected ACLs, same-directory
write-through replacement, and a blocking tombstone for exact stage removal.
The trust boundary uses a handle-bound final path, fixed local volume and
reparse refusal, offline/no-UI WinVerifyTrust, explicit secondary-signature
rejection, and a SHA-256 leaf-SPKI pin.

The inventory is not production wiring. Add APIs in reviewable stages, test
only synthetic storage/fake trust adapters, and keep both unavailable
placeholders until their independent review and profile evidence exist.

## ADR-022: Compile the native ledger against synthetic storage first

Implement current-user DPAPI, exact protected ACLs, no-reparse handle checks,
bounded exclusive I/O, write-through replacement, and tombstone removal only
behind an explicit synthetic temporary-base constructor. Inject failures at
every durable boundary and reload after each one. Any leftover temporary or
tombstone artifact blocks automatic use.

Do not add a production LocalAppData constructor or replace
`UnavailableLedger` in the same change. Parent-chain/local-volume review,
independent unsafe audit, real process-termination testing, and human recovery
remain separate activation decisions.

## ADR-023: Close every WinTrust state before accepting copied evidence

Freeze a single embedded-file, noninteractive, no-UI, cache-only WinTrust call
policy behind a crate-private adapter. After VERIFY creates state, attempt
exactly one CLOSE whether extraction succeeds, fails, or unwinds. A CLOSE
failure or panic overrides apparent success. Only copied content-free evidence
may reach the pure verifier after CLOSE. Retain an opaque original-path state
through CLOSE and observe the third file identity only afterward.

Reject catalog choice, secondary signatures, nonzero trust status, and
non-exact primary signer cardinality without fallback. Keep production on
`UnavailableExecutableTrust` until a separate native adapter and independently
reviewed signer/root profile exist.

## ADR-024: Retain the canonical LocalAppData base handle before ledger wiring

Resolve current-user LocalAppData without environment variables, inspect both
the original Shell path and handle-derived volume-GUID path component by
component without following reparse points, require a fixed local volume, and
retain the canonical base handle through the ledger store lifetime. Revalidate
that handle before and after opening the protected child directory.

Compile the complete constructor separately from the synthetic store, but do
not reference it from `NativeMutationPort`. Existing directories are accepted
only after the same exact type, owner, protected-DACL, and entry checks used by
the synthetic boundary. Production remains on `UnavailableLedger` until an
independent unsafe review and a separate wiring decision.
