# Child A handoff: guarded Windows transactions, Wave 2

## Status

Complete on branch `agent/win-send-w2`. The atomic child commit is the branch
tip containing this handoff; its exact SHA is reported to root after commit
creation because a commit cannot contain its own content-derived SHA.

Default builds do not compile a production UI write boundary. The root-owned
`windows-ui-write` Cargo feature is default-off. With the feature enabled, the
backend accepts only `&ApprovedSend`, validates the approval envelope, runs on
a scoped windowless MTA worker, acquires a zero-wait named OS mutex, and treats
the approval snapshot only as expected evidence. PID, executable-instance
fingerprint, creation time, session, integrity, window/composer fingerprints,
profile, visibility/enabled/modal state, foreground/focus state, target
identity, draft classification, staleness, and commit selector state must all
be freshly and independently observed before the one-shot execution claim and
first mutation.

The current `26.7.0.5255` profile has neither a privacy-safe verified self-chat
selector nor a verified send-button selector. Native fresh state therefore
keeps `self_chat_verified`, `exact_target`, and `unique_target` false and does
not call `CurrentValue`. Stage refuses before claiming or calling `SetValue`.
Commit additionally reports an unconfigured selector and cannot acquire or
call `InvokePattern`. `UiCapabilities.send_open_chat` remains false. This is an
intentional production refusal, not a claim that process/window identity proves
target identity.

The platform-independent transaction seam implements the future guarded flow:

- stage requires an independently verified empty draft, claims the approval
  exactly once immediately before `SetValue`, requires exact UTF-16 readback,
  and clears only while the exact owned value and every live invariant remain;
- a changed/mixed draft is never cleared;
- commit requires a verified unique `InvokePattern` selector before staging,
  repeats fresh exact readback/state validation before one Invoke, never
  retries, and maps every returned error or panic after Invoke entry to
  `SubmissionUncertain` (`retry_safe=false`), which the safety/CLI layer maps to
  the `Indeterminate` outcome;
- selector loss after staging permits restore only when all non-selector
  evidence still proves the exact value is owned.

No approval-snapshot boolean substitutes for fresh native evidence. In
particular, a public caller cannot inspect a real backend, flip public fields in
a fake probe, authorize against that fake, and thereby reach a mutation.

## Changed files

- `src/platform/windows/mod.rs`
- `src/platform/windows/native.rs`
- `src/platform/windows/transaction.rs`
- `tests/windows_backend/main.rs`
- `docs/windows-port/handoffs/child-a-wave2.md`

Child A did not edit a manifest, lockfile, common contract, policy, CLI/output,
module index outside the owned Windows module, or any non-handoff documentation.

## Security and privacy invariants

- The named mutex is held across final native validation, SetValue, exact
  readback, restore, and any future Invoke. Contention and abandoned ownership
  fail closed; there is no wait/retry loop.
- The execution-scoped process digest binds the absolute executable path to the
  process creation `FILETIME`. Raw path, time, PID/HWND-derived identities, and
  UIA interfaces never leave the native worker. PID, HWND, path, session, and
  creation time are rechecked inside every SetValue/Invoke boundary.
- `OpenProcess` requests only `PROCESS_QUERY_LIMITED_INFORMATION`; there is no
  process-memory access.
- `CurrentValue` is unreachable until live self-target evidence is true. When a
  future profile supplies that evidence, its BSTR is compared only as UTF-16
  emptiness/exactness, never decoded, formatted, logged, or serialized.
- Secret message UTF-16 is created directly in a `Zeroizing<Vec<u16>>`.
  `BSTR::from_wide` avoids windows-strings' unsanitized `From<&str>` temporary.
  A narrow wrapper scrubs both outbound and returned BSTR allocations in place
  before their normal `SysFreeString` drop.
- No focus/Z-order APIs, key input, clipboard, screen capture, raw UI tree,
  window/UIA Name, window title, KakaoTalk data file, credential, token, hook,
  injection, or window-message API is present.
- The mutation worker is scoped and joined. There is no detached timeout that
  could return while a UIA provider continues mutating.

## Synthetic verification

All Rust artifacts used the isolated `.target/child-a` directory. No test
called `WindowsBackend::inspect`, `stage`, or `commit` against the desktop.

- `cargo fmt --all -- --check`: passed.
- `cargo check --lib`: passed (default feature set).
- `cargo check --lib --all-features`: passed.
- `cargo test --lib platform::windows`: passed, 19 tests; 0 failed.
- `cargo test --lib platform::windows --all-features`: passed, 19 tests; 0 failed.
- `cargo test --test windows_backend`: passed, 2 tests; 0 failed.
- `cargo test --test windows_backend --all-features`: passed, 2 tests; 0 failed.
- `cargo clippy --lib -- -D warnings`: passed.
- `cargo clippy --lib --all-features -- -D warnings`: passed.

Synthetic tests cover the complete fresh-precondition refusal table with zero
claim/SetValue/clear/Invoke calls; forged/fake-approved live self-target
mismatch; exact-expiry refusal; final native preflight failure before claim;
one-shot claim rejection; exact stage/readback/restore; changed-draft no-clear
behavior; absent/ambiguous/unconfigured commit selectors; exact single Invoke;
post-Invoke uncertainty/no-retry; selector-loss safe restore; version gating;
selector uniqueness; and native-to-contract mapping.

## Skipped tests and safety ledger

- Live KakaoTalk/UIA discovery or mutation: not run.
- `CurrentValue`, `SetValue`, or `InvokePattern::Invoke` against a live COM
  provider: 0 calls.
- Messages sent, focus changes, key/clipboard operations, screenshots/UI dumps,
  process-memory reads, KakaoTalk data/credential reads: 0.
- Package installs, network writes, pushes, merges, and PRs: 0.

No stage-only live canary or automatic commit is authorized by this handoff.

## Unsafe audit

Every unsafe block in `native.rs` was reviewed. They are limited to:

- balanced COM apartment initialization/uninitialization and same-apartment UIA
  interfaces;
- synchronous `EnumWindows` with panic containment and a stack-bounded callback
  context;
- read-only Win32 process/window/token/version/session/creation-time queries;
- kernel mutex create/wait/release/close with explicit ownership states;
- exact, bounded UIA property conditions and pattern calls behind all guards;
- validated pointer/layout access for token SIDs and version resources; and
- the uniquely owned BSTR allocation scrub immediately before normal free.

No unsafe block transfers a COM interface across threads, retains a borrowed
HWND beyond its scoped worker, reads process memory, or introduces a retry.

## Assumptions and residual risks

- Disabled top-level state is the current conservative modal signal. No private
  modal title/tree is inspected, so richer modal classification remains open.
- User inactivity is conservatively checked through target foreground state and
  composer keyboard focus immediately before mutation. No focus is changed.
- Exact basename/version and creation-bound path digest are not executable
  signing or canonical install-root verification.
- Synchronous UIA providers can hang. A mutation worker intentionally waits
  rather than returning while a detached mutation might still complete.
- If state ceases to prove the staged value is owned, the backend intentionally
  leaves it untouched. A future caller must surface that possible staged draft
  for human resolution; automatic cleanup is unsafe.
- The OS mutex is cross-process mutual exclusion, not durable replay storage.
  Durable replay is not authorized or required while commit remains unsupported.
- The root-owned consuming `ApprovedOperation::execute` contract change
  (`658b541`) closes the public borrowed-capability replay seam at orchestration;
  backend `try_claim_execution` remains defense in depth immediately pre-write.

## RFCs and blockers

Root-owned RFCs accepted before this child commit:

- `approved-send-one-shot-execution-claim` (`ebc9368`): crate-private atomic
  `ApprovedSend::try_claim_execution` with fail-closed reuse error.
- `windows-ui-write-build-gate` (`5550384`): additive, default-off
  `windows-ui-write` Cargo feature; no dependency or license change.

Remaining blockers are intentionally not guessed:

1. **Self-target evidence RFC.** Supply a privacy-safe, version-bound selector
   or other independently live proof of self-chat, including exact/unique
   semantics, 20/20 measured uniqueness, negative-room results, fingerprint
   derivation, staleness behavior, and proof that no private label is emitted.
   Until accepted, Value is not read and stage is unavailable.
2. **Send-selector profile RFC.** Supply exact case-sensitive class,
   AutomationId, control type, bounded ancestor relation, enabled state, and
   `InvokePattern` availability for version `26.7.0.5255`, with 20/20 uniqueness
   and absent/duplicate/wrong-room negative results. Keyboard/Enter fallback is
   excluded. Until accepted, commit is unavailable.
3. **Durable replay RFC.** Define storage scope, atomicity, crash recovery,
   privacy retention, permissions, and compatibility before any supported
   automatic commit. This wave neither creates nor reads durable state.

No dependency, feature, or common-contract change remains requested by Child A.
