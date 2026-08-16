# Child B Wave 2 P50 adversarial audit handoff

## Status and provenance

- Task: P50 safety-policy adversarial audit.
- Branch: `agent/safety-audit-w2`.
- Wave 1 integration ancestor: `fed2bb1558b4e07878f17f4c8140aab5ead682b2`.
- Status: owned hardening, synthetic audit coverage, and build verification
  complete. The atomic commit SHA is reported to root after creation.
- Atomic commit: the commit containing this file. Its content-derived SHA
  cannot be embedded in itself and is reported to root after creation.

The audit used only synthetic snapshots, messages, labels, clocks, probes, and
senders. It performed no Windows API call, UI inspection, UI mutation, send,
KakaoTalk data access, credential access, network operation, install, push, or
pull request.

## Owned changes

- Snapshot strings that cross into an approval must now use the production
  execution-scoped fingerprint shape (`run:` plus 128-bit lowercase hex).
  Arbitrary strings are refused before a dry-run plan or approval is created.
- The selector profile identifier must exactly equal the supported frozen
  selector profile, rather than merely being nonempty.
- Window and composer fingerprints must be distinct.
- Probe errors are rewritten to fixed dry-run/authorization policy operation
  codes while preserving the frozen error kind and conservative retry flag.
  Clock errors become a fixed `StaleSnapshot` refusal.
- Approval mutex contention now refuses immediately instead of blocking for an
  unbounded time. Poisoning remains fail-closed. A contention refusal does not
  consume the waiting nonce.
- Empty and all-whitespace configuration labels are refused. Exact matching
  still performs no trimming, case folding, normalization, glob, regex, or
  confusable mapping.
- Empty and all-whitespace messages are refused. Unicode line and paragraph
  separators join the existing NUL/CR/LF/control-character refusals.
- Rejected configuration buffers, stored configuration labels, and the raw
  nonce consumed during approval are zeroized within the owned boundary.

## Synthetic audit coverage

The expanded policy suite covers:

- non-self, non-exact, duplicate target, duplicate top-level windows, missing
  target, and multiple composers;
- app disappearance, unsupported version/profile, session/integrity refusal,
  draft appearance, focus/user activity, and modal presence;
- arbitrary/unredacted process, window, composer, and selector evidence;
- partial, case, ASCII whitespace, non-breaking/ideographic/zero-width space,
  Cyrillic lookalike, and composed/decomposed Unicode label variants;
- zero, exact scalar/byte limit, one-over-limit, control, CR/LF, Unicode
  line/paragraph separator, and all-whitespace message cases;
- expiry boundary, future observation, inverted/zero/overlong TTL;
- explicit confirmation, dry-run non-approval and zero mutation calls;
- same-nonce racing, distinct-nonce contention, mutex poisoning, replay after
  lease drop, and independent policy-instance behavior;
- probe/clock operation-string injection, configuration/plan/approval/error
  Debug and serialization redaction;
- an audit sequence where PID, process/window/composer fingerprints, draft,
  focus, and modal state change after authorization;
- an audit sender proving that the same lent `&ApprovedSend` can currently
  reach a fake commit more than once.

The last two tests intentionally document current cross-owner contract gaps;
they do not claim the behavior is safe.

## Findings by severity

### Critical before any live mutation: approval replay and TOCTOU

`WindowsSafetyPolicy::authorize` validates one snapshot and returns an
`ApprovedOperation`. `ApprovedOperation::approved(&self)` can lend the same
`&ApprovedSend` repeatedly, and `MessageSender::commit` accepts that shared
borrow. Nonce consumption prevents minting a second approval in the same
policy instance, but it does not prevent two or more mutation calls with the
already-minted approval.

The approval also retains only its original snapshot. PID, process/window/
composer fingerprints, target, draft, modal, or focus can change after policy
inspection and before a sender call. Nothing in the current trait requires a
fresh comparison, and a stale approval remains lendable. The production Wave
1 CLI does not invoke authorization or mutation, so this is latent rather than
an active send path.

### Critical current gate: target identity and draft evidence remain absent

The production backend deliberately reports self-chat/exact/unique/draft-empty
evidence false. This is the correct fail-closed behavior. No write capability
may become true until a separately approved, privacy-preserving evidence
design binds the requested allowlisted label to the observed target and proves
the draft is empty.

### High before mutation: PID reuse and recycled native identity

`ProcessFingerprint` contains PID, executable-path fingerprint, and session,
but no process creation time or process-instance identifier. A restarted copy
of the same executable can reuse the same PID/session and become
indistinguishable. The Windows window/composer fingerprints are based on
native handle plus PID (and selector domain), so handle recycling in the same
backend execution can also recreate an old published identity.

### High before mutation: mutex and replay are instance-local

The standard-library mutex and nonce digest set belong to one
`WindowsSafetyPolicy`. Two policy instances in one process, and necessarily
two CLI processes, can approve the same nonce concurrently. State also resets
on process exit. Owned code now refuses contention within one instance, but it
cannot provide cross-process exclusion or durable one-shot semantics.

### High contract issue: mutation-start uncertainty remains untyped

The audit initially found `SendOutcome::retry_safe()` returning `true` for
`EchoConfirmed`. Root resolved that classification after this branch's base in
commit `8a8943132866bc4fc2fc3c0c4a9a87d2db150c19` and covered it in the shared
outcome test. The trait still permits a commit implementation to return
`NotSubmitted`, `StagedAndRestored`, `DryRun`, or a retry-safe `Timeout` after
the mutation call began. No type records the commit-start boundary.

There is no production retry loop or production commit call in the integrated
Wave 1 source. Nevertheless, the shared-borrow approval and result contract
permit a future caller to retry, including after `Indeterminate`.

### High privacy issue: rendered operation codes are not closed

`UiError.operation` is an arbitrary `&'static str`, and Windows output copies
it directly into stderr and JSON. A backend or caller can therefore inject a
static canary. The safety policy now rewrites errors received from its own
probe/clock seams, but UI doctor and other callers remain outside that owned
fix, and the renderer itself is not a trust boundary.

### Medium integration issue: nonce correlation was erased

The owned replay set retains only a domain-separated digest, and the nonce
inside `ApprovedSend` is a redaction marker. This prevents formatting leaks
but leaves a future indeterminate transaction without a safe correlation value
for the human verification required by the safety plan.

## Exact root RFCs

### RFC-P50-001: consuming, revalidated mutation permit

Replace repeatable `ApprovedOperation::approved(&self)` access with a
non-cloneable, consuming mutation permit. `MessageSender::stage` and `commit`
must consume the appropriate permit or otherwise atomically reject reuse.
Immediately before any mutation, the backend must re-inspect and compare the
approved process instance, executable, session/integrity, top-level window,
target proof, composer, selector profile, draft, modal, focus/user activity,
and TTL while holding the cross-process send mutex. A mismatch aborts without
rediscovery/automatic continuation. The final native validation and mutation
must be one backend transaction; a policy-only second probe is not sufficient.

### RFC-P50-002: process-instance and recycled-handle identity

Extend the common snapshot contract with an execution-scoped process-instance
fingerprint derived from verified executable identity plus process creation
time (not PID alone). Bind window/composer fingerprints to that process
instance and revalidate native ownership immediately before mutation. The
public value remains an opaque redacted fingerprint; no raw path, handle, or
creation timestamp is formatted or serialized.

### RFC-P50-003: cross-process exclusion and replay ledger

The Windows backend must acquire a narrowly named OS mutex before final
revalidation/stage/commit and fail closed on contention/abandonment. Define an
application-owned, privacy-safe transaction ledger or equivalent idempotency
mechanism so a committed/indeterminate nonce cannot be replayed after process
restart. Do not store message text, raw target labels, native handles, or
KakaoTalk data in that ledger.

### RFC-P50-004: confirmed-submission retry semantics (resolved)

Root changed `EchoConfirmed.retry_safe()` to `false` in
`8a8943132866bc4fc2fc3c0c4a9a87d2db150c19` and added coverage to the shared
outcome test. No further action remains for this exact classification.

### RFC-P50-008: commit-start and uncertainty semantics

Encode whether the native commit call started; from that transition onward
every success, timeout, error, and uncertainty result must have
`retry_safe=false`. A commit timeout maps to
`SubmissionUncertain`/`Indeterminate`, never ordinary retry-safe `Timeout`.
The orchestration API must contain no automatic retry edge and the consumed
permit must make a manual second call impossible without a fresh, explicitly
reviewed transaction.

### RFC-P50-005: closed operation-code contract

Replace arbitrary rendered `UiError.operation` strings with a closed enum or a
central allowlist. Windows rendering must map unknown values to one fixed
redacted code before human or JSON output. Add a regression using an injected
static canary through a non-policy probe/doctor path and assert the canary is
absent from both streams.

### RFC-P50-006: privacy-safe nonce correlation

Introduce an opaque transaction/correlation identifier that the backend and
human indeterminate-recovery flow can compare, while custom Debug/Display and
serde always redact it. Keep the raw caller nonce zeroized and retain only a
domain-separated keyed or collision-resistant representation in journals.

### RFC-P50-007: requested-label binding

Future target evidence must cryptographically or structurally bind the exact
requested allowlist entry to the observed self-chat fingerprint. The current
independent checks (requested label is in the allowlist; snapshot boolean says
self-chat) do not prove they refer to the same observed label. Preserve
byte-exact/no-normalization semantics and never expose the raw label.

## Assumptions and residual risks

- Strict `run:` fingerprints match the current production Windows backend.
  Any representation change will fail closed until policy and backend are
  reviewed together.
- In-instance mutex contention is now nonblocking and fail-closed; it is not a
  substitute for RFC-P50-003.
- A syntactically valid fingerprint proves only redaction shape, not native
  continuity or authenticity. RFC-P50-001 and RFC-P50-002 remain mandatory.
- System clock rollback/advance causes TTL refusal when observed; a monotonic
  transaction deadline should accompany future live mutation.
- No live stage, commit, echo, UI compatibility, cross-process mutex, or
  process-restart test was authorized or run.

## Verification

All authorized gates passed using the ignored `.target/child-b` directory:

- `cargo fmt --check`;
- `cargo test --lib safety::` (3 passed);
- `cargo test --test windows_policy` (23 passed);
- `cargo clippy --lib -- -D warnings`.

No live stage, commit, echo, native UI, or product command was run. Tests use
only synthetic fakes and snapshots.
