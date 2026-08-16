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

At adoption, the probe had no cancellation handshake for an in-process COM
provider call. Hold a process-wide atomic lease for the lifetime of each
detached read-only worker, including after the caller's eight-second receive
deadline. While that lease is held, every backend instance refuses a new probe
without creating a thread. Timeouts are non-retryable. The lease is released
only when the native call returns or unwinds; thread-creation failure also
clears it.

This bounds a provider hang to one retained read-only worker per process. It
does not claim to cancel the provider and does not change the synchronous,
joined mutation-worker rule.

ADR-037 later adds one bounded client-side cancellation request while
preserving this single-flight lease and non-retry rule for unsupported or
still-running providers.

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

## ADR-025: Compile the real trust API adapter without trusting this installation

Implement the process-bound file and WinTrust calls behind the existing
crate-private orchestration seam, but leave the constructor disconnected from
`NativeMutationPort`. Duplicate the already selected process handle, recheck
HWND/PID/creation time, hold no-follow process-image and verification handles,
require a normalized fixed volume-GUID path and reparse-free ancestor chains,
and bind every file identity to process creation time.

Keep WinTrust action, file info, signature settings, and data in stable owned
allocations through exactly one CLOSE attempt. Accept only zero trust status,
one provider signer, no secondary signature, and a bounded DER encoding of the
leaf SPKI. Do not derive an installation-root pin from the current machine:
the native adapter emits no root digest, has no production reference, and
therefore cannot satisfy the pure verifier. A reviewed signed fixture,
signer/root provenance, independent unsafe audit, and a separate wiring
decision remain mandatory.

## ADR-026: Initialize the production ledger lazily and only after trust

Replace `NativeMutationPort`'s unavailable ledger with a lazy factory for the
reviewed LocalAppData store, but perform no known-folder or file operation when
constructing the port. Preserve the transaction's mandatory executable-trust
check before its first ledger method. Because production continues to use
`UnavailableExecutableTrust`, the real locator and store remain unreachable.

Consume the factory before its sole open attempt. Map an error or unwind to the
fixed non-retryable `windows_ledger_state_uncertain` code and do not recreate
or retry it in that transaction object. This closes the production composition
seam without changing capability, target evidence, submit-selector state, or
live authorization. ADR-019, ADR-022, and ADR-024 record the intentionally
earlier disconnected phases; this decision is their reviewed wiring successor.

## ADR-027: Type installation roots as reviewed relative relations

Do not let `ExecutableTrustProfile` accept an arbitrary digest for its
signer or installation root. Accept the signer only through a distinct wrapper
constructed from a source-static 32-byte array, while runtime extraction
produces the evidence-only digest type. Construct the root digest only from a
source-static versioned root kind and bounded exact relative components.
Version 1 permits Program Files x86,
Program Files 64-bit, or current-user LocalAppData as a kind; it accepts only
portable printable-ASCII components, rejects Windows separator/ADS/dot/space/
reserved-character and DOS-device-name ambiguity, folds ASCII case,
length-delimits every
component, and hashes with a fixed domain.

This codec defines how signed provenance can be represented; it supplies no
Kakao value and performs no observation. Keep the native adapter's observed
root absent and production trust unavailable until an independently reviewed
release source selects the exact kind/components and signer SPKI. Also require
the live WinTrust provider state to point back to the exact caller-owned
data/action/signature-settings objects and report primary verified index zero
when no secondary signature exists.

## ADR-028: Bind requested and observed targets with ephemeral opaque proof

Do not treat an allowlist match and three target booleans as proof that the
same target was observed. For every policy inspection, generate a fresh
32-byte key and derive an exact UTF-16 label tag with domain-separated
HMAC-SHA-256. Give the probe only an opaque non-cloneable request. It may mint
evidence only by presenting an exact observed UTF-16 candidate; bind the proof
to every redacted authorization snapshot field.

Keep the permit policy-owned and carried inside `ApprovedSend`. Evidence has
no byte accessor, redacts Debug, is omitted by serde, and fails under another
request key or after any snapshot field changes. Require a separate fresh
`target_binding_verified` gate before draft access and mutation, so
self/exact/unique booleans alone never suffice.

This is a synthetic contract, not permission to read a real label. The
production Windows observer remains unchanged and returns no evidence. Any
ephemeral native UTF-16 reader, selector measurement, or live observation
still requires the separately named privacy approval in `ACTIVATION_RFC.md`.

## ADR-029: Hold canonical read-share guards across native trust verification

Do not rely on before/after file identity equality around
`GetFileVersionInfoW`: that API ignores its legacy handle parameter and reads
by filename, so replace/read/restore is otherwise indistinguishable. Keep the
initial process-image discovery handle broadly shared, then open the canonical
verification file and each canonical parent directory with
`FILE_SHARE_READ` only. A conflicting existing writer/deleter fails closed;
future write, delete, and rename opens remain excluded until VERIFY, provider
extraction, CLOSE, and final reopen finish.

Retain all guards in the opaque path state, preserve no-follow/fixed-volume/
process-creation/three-identity checks, and keep the adapter disconnected with
no installation-root digest. Freeze fixture and production evidence acceptance
in `TRUST_PROVENANCE.md`; this decision supplies no Kakao signer, path, root,
selector, or capability activation.

## ADR-030: Commit a non-retained-key Authenticode fixture and preserve WinTrust in/out flags

Generate one inert PE from committed C/resource source, sign it once without a
timestamp using a one-purpose self-signed code-signing certificate, retain only
the public DER certificate, remove the temporary PFX, clear its byte buffer,
and dispose the certificate/key objects after signing. The repository retains
no private key. Record
build-script/source/unsigned/signed/certificate/SPKI hashes and
the exact reviewed Windows toolchain in a committed manifest. Regeneration
creates a new key and requires explicit review of every changed artifact and
hash. The fixture signer can never satisfy a production profile.

Use one deterministic test to bind those committed bytes to a bounded PE32+
security directory, exactly one `WIN_CERTIFICATE`, parseable certificate DER,
and the expected SPKI digest without executing the PE. Use a separate Windows
test to open only that repository fixture through no-follow fixed-volume
guards, call `WinVerifyTrust` with the unchanged cache-only/noninteractive
production policy, accept either cached trust result, and attempt CLOSE exactly
once. Do not install a certificate, alter a trust store, weaken flags, or make
trust success a normal-CI requirement.

Treat `WINTRUST_SIGNATURE_SETTINGS.dwFlags` as the documented in/out field it
is. After VERIFY, require the input mask to remain exactly
`WSS_GET_SECONDARY_SIG_COUNT`, allow only documented `WSS_OUT_*` result bits,
and reject every changed input or unknown bit. The fixture call demonstrated
that byte-for-byte flag equality incorrectly rejects real WinTrust output.
This decision changes no production reference, root digest, selector, or
capability.

## ADR-031: Derive observed roots from a source-static known-folder kind

Retain the reviewed root kind inside `ExecutableTrustProfile` while keeping its
expected component list and digest private to the pure verifier. Pass only that
kind to the disconnected native observer. Map it exactly to
`FOLDERID_ProgramFilesX86`, `FOLDERID_ProgramFilesX64`, or
`FOLDERID_LocalAppData`; never use an environment variable, registry guess, or
path learned from the current executable as the authority.

Own and free every non-null Shell path allocation even on HRESULT failure.
Open the selected source/canonical root and all ancestors without following
reparse points and retain canonical read-share-only handles through executable
version lookup, WinTrust VERIFY/extract/CLOSE, root revalidation, and the final
executable reopen. Require both handle-derived paths to use the same fixed
volume-GUID root and require the executable to be a strict descendant at an
exact component boundary.

Reduce only one to eight bounded portable ASCII relative components in
zeroizing temporary buffers through the existing version-1 codec. Runtime code
receives only an evidence `TrustDigest`; it cannot construct the distinct
reviewed root type. This supersedes the deliberately absent-root portion of
ADRs 025 and 029, but supplies no production kind, components, signer, adapter
caller, selector, or capability activation. No test or production path resolves
a real executable-trust known folder in this change.

## ADR-032: Prove Shell path ownership before HRESULT interpretation

Keep the raw `SHGetKnownFolderPath` declaration because the generated wrapper
cannot preserve a non-null output pointer on failure. Move the returned HRESULT,
pointer, and private matching release function immediately into one result
decoder. It must construct the RAII owner before inspecting HRESULT and release
every non-null pointer exactly once on success, failure, or later path
validation refusal; NULL is never passed to a release callback. Keep the raw
decoder, constructor, and release callback typed `unsafe` with documented
matching-allocation and successful-string preconditions at each caller.

Exercise this lifetime with synthetic `CoTaskMemAlloc` buffers and a counting
release wrapper. Cover success, `E_FAIL`, relative-path refusal, successful
NULL, and failed NULL without invoking `SHGetKnownFolderPath`. The production
release remains `CoTaskMemFree`, the full adapter remains disconnected, and
this decision supplies no Kakao value, native observation, or activation.

## ADR-033: Carry approval-owned target binding through native preflight

Do not let a native target observer choose which authorization snapshot an
observed label is checked against. `ApprovedSend` exposes only an exact UTF-16
label check that always verifies the permit against the private snapshot stored
inside that same approval. It accepts no caller-supplied snapshot.

Make `NativeMutationPort` borrow that `ApprovedSend` for the full synchronous
stage or commit operation. Use the same approval-owned check during fresh
observation and every final target preflight before draft access, `SetValue`,
or `Invoke`. Reduce an ephemeral observed-label option to booleans immediately;
retain no label in `TargetEvidence` or the port. Exactness and uniqueness remain
separate mandatory evidence rather than consequences of a label match.

The current profile passes no observed label and sets exactness and uniqueness
false, so the verifier is not called and production still refuses without
reading title, UIA Name, or any room/profile text. Synthetic tests cover absent,
exact, mismatched, inexact, and non-unique observations. This decision adds
permit plumbing only; it supplies no selector, label reader, live permission,
or write activation.

## ADR-034: Make contradictory target observations unrepresentable

Do not accept an optional observed label plus independently supplied exact and
unique booleans. That tuple permits impossible combinations and could invoke
the approval-owned label verifier for an inexact or ambiguous selection.

Represent native target selection with a closed internal state:
`Absent`, `UniqueInexact`, `AmbiguousInexact`, `AmbiguousExact`, or
`ExactUnique(label)`. Derive every `TargetEvidence` boolean from that state.
Only `ExactUnique` may carry an ephemeral UTF-16 label or invoke the binding
callback; every other state produces no binding or self-chat proof. Keep the
four-way authorization conjunction even though the closed state narrows valid
combinations, so downstream checks remain fail-closed under future changes.

The current production observer constructs only `Absent`. Synthetic tests
cover every state plus an exact-unique label mismatch and prove by panic
canaries that no non-exact/non-unique state calls the verifier. This supersedes
only ADR-033's tuple representation; it adds no selector, label read, Kakao
value, live permission, or capability.

## ADR-035: Seal every approval to a process-local monotonic deadline

Do not rely on the snapshot's Unix-millisecond expiry alone. Immediately before
the policy reads its wall clock, capture `std::time::Instant`; after the existing
half-open snapshot validation, add only the remaining wall-clock lifetime to
that anchor and store the resulting private deadline inside `ApprovedSend`.
The deadline is neither public, cloneable independently, serializable, nor
included in Debug output.

Treat an approval as fresh only while both clocks remain fresh. Policy execute
refuses at the monotonic boundary before calling a sender. The Windows backend
checks the same approval-owned deadline before worker dispatch, native entry,
correlation consumption, every fresh observation, final native revalidation,
and the actual `SetValue` or `Invoke` call. Native checks retain the wall-clock
expiry as a second independent gate. Equality is stale for both clocks.

This makes a wall-clock rollback unable to extend an approval; a wall-clock
advance can only refuse earlier. The deadline is intentionally process-local:
approvals are already nonserializing in-process capabilities and cannot be
restored after restart. Synthetic tests inject future `Instant` values and use
pure clock-state cases; they do not sleep, change the system clock, inspect a
desktop, or mutate UI. This decision changes no selector, capability, live
permission, or retry rule.

## ADR-036: Treat visible owned popups in the selected owner group as modal

Do not infer modal absence solely from the selected window's enabled style.
After exact executable-name verification during native inspection,
synchronously enumerate top-level windows and mark the selected window blocked
when it is disabled or a visible same-process candidate has an owner and the
same `GA_ROOTOWNER`. Ignore hidden,
foreign-process, unowned, and different-root-owner candidates. Treat every
matching owned popup as blocking even if it might be modeless; safety accepts
that conservative false positive. Any relevant owner-chain uncertainty fails
closed.

Read only HWND/PID, visibility, owner, and root-owner metadata. Retain no
candidate collection or text, and never query a candidate title/class, UIA
Name/Value, room/profile label, or draft. The already selected window's exact
class/PID is revalidated. Positive modal evidence prevents composer
traversal and suppresses composer identity and input availability in the
public snapshot. Repeat the scan in fresh observation, final native preflight,
and each actual `SetValue`/`Invoke` boundary before the final time check and
native call.

Pure synthetic classification and mapping tests invoke no desktop API. This
generic owner-chain rule cannot recognize unowned custom dialogs or overlays
drawn inside the selected window, so those remain future negative measurement
requirements. The decision adds no selector, write capability, live
authorization, or KakaoTalk observation.

## ADR-037: Request cancellation for timed-out read-only COM calls

Enable COM call cancellation on the fresh read-only MTA worker before any
inspection call, then publish that worker's OS thread ID to the caller. Treat
thread creation, cancellation readiness, and inspection as one eight-second
budget. The caller grants one inspection permit only after receiving readiness
within that budget, and the worker rechecks the budget before native entry.
Closing the permit on an earlier timeout prevents a racing readiness event
from starting late work. If the deadline expires after readiness, keep the
worker blocked on a release channel while the caller makes exactly one
`CoCancelCall(thread_id, 0)` request. Release and detach only after that
request. This ordering prevents thread-ID reuse from directing cancellation at
an unrelated COM call. Catch a post-readiness Rust unwind as a fixed worker
failure so it follows the same pinned lifetime.

Pair every successful `CoEnableCallCancellation` with one
`CoDisableCallCancellation` attempt while the worker apartment is live;
`CoUninitialize` resets the fresh thread even if disable reports failure. A
normal completion releases and joins the worker before returning. Continue to
return the same non-retryable timeout after a cancellation request and ignore
late results.

This is a client-side containment request, not proof that provider work
stopped. Standard-marshaled synchronous calls may unblock, while a custom
marshaler may provide no cancel object and a server may continue processing.
The process-wide lease therefore remains owned by the worker until it actually
returns. Restrict cancellation to metadata-only inspection; the synchronous,
joined mutation worker is never cancellation-enabled. Pure tests cover the
total budget, pre-readiness permit closure, terminal HRESULT classification,
and thread-release ordering without calling COM or a desktop API. This
decision adds no dependency feature, selector, capability, live permission,
or KakaoTalk observation.
