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

## ADR-038: Make hosted Windows CI match the local safe release matrix

Gate the same five synthetic compatibility targets, both default and
all-feature release builds, and the optimized all-feature Windows unit-test
subtree that root already requires locally. Keep the existing exact-name CLI
allowlist; never broaden it to a whole target or a skip-based denylist.

Validate every local link below `docs/windows-port`, reject resolved targets
outside the repository, require the exact repository toolchain pin, and parse
every third-party `uses:` reference in the Windows workflow as a full
lowercase 40-hex commit SHA. Trigger the workflow for every Windows-port
documentation change. Keep this validator inline so the hosted gate does not
depend on relaxing PowerShell execution policy or installing a parser.

These additions may read repository source and execute only synthetic tests.
They must not invoke the product, prepare a desktop session, upload artifacts,
inject secrets, or infer live authorization from a green result. The first
GitHub-hosted run remains external evidence; local parity proves only that the
committed commands pass in the current non-live workspace.

## ADR-039: Verify provider-owned WinTrust policy and catalog state

Do not derive catalog absence from the caller-owned `WINTRUST_DATA` union: it
is fixed to `WTD_CHOICE_FILE` before VERIFY and therefore cannot independently
describe provider recall. After a zero WinTrust result and before signer
extraction, require the returned `CRYPT_PROVIDER_DATA` to retain exact pointers
to the caller's data, action, and signature-settings allocations, select
`CPD_CHOICE_SIP`, report the exact caller low-word flags plus
`CPD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, and carry zero low-level and final
errors. Treat `fRecallWithState=true` as catalog ambiguity and refuse through
the existing pure trust verifier.

Exercise every field with an inert in-memory provider structure. These tests
call no helper, WinTrust, filesystem, process, window, or UI API. Keep the
adapter disconnected and `UnavailableExecutableTrust` wired until independent
fixture/root review and production provenance are complete.

## ADR-040: Make provider-chain traversal fakeable and reject nested errors

Place the three WTHelper pointer-returning operations behind one private
raw-pointer trait and make the single consuming extraction function unsafe.
Its call contract retains every returned provider structure until CLOSE. The
production implementation delegates only to the documented helpers. A test
implementation retains boxed `CRYPT_PROVIDER_DATA`,
`CRYPT_PROVIDER_SGNR`, and `CRYPT_PROVIDER_CERT` structures and returns their
exact pointers synchronously.

After top-level provider policy validation and exact signer cardinality one,
require the signer helper to return `pasSigners`, require signer `dwError` to be
zero, require a nonempty bounded certificate chain, require the certificate
helper to return `pasCertChain`, and require the leaf provider certificate's
`dwError` to be zero before consuming its context or SPKI. Exercise one exact
successful fixture-SPKI path, both nested error fields, and both helper pointer
substitutions without calling WinTrust or opening a file. This qualifies local
traversal logic only; real provider output, the helper ABI, independent unsafe
review, production provenance, and wiring remain separate gates.

## ADR-041: Bind executable trust to every reviewed target byte and SHA-2 policy

Add a distinct source-static `ReviewedExecutableDigest` to every executable
trust profile. It represents `whole-file-sha256-v1` for the installed target,
not the installer and not the Authenticode PE digest. Stream the complete
guarded file through a bounded zeroizing buffer, restore the handle position on
every path, and require the runtime digest, exact version, target leaf SPKI,
and root relation independently. Runtime evidence cannot construct any
reviewed profile value.

Populate `WINTRUST_SIGNATURE_SETTINGS.pCryptoPolicy` with a stable
`CERT_STRONG_SIGN_PARA` selecting `szOID_CERT_STRONG_SIGN_OS_1`. Retain and
revalidate the allocation and OID pointer through VERIFY and CLOSE. This makes
the intended OS policy explicitly SHA-2-only instead of relying on
`WTD_DISABLE_MD2_MD4`, which does not exclude MD5 or SHA-1. Pure and inert-
state tests cover missing/mismatched target bytes and every mutable policy
field. A trusted SHA-2 success plus MD5/SHA-1 rejection on an isolated pinned
Windows image remains an activation gate. Production stays disconnected.

## ADR-042: Describe and qualify the NTFS path-requery guard honestly

`QueryFullProcessImageNameW` returns text derived from a process handle; it
does not provide a caller-owned backing-file handle or a documented atomic
file identity. Rename/replace testing proved that an executing synthetic PE
can be renamed on NTFS while the original name is replaced. Therefore hold the
first candidate without write/delete sharing, query the image path again,
independently guard the second candidate, and require exact canonical path and
file-ID agreement before any version, hash, or WinTrust decision. Restrict the
pure verifier to NTFS on a fixed local volume.

Name the evidence `RequeriedProcessImagePathGuarded` and
`process_image_path_requeried_and_guarded`; never call either candidate a
process-image backing handle. This supersedes that inaccurate wording in
ADR-020 and ADR-021. The guarded protocol closes races during observation, but
the API contract does not promise rename freshness. Production wiring remains
blocked until before/between/after-query substitution tests pass on every
supported Windows/NTFS image. The stronger long-term option is a backing-file
handle retained from launch or another documented kernel identity.

## ADR-043: Treat WinTrust provider high-word flags as activation evidence

Keep the disconnected adapter fail-closed while provider ABI qualification is
incomplete. The current exact `CRYPT_PROVIDER_DATA.dwProvFlags` comparison
accepts the caller low word plus `CPD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT` and
rejects all other high-word bits. That cannot weaken verification, but it may
refuse a valid RFC3161-timestamped target because the provider may add
`CPD_RFC3161v21` or another documented flag.

Before activation, exercise a trusted timestamped target on the pinned Windows
image. The final policy must preserve the caller low word exactly, select only
chain-excluding-root revocation, explicitly review any RFC3161 or lower-quality
chain bit, and reject `CPD_USE_NT5_CHAIN_FLAG` and unknown bits. Do not loosen
the comparison merely to make the self-signed untimestamped fixture pass.

## ADR-044: Keep every branch-push CI workflow inside the non-live boundary

Both workflows triggered by an integration-branch push must be safe together.
Replace the legacy broad cross-platform `cargo test` with explicit synthetic
library/binary/compatibility suites and the same fourteen exact parser cases as
Windows CI. Never execute the product on macOS. Pin Rust, lock dependencies,
pin every third-party action by full commit SHA, grant only read-only contents
permission, disable checkout credential persistence, reference no secret, and
upload no artifact.

The Windows validator scans both non-release workflows for mutable action
references and local documentation links. A validator running in a parallel
workflow does not prevent future bad action code from starting first, so a
same-workflow validate/`needs` topology remains optional hardening. The
tag/manual release workflow is outside this non-release claim and requires its
own review before use.

## ADR-045: Automate supported-image native-trust assumption qualification

Treat SHA-2 strong-hash semantics and process-image path freshness as explicit
supported-Windows evidence rather than implications of pointer layout or one
manual rename experiment. Run `CertIsStrongHashToSign` with the exact
production `CERT_STRONG_SIGN_PARA` and no certificate; require MD5/SHA-1
refusal and SHA-256 acceptance. Exercise replacement completed before the
first process-image query, between the first query and guarded open, and after
the second query.

The hosted OS gate may make only a byte-exact copy of the OS-supplied System32
`ping.exe` inside a generated temporary root, launch it windowlessly against
`127.0.0.1`, stop every owned process, and delete only that validated root. A
Rust unit test separately launches an exact ignored copy of its own harness and
calls the production requery helper. Neither path executes the product, touches
user or application state, changes a trust store, or performs external network
access.

The signed-PowerShell equivalent passed on Windows `10.0.26200.0`/NTFS. Local
Smart App Control refused the newly linked unsigned Rust test executable before
entry, so do not weaken or bypass that policy; require the committed test on a
pinned hosted Windows image. These gates qualify only hash-policy and path-
requery assumptions. A trusted timestamped positive provider traversal,
weak-signed WinTrust end-to-end refusal, architecture-specific target bundle,
and separate production wiring review remain mandatory for activation.

## ADR-046: Accept the qualified x64 target and exact provider output

The accepted
[`KAKAOTALK_X64_TRUST_PROFILE.md`](KAKAOTALK_X64_TRUST_PROFILE.md) supersedes
ADR-043's provisional high-word decision. Two positive target reproductions
returned `CRYPT_PROVIDER_DATA.dwProvFlags=0x80003080`: the SDK-guaranteed caller
low word plus only `CPD_USE_NT5_CHAIN_FLAG`. Require that exact value. Continue
to reject CPD revocation high bits, RFC3161, lower-quality-chain, and unknown
bits; the caller already requires whole-chain revocation excluding root,
cache-only retrieval, and the SHA-2-only strong-sign policy.

The x64 installer also accepts NSIS `/D`. Treat that as explicit distribution
behavior, not as a reason to weaken or abandon the canonical-root boundary.
The production profile selects only `FOLDERID_ProgramFilesX64` with components
`Kakao`, `KakaoTalk`, `KakaoTalk.exe`; every override and alternate relation
must fail closed. This supersedes the earlier rule that installer support for
more than one root automatically blocks an otherwise exact runtime profile.

Profile acceptance authorizes source-static executable/signer/root values and
native trust wiring only. It leaves `send_open_chat=false`, self-target and
submit selectors unconfigured, and every L10-L40 live gate separately
unauthorized.

## ADR-047: Ignore invisible exact-class windows only in read-only discovery

`EnumWindows` can report invisible helper or parking windows that share
KakaoTalk's exact top-level class. An invisible window cannot satisfy the
existing visible-target gate, but counting it in read-only discovery can either
consume the eight-candidate ceiling or produce `NotInspected`, which makes an
otherwise unique composer-bearing window ambiguous.

Give native enumeration two explicit scopes. Read-only doctor discovery keeps
only visible exact-class windows before applying the existing bounded composer
narrowing. Every mutation preflight continues to use raw exact-class
enumeration and require exactly one raw top-level window. A pure four-case
classifier test freezes the class/visibility matrix for both scopes so a future
refactor cannot silently weaken the mutation boundary.

This change reads only `IsWindowVisible`, never activates or reorders a window,
does not establish self-chat identity, and does not add a submit selector or
send capability. The two failed L10 sessions retained no raw count, so this is
a conservative remediation of a source-level false-ambiguity class rather than
a claimed live root cause. It authorizes no L10 retry or later gate.

## ADR-048: Classify read-only ambiguity with fixed content-free reasons

A third separately approved L10 doctor on the visibility-narrowed successor
still returned `top_level_window_ambiguous`. The existing ambiguous snapshot
discarded every inspected aggregate, so that fixed output could not distinguish
the candidate ceiling, duplicate composers, an internally ambiguous composer,
an uninspected candidate, or the all-absent-composer case. It retained no
private data, but it also could not guide a conservative offline correction.

Carry exactly one `ReadOnlyWindowAmbiguity` value in internal snapshot state:
`CandidateLimit`, `DuplicateComposer`, `ComposerAmbiguous`,
`CandidateNotInspected`, or `NoComposer`. Select the reason with a fixed order
independent of `EnumWindows` ordering. Snapshot serde skips the field; schema-v1
reports map it only to one fixed allowlisted evidence code and never emit the
raw candidate count, native identifiers, labels, titles, values, or paths.

The policy treats any such reason as `AmbiguousTarget` even if other public
fields are forged as acceptable, and the request-scoped target HMAC commits to
the reason. This is diagnostic-only fail-closed state. It neither ignores an
unknown candidate nor supplies self-chat, draft, submit-selector, or send
evidence, and it authorizes no live retry or later gate.

## ADR-049: Union fixed blocker classes for uninspected candidates

The next separately approved L10 on `84955a8` returned
`read_only_candidate_not_inspected`. That primary class proves only that one or
more visible exact-class candidates could not enter composer discovery; it does
not distinguish a rejected executable, unsupported profile, concurrent
visibility change, disabled/modal state, session mismatch, or integrity
incompatibility.

When the primary class is `CandidateNotInspected`, carry a private bounded
bitset formed only from booleans the existing inspection already computed.
Across candidates, union the classes without retaining counts or candidate
associations. The report may append only these fixed codes, in fixed order:
`read_only_candidate_executable_unverified`,
`read_only_candidate_ui_profile_unknown`,
`read_only_candidate_not_visible`, `read_only_candidate_disabled`,
`read_only_candidate_modal_present`,
`read_only_candidate_session_mismatch`, and
`read_only_candidate_integrity_incompatible`.

No new native/UIA call, title/name/value read, raw identifier, or per-candidate
record is introduced. Snapshot serde omits the primary reason and its blocker
set; Debug redacts the private bits. The target-binding HMAC commits to every
blocker bit, and the primary ambiguity continues to force policy refusal. This
diagnostic successor authorizes no live retry, UI mutation, or send gate.

## ADR-050: Diagnose an absent composer with exact two-property conditions

The first L10 after candidate-blocker reporting found a modal and stopped. A
separately approved retry after the user closed it established the reviewed
process, version, session, integrity, one exact-class window, and no modal, but
the full `RICHEDIT50W` / `1006` / Edit selector returned no composer. The user
then confirmed that the self-chat message input was visible during that probe.
Repeating the unchanged selector cannot add evidence.

Only after the full selector returns zero elements, query its three exact
two-property combinations: class plus AutomationId, class plus control type,
and AutomationId plus control type. Reduce each result immediately to an
existence boolean. The snapshot retains a private three-bit value with no
element, count, association, or observed property value. Reports emit only a
generic mismatch code plus fixed near-match-without-expected-class-name,
near-match-without-expected-AutomationId,
near-match-without-expected-control-type, or no-two-property-near-match codes.

The diagnostic is omitted from serde, redacted in Debug, committed into target
binding, and independently rejected by policy even if all normal input fields
are forged as acceptable. It does not read Name or Value and does not alter the
mutation selector, target proof, draft proof, or send capability. Mutation
preflight explicitly skips the three diagnostic queries. This authorizes no
live retry or mutation.

## ADR-051: Revise the exact RichEdit selector to Document without fallback

The separately approved successor to ADR-050 ran exactly one guarded read-only
probe against commit `54c1381`. It returned the fixed
`read_only_composer_near_match_without_expected_control_type` code: at least
one descendant matched exact class `RICHEDIT50W` plus AutomationId `1006`,
while the full triple using Edit returned none. The diagnostic retained no
element, count, association, or actual property value. Every external guard
was stable and no retry or UI mutation followed.

Microsoft's published
[UI Automation support table](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-controlsupport)
maps the standard RichEdit control to the Document control type. Replace Edit
with Document in the exact three-property composer selector and bump the
combined selector ID from v1 to v2. Read-only discovery, policy, target
fingerprints, and mutation-time revalidation all require v2. Do not accept v1
or add an Edit/Document OR condition: zero or multiple exact Document matches
remain refusals.

This is an evidence-backed candidate correction, not proof of a unique live
composer, self-chat identity, draft state, or send control. It authorizes no
live retry, stage, commit, or message send.
