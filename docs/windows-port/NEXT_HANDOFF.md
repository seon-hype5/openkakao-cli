# Windows port handoff after Wave 2 / I20

Date: 2026-08-17 KST

> Current successor update: a metadata-only live selector measurement found
> the exact Document composer but no send element or InvokePattern. ADR-053
> therefore binds the default-off `windows-ui-write` build to one synchronous,
> composer-targeted Enter message after all existing trust, target, draft,
> inactivity, modal, mutex, approval, and ledger gates. The default build stays
> read-only. Earlier `send_open_chat=false` and unconfigured-submit statements
> below describe predecessor checkpoints and are superseded for feature builds.

> Latest successor update: the accepted x64 bundle is
> [`KAKAOTALK_X64_TRUST_PROFILE.md`](KAKAOTALK_X64_TRUST_PROFILE.md), the exact
> provider output is `0x80003080`, and the profile-bound native observer is now
> wired while `send_open_chat=false`. Earlier statements below that production
> still uses `UnavailableExecutableTrust` describe predecessor checkpoints.
> The next live step is still a freshly approved L10 session; no earlier
> approval carries forward.
>
> Latest target-boundary update: a `local-send` request can resolve exactly one
> allowlist entry without an argv target, compare one selected root UIA Name in
> scrubbed UTF-16 memory, and inspect only the exact composer's empty/nonempty
> draft bit after a successful binding. Plain `doctor --ui` still reads neither
> property. The candidate has not completed 20 positive observations or the
> required negative matrix; the submit selector is still absent and
> `send_open_chat=false`.
> Earlier target-boundary statements below that production supplies no label,
> reads no Name/Value, or constructs only `Absent` describe predecessor
> checkpoints and are superseded by this update.

## Status

The non-live Windows release candidate is complete through DAG task `I20` on
branch `integration/windows-mvp`. Its reviewed qualification predecessor is
`e2f257d2e3b2d6017f698a47fa9c2694e1d545a0`. The successor containing this
handoff restores Linux/macOS compile parity exposed by the first hosted run and
records that run; its final SHA must be reported externally because a commit
cannot embed its own content-derived SHA.

Completed tasks: `B00`, `B10`, `B20`, `B30`, `C00`, `C10`, `P10`, `P20`,
`P30`, `I10`, `P40`, `P50`, `P60`, and `I20`.

`L10` was subsequently approved and attempted in eight separate read-only
sessions; all failed closed and it is not complete. Not completed or
authorized now: a new `L10` attempt, `L20`, `L30`, `L40`, and final post-live
task `R00`. A green I20 does not carry authority into any live gate.

The requested topology was used: root plus Child A/B/C, with isolated
worktrees and no child subdelegation. Rust builds were kept within the stated
concurrency limit.

## Provenance

- pinned upstream: `be6edd442c803de8e4f06bfc4446d166ac474952`;
- frozen contract: `d974c0597528e079919d4c45ee0893fa61d4335d`;
- Wave 1 integration ancestor:
  `fed2bb1558b4e07878f17f4c8140aab5ead682b2`;
- P50 child source: `f9ca1964942276fa3fb0a4305a5408afb5599e2d`,
  integrated and reconciled beginning at `cd0faf4`;
- P60 child source: `f09fc19bb05e11b0d4659a726e662e414c1e1408`,
  integrated at `b6b4c7b` and hardened at `fb51d1f`;
- P40 child source: `47452d8327d4ce52929de17523a6fc4f971d4293`,
  integrated at `280a35e`;
- root guarded orchestration and contract chain: `ebc9368`, `5550384`,
  `8a89431`, `658b541`, `a61b3d7`, `f60876c`, and `60adc01`;
- final root adversarial reconciliation, CI, tests, and documentation:
  `272c8cb70c716066e22b9d5a6cf8e2d8da3a3d43`;
- request-scoped target binding and exhaustive snapshot invalidation:
  `aaac7beb2681a9258197531063ebd8fcad32e68c`;
- canonical trust-path share-guard audit and remediation:
  `27f50c8d0a272eb0b9af35d99568c431001157b5`;
- repository-owned signed fixture and offline WinTrust lifetime qualification:
  `74dff3ef5c6d957f275f3c21d7af375b0c2f04c5`;
- guarded native installation-root relation derivation:
  `efa4f13d6d94a71aeadcaadb7d6962b0bb17601d`;
- Shell result ownership before HRESULT interpretation:
  `3b06ecc785acde8fb0b01073ee535c142b8eb0b5`;
- approval-owned native target verification through fresh/final preflight:
  `7dfbf0d3b55a9d6b16d690092beac48ebc9993ad`;
- closed native target-observation state:
  `36cc84723f9aa6ba4c8e806b5aef57b405a9e494`;
- approval-owned process-local monotonic lifetime enforcement:
  `e94801fa9f181e95fc44505ba374b80be3e5ace2`;
- same-process owner-group modal evidence with repeated mutation-boundary
  checks: `d4532399d00438eb7489fdb20f06ed95c768c7b3`;
- pinned-worker read-only COM call cancellation with retained single-flight:
  `34227b4b68d1b0ec3e6b13c844ed4de2e9970eb7`; and
- hosted Windows safe-matrix parity and static documentation/pin gate:
  `6bbb4efbe7d280d8b1cdbf0af623c0060880f6aa`; and
- provider-owned subject/revocation/error/catalog validation before signer
  traversal: `6a4012a6c541c3ebd3a2f8fdd4f5aa84f8f7136b`; and
- exact provider-to-signer-to-leaf traversal with nested error refusal:
  `1fc9dc3c32c882fbb33fbd195c264a93f9bd6cbe`; and
- branch-push CI containment, target-byte/strong-sign hardening, public
  installer corroboration, and independent safety review:
  `f7d94c68e875aafcc3722c7199dda2fdf69e1682`; and
- shared SHA-2/NTFS qualification gates and their hosted Windows execution:
  `e2f257d2e3b2d6017f698a47fa9c2694e1d545a0`.

The Child A native unsafe audit and Child B adversarial audit were followed by
a focused re-audit of root's fixes. The re-audit found no correctness blocker
for merging the default-off scaffold.

## L10 read-only attempt: failed closed

The user approved one L10 session and confirmed the self-chat was manually
opened with no recording, screenshot, or output redirection. Root rebuilt the
exact `1c358db` commit with default features, kept every child idle, and ran
one guarded `doctor --ui` plus one synthetic stdin dry-run. The session ended
at approximately `2026-08-16T19:57:34+09:00`.

- `doctor --ui` exited 0 and produced a valid redacted schema-v1 report with
  19 fixed evidence codes, no attempted action, and `not_submitted`.
- The report did not establish a supported UI profile.
- Independent before/after guards could not establish an exact unique
  KakaoTalk top-level window or composer, so composer length remained
  unobserved. L10 therefore did not pass.
- The synthetic dry-run was refused before UI inspection with fixed
  `invalid_input` / `policy_allowlist_config`, exit 2. Neither the synthetic
  target nor canary was echoed.
- Foreground, focus, Z-order neighbors, clipboard sequence, visibility, and
  enabled-state observations were unchanged across the session.
- Raw doctor/dry-run output, HWNDs, PIDs, labels, draft material, and
  fingerprints were not emitted or persisted.

No retry, weaker selector, alternate live probe, stage, or commit followed the
failure. The troubleshooting runbook permits only offline source/synthetic
work now. L20 is blocked.

### Later L10 retry at the accepted x64 profile

After the x64 executable-trust profile and its hosted qualification were
accepted, the user granted a fresh one-session L10 approval and manually kept
the intended self-chat open. Root ran exactly one release-build
`doctor --ui --json` against `4084687`. It exited 0 with the fixed redacted
schema, `ui_profile=null`, `attempted=false`, and `not_submitted`; the evidence
included the fixed `top_level_window_ambiguous` and
`composer_fingerprint_not_observed` codes. No title, room/profile label,
composer value, HWND, PID, or private content was emitted.

Selector ambiguity is an L10 abort condition, so no dry-run, retry, weaker
matching, focus, input, clipboard operation, stage, or commit followed in that
session. This second failure supplied no authority for another live attempt.

### Third L10 after visibility-only narrowing

After `caed3f2` and both hosted workflows passed, the user granted one fresh
L10-only approval and kept the intended self-chat open with recording and
screenshots disabled. Root reverified the clean exact commit and ran exactly
one default-feature release `doctor --ui --json` from the reviewed artifact
(SHA-256
`0ca240a1d120a6647ed82202e8043cd808c6a1343f17713875bbb35a5f2f746a`).
It exited 0 with schema v1, `ui_profile=null`, `attempted=false`,
`not_submitted`, and the fixed `top_level_window_ambiguous` evidence. The
predecessor schema did not retain which conservative ambiguity class applied.

An in-memory read-only guard reported stable foreground, focus, Z-order
neighbors, and clipboard sequence; focus observation was available. No raw
handle/value, title, label, composer value, screenshot, or trace was printed or
persisted. No dry-run, retry, input, stage, commit, or send followed. This third
failure supplied no authority for another live attempt.

### Fourth L10 with primary ambiguity reason

After the ambiguity-reason successor `84955a8` passed Windows run
`31998321030` and Linux/macOS run `31998321066`, the user granted another
fresh L10-only approval under the same manually prepared self-chat and
no-capture conditions. Root reverified the clean local/fork head and exact
default-feature release binary (SHA-256
`80d4a7e2dae7927119d68b49ef5ecc810f6f9c617e5c27ec941503b267841b6f`),
then ran one `doctor --ui --json`.

The command exited 0 with schema v1, `ui_profile=null`, `attempted=false`,
`not_submitted`, the primary `top_level_window_ambiguous`, and
`read_only_candidate_not_inspected`. This establishes only that at least one
visible exact-class candidate could not enter composer inspection; the
predecessor did not retain its fixed blocker class. Foreground, focus, Z-order
neighbors, and clipboard sequence were all stable, and focus observation was
available. No label/title/value, handle, PID, raw count, screenshot, trace,
input, stage, commit, or send occurred. The session ended without a retry and
supplied no authority for another live attempt.

### Fifth L10 with candidate blocker details

The candidate-blocker successor and Unix lint follow-up `b7df418` passed
Windows run `32000123935` and Linux/macOS run `32000123938`. Under a fresh
L10-only approval, root reverified the clean local/fork head and exact
default-feature release binary (14,288,384 bytes; SHA-256
`749ee4aa3821e84b35bab858f7e3d32a39ff3e8a5f4e33950e58e70d95367721`),
then ran one guarded `doctor --ui --json`.

The report remained `attempted=false` / `not_submitted` and identified
`read_only_candidate_modal_present`. Foreground, focus, Z-order neighbors, and
clipboard sequence were stable. No title, label, Value, raw identifier, input,
stage, commit, or send occurred. The session ended without a retry.

### Sixth L10 after the user closed the modal

After the user closed the visible modal and granted a new one-session
approval, root reverified the same binary and ran one guarded
`doctor --ui --json`. This time the report established the app and process,
interactive session, compatible integrity, reviewed `26.7.0.5255` profile,
one exact-class top-level window, and no modal. The exact reviewed composer
selector nevertheless returned absent. The report retained only fixed
`composer_fingerprint_not_observed` / `composer_absent` state; it read no Name
or Value. The user then confirmed that the self-chat message input was visible
during this probe, so repeating the unchanged selector cannot add evidence.

All before/after guards were stable and focus observation was available. No
input, stage, commit, send, content read, screenshot, trace, or retry followed.
This sixth failure supplied no authority for another live attempt.

### Seventh L10 with fixed composer near-match evidence

The composer-diagnostic successor `54c1381` passed Windows run `32004418562`
and Linux/macOS run `32004418502`. Under a fresh one-session L10 approval,
root reverified the clean local/fork head and exact default-feature release
binary (14,246,912 bytes; SHA-256
`7dccedb15773df107e1c36aa9200e76c9bf2d54d3e2445bf284df79b42ab8dd2`),
then ran one guarded `doctor --ui --json`.

The report remained `attempted=false` / `not_submitted` and established the
reviewed process/profile, one exact-class top-level window, and no modal. It
emitted `read_only_composer_selector_mismatch` plus only
`read_only_composer_near_match_without_expected_control_type`. This proves
only that at least one descendant matched exact `RICHEDIT50W` plus AutomationId
`1006`, while the full Edit triple matched none. It retained no element,
count, association, actual control type, Name, or Value.

Foreground, focus, Z-order neighbors, and clipboard sequence were stable;
focus observation was available. No input, stage, commit, send, content read,
screenshot, trace, or retry followed. This seventh result supplied no authority
for another live attempt.

## Offline remediation after the failed L10

The failed sessions retained only fixed booleans, so they did not preserve a
raw window count and do not prove a root cause. Offline source review identified
conservative failure classes. The read-only backend originally returned
ambiguous as soon as more than one exact `EVA_Window_Dblclk` window existed,
before determining whether only one contained the exact known-profile
composer.

The successor to this handoff adds bounded diagnostic narrowing. A probe now
inspects at most eight exact-class candidates and selects one only if exactly
one candidate has exactly one `RICHEDIT50W` / `1006` / Edit composer and every
other candidate has none. Duplicate composers, an internally ambiguous
composer, too many windows, or any native/UIA inspection error still fail
closed. Synthetic tests cover the unique, duplicate, internally ambiguous,
unsupported, and absent-composer shapes.

A later audit found one remaining contradiction in that read-only path:
`EnumWindows` can return invisible exact-class helper or parking windows, while
an invisible window can never satisfy the existing visible-target gate. Such a
window was nevertheless counted toward the eight-candidate ceiling or mapped
to `NotInspected`, which forces ambiguity. The next offline successor therefore
excludes invisible windows only when constructing the read-only candidate set.
The mutation path retains a separate raw exact-class enumeration and still
requires exactly one raw top-level window. A pure four-case test freezes both
scopes. This is a conservative source diagnosis, not proof that an invisible
window caused either observed failure.

The third failed session showed that visibility-only narrowing was not enough,
while the predecessor's fixed output could not identify the remaining
fail-closed class. The next offline successor therefore carries one internal,
content-free ambiguity reason and maps it to one allowlisted report code:
candidate limit, duplicate composer, internally ambiguous composer, candidate
not inspected, or no composer. The reason is omitted from snapshot serde,
included in request-scoped target binding, and independently forces a policy
refusal. Candidate order cannot change the chosen reason. No raw count or
native/private value is emitted.

The fourth result narrowed the primary reason but still combined all
uninspected-candidate causes. The next offline successor therefore unions only
already-computed candidate blocker booleans and emits fixed supplemental codes
for executable trust, UI profile, visibility, enabled/modal state, session,
and integrity. It keeps no count or candidate association, performs no new
native/UIA call, redacts the private bitset in Debug and serde, binds every bit
into target evidence, and leaves the same `AmbiguousTarget` policy refusal.

The fifth result identified an environmental modal; the user closed it without
a code change. The sixth result then established one otherwise eligible
known-profile window but no full composer match, while the user independently
confirmed the input was visible. The next offline successor therefore runs
only after a zero-result full selector and checks its three exact two-property
subsets. Each returned array is reduced immediately to one existence boolean.
Only fixed near-match-without-expected-class-name, AutomationId, or
control-type codes, or a no-two-property-near-match code, can be emitted. The
private three-bit value is serde-skipped, Debug-redacted, target-bound, and an
independent policy refusal;
no actual property value, element, count, or association is retained.

The seventh result isolated the changed property without reading its value.
Microsoft's official standard-control table maps RichEdit to UI Automation
Document, so the next offline successor changes the exact triple to
`RICHEDIT50W` / `1006` / Document and bumps the combined selector profile from
v1 to v2. Read-only discovery, policy, target fingerprints, and mutation-time
revalidation require the same v2. There is no Edit fallback or OR condition;
zero or multiple exact Document matches still fail closed.

This is not a self-chat selector and does not authorize a live retry. All
target-identity booleans remain false, `send_open_chat` remains false, and the
mutation path still requires raw enumeration to return exactly one top-level
window. No live KakaoTalk/UIA call was made while implementing or testing this
remediation.

### Eighth L10 with the v2 Document composer

After `988fc0f` and both hosted workflows passed, the user granted a fresh
one-session L10 approval and kept the intended self-chat open. Root reverified
the exact default-feature release binary (14,246,912 bytes; SHA-256
`5979d551b9fd1da3fff9aff069e12dbfa2805463aae5e41d77ef6d6877e557b0`) and ran
one guarded `doctor --ui --json`.

The report established the accepted process/profile, one narrowed top-level
window, no modal, and one exact v2 Document composer with enabled/writable
metadata. The composer was focused, while target identity and draft state
remained unverified; plain doctor read no Name or Value. Foreground, focus,
Z-order-neighbor, and clipboard-sequence guards were stable. No input, stage,
commit, send, screenshot, trace, or retry followed. This eighth result supplied
no authority for the later private target-boundary read.

The latest offline successor also closes the policy contract gap between a
configured requested label and independently observed target evidence. Every
policy inspection now uses a fresh opaque HMAC request; exact UTF-16 evidence
is bound to the complete redacted snapshot, never serialized, and retained as
a private approval permit. Fresh transaction state has a fourth independent
`target_binding_verified` gate. A later privacy-approved successor connects the
bounded root-Name candidate described in the top update, but its required live
matrix is still incomplete and production remains fail-closed. Neither version
is target-profile qualification or write permission.
An exhaustive synthetic mutation test now changes every current app, process,
target, time, and input snapshot field independently and proves that each
invalidates the request-scoped permit.

A focused native trust/API audit then found an ABA gap around the path-only
version API: permissively shared handles plus before/after file identities did
not exclude replace/read/restore. The disconnected adapter now retains the
canonical verification file and all canonical parent directories with read
sharing only through WinTrust CLOSE and final reopen. Conflicting existing
writers/deleters fail closed, and later writes, deletes, and renames cannot
enter while the guards live. This path still has no production reference or
root digest. [`TRUST_PROVENANCE.md`](TRUST_PROVENANCE.md) freezes the synthetic
fixture and production evidence plan without adding a fixture or Kakao value.

The current successor implements that synthetic fixture plan. It commits an
inert self-signed PE, public certificate, source, license, hash/toolchain
manifest, and regeneration script that removes the temporary PFX and retains
no private key.
One test validates the manifest, bounded PE signature structure, certificate,
and SPKI entirely from committed bytes. A second opens only that fixture and
performs an actual cache-only/noninteractive WinTrust VERIFY/CLOSE cycle
without executing it or requiring trust success. The real call exposed that
WinTrust adds documented output bits to the signature-settings flag field; the
native invariant now preserves exact input bits, permits only those output
bits, and rejects every unknown bit. No production value or reference was
added.

The root-derivation successor completes generic runtime installation-root
derivation without adding a Kakao value or caller. A reviewed profile exposes
only one root kind; the disconnected adapter maps it to the exact Windows
known-folder ID, owns/frees the Shell allocation, retains no-follow
read-share-only canonical root/ancestor handles through VERIFY/CLOSE and final
revalidation, and hashes only a bounded strict-descendant relative relation.
Expected components never enter the observer, observed paths/components cannot
construct the reviewed type, and all production references remain absent.

The newest offline successor makes the Shell allocation lifetime directly
testable without changing that production flow. A single private decoder takes
ownership before HRESULT interpretation. Synthetic `CoTaskMemAlloc` buffers
and a counting matching release prove one free on success, `E_FAIL`, and later
path refusal, and zero frees for NULL. No test calls `SHGetKnownFolderPath`.

The latest successor closes a native target-permit plumbing gap. The mutation
port now borrows the same `ApprovedSend` throughout fresh observation and
final preflight, and an ephemeral observed UTF-16 label can be checked only
against that approval's own private policy-bound snapshot. Native callers can
no longer substitute a snapshot, and neither the port nor target evidence
retains the label. Synthetic absent, exact, mismatch, inexact, and non-unique
cases cover the seam. Production still supplies no label or selector evidence
and performs no new UI read.

The newest successor removes contradictory native target observations from the
type surface. Instead of accepting an optional label with independent exact
and unique booleans, the helper now accepts one closed absent, inexact,
ambiguous, or exact-unique state. Only exact-unique can carry a borrowed label
or invoke the approval-owned verifier; all flags are derived from the state.
Synthetic tests cover every state and a mismatched exact-unique label, while
production constructs only absent and still performs no label read.

The latest offline successor closes the recorded wall-clock rollback lifetime
risk. Policy pairs its approved wall-clock reading with a process-local
`Instant`, seals only the remaining lifetime inside `ApprovedSend`, and refuses
at the half-open monotonic boundary before sender dispatch. The Windows path
rechecks both clocks before worker/native entry, correlation consumption,
every observation, final revalidation, and each actual Value/Invoke call.
Synthetic future instants and a pure two-clock truth table prove rollback
cannot extend approval lifetime without sleeping or changing system time.

The current offline successor expands conventional modal evidence beyond the
selected window's enabled style. After exact executable-name verification, a
disabled selected window or a visible same-process owned top-level popup in
its root-owner group is blocking; hidden, foreign-process, unowned, and
different-group windows are not. The metadata-only callback retains no
candidate list or text, uncertainty fails closed, and any positive result
suppresses composer identity/input-availability evidence. Fresh observation,
final preflight, and each actual Value/Invoke boundary repeat the scan. Pure
classification and mapping tests call no desktop API. Generic owner chains
still cannot identify an unowned custom dialog or an in-window overlay, so
future negative live measurement remains required.

The current offline successor also contains timed-out read-only COM calls.
The fresh MTA worker enables call cancellation and publishes its OS thread ID
before inspection. Startup and inspection share one eight-second budget; on
readiness the caller grants one inspection permit and the worker rechecks the
budget before native entry. Expiry after readiness pins that worker through
exactly one zero-wait `CoCancelCall` request and still returns the same
non-retryable timeout. Normal completion disables cancellation and joins. A
caught post-readiness unwind follows the same pinned lifetime, preventing
thread-ID reuse from targeting an unrelated COM call.

This request is not proof that provider work stopped. Standard marshaling may
unblock the client, while custom marshaling may expose no cancel object and a
server may continue. The worker therefore retains the process-wide
single-flight lease until its native call actually returns. Cancellation is
restricted to bounded read-only inspection; mutation workers remain synchronous,
joined, and cancellation-disabled. Pure tests call no native COM or desktop
API, and no live provider compatibility was measured.

The qualification predecessor makes hosted Windows CI reproduce the complete
local safe release matrix. It adds the five synthetic compatibility targets,
default and all-feature release builds, and optimized all-feature Windows unit
tests. An inline PowerShell gate validates every Windows-port local Markdown
link, rejects out-of-repository targets and mutable action references, and
rechecks the exact Rust toolchain pin. Every Windows-port documentation change
now triggers the workflow. The exact-name CLI allowlist, read-only permissions,
no-artifact policy, and ban on product invocation remain unchanged. The first
[hosted Windows run](https://github.com/seon-hype5/openkakao-cli/actions/runs/31985013629)
passed every gate, including the OS and Rust native-assumption tests. Its paired
[cross-platform run](https://github.com/seon-hype5/openkakao-cli/actions/runs/31985013674)
passed the Linux synthetic suite and exposed one Linux all-feature dead-code
scope error plus one macOS `CFArray` indexing error. The current successor fixes
those compile-only defects without changing a live boundary.

The newest offline successor closes a provider-state evidence gap before
signer traversal. A zero WinTrust result must now retain the exact provider
back-pointers, `CPD_CHOICE_SIP`, the caller low-word offline flags plus the
CPD chain-excluding-root mode, and zero provider errors. Catalog recall comes
from provider-owned `fRecallWithState`, rather than the caller's immutable FILE
union, and is refused before certificate extraction. An inert-structure test
mutates every field without calling WinTrust or opening a file. The adapter
remains disconnected and no production value was added.

The current offline successor makes the complete successful
provider-to-primary-signer-to-leaf SPKI traversal independently executable
without WinTrust. Three pointer-returning WTHelper operations are behind a
private trait and one unsafe extraction lifetime contract; production still
calls the same helpers, while the test implementation retains exact Rust-owned
structures. Signer and leaf `dwError` must now both be zero, and substituted
helper pointers refuse before dereference. The committed public fixture DER
supplies only the certificate context/SPKI bytes. No file, process, window,
product, or live adapter call occurs.

## Delivered release-candidate behavior

- Windows process/window/version/session/integrity/process-creation and exact
  composer metadata discovery runs on a dedicated windowless MTA thread.
- Read-only discovery examines at most eight exact-class windows and narrows to
  one only under the exact unique-composer rule; writes retain stricter raw
  top-level uniqueness.
- Read-only UIA work is process-wide single-flight. Startup and inspection
  share one eight-second budget. Expiry after cancellation readiness pins the
  worker through one zero-wait COM cancellation request and returns a
  non-retryable timeout. Unsupported or still-running providers keep the lease
  until they return, so further probes create no worker.
- Windows CI statically validates documentation links, action/toolchain pins,
  and runs the synthetic compatibility targets plus default/all-feature debug
  and release builds and optimized Windows tests without invoking an artifact.
- Plain doctor inspection is metadata-only and redacted. A target-bound probe
  may compare only the selected root Name and, after exact binding, reduce the
  exact composer Value to an empty/nonempty bit. It binds the Name again after
  the Value read and discards the bit on mismatch; no raw private value leaves
  the worker.
- Modal evidence covers a disabled selected window plus visible same-process
  owned popups in its root-owner group. Positive evidence prevents composer
  traversal and is rechecked at final and actual mutation boundaries.
- Windows CLI provides `doctor --ui` and stdin-only/opened-only `local-send`,
  with no Windows target/message positional and generic parse failures that
  cannot echo rejected private input.
- Input stops at 4,001 raw bytes, accepts at most 4,000 valid UTF-8 bytes and
  1,000 Unicode scalars, rejects dangerous controls/whitespace forms, and
  zeroizes secret buffers.
- The exact allowlist is checked before stdin. Windows has its own default-off
  `safety.allow_windows_ui_write` flag; macOS `allow_ax_send` cannot authorize
  it.
- Dry-run is inspection-only by type and reuses one policy snapshot.
- Policy dry-run/authorization require request-scoped, nonserializing exact
  observed-target evidence; stale, replayed, normalized, or state-moved proof
  refuses.
- The native mutation port carries that same approval through fresh and final
  target checks; its label verifier is fixed to the approval-owned snapshot and
  stores no observed label.
- Native target selection is a closed state; only exact-unique may invoke the
  label verifier, so absent/inexact/ambiguous states cannot fabricate a
  contradictory target-evidence tuple.
- Write execution uses a consumed approval lease, a sealed sender, an atomic
  one-shot claim, exact mode/outcome compatibility, and no retry edge.
- Every approval has a private process-local monotonic deadline in addition to
  wall-clock expiry. Either half-open boundary refuses, and deadline checks
  precede sender dispatch, native observation, final preflight, and the actual
  Value/Invoke boundary.
- `windows-ui-write` is a real default-off compile boundary. All-feature builds
  compile the native Value/Invoke path without granting authority.
- The guarded transaction binds PID/HWND/path/process creation/session/UIA
  evidence, half-open TTL, a named cross-process mutex, final native preflight,
  exact stage readback, owned-value-only restore, and at most one Invoke.
- The disconnected executable-trust adapter retains read-share-only canonical
  file and parent guards across its path-only version query, VERIFY/CLOSE, and
  final identity reopen; write/delete/rename conflicts refuse.
- The repository-owned Authenticode fixture binds its build/source/artifact/
  certificate/SPKI hashes, is never executed, and exercises one exact offline
  WinTrust state lifetime without changing a trust store or requiring success.
- Successful provider traversal additionally requires exact SIP subject,
  effective offline/revocation flags, zero provider errors, and no catalog
  recall before the first signer pointer is consumed.
- Primary signer and selected leaf provider-certificate errors must also be
  zero, and both helper returns must equal their parent structure's exact array
  pointer. An inert helper implementation proves the full successful SPKI path
  plus both nested-error and pointer-substitution refusals.
- Generic native root derivation binds the source-static root kind to an exact
  known-folder ID and same-volume handle-derived relative digest while keeping
  all absolute/component text out of evidence and reviewed profile types.
- Synthetic Shell result tests prove every non-null known-folder output is
  owned before HRESULT interpretation and released once on every exit path.
- Same-process foreground popups count as user activity. Mutex contention,
  abandonment, wait failure, and every error/panic after SetValue entry are
  `SubmissionUncertain`, exit 21, and never retry-safe.
- Secret UTF-16 is written directly into a presized zeroizing allocation;
  outbound and CurrentValue BSTR allocations are scrubbed before release.
- Reports remain schema v1 and allowlist action/profile/evidence/operation
  codes. Unknown strings are redacted in human and JSON streams.

## Intentional production refusal

The transaction code exists for review and synthetic verification, but a live
write is not reachable:

1. `windows-ui-write` defaults off;
2. `allow_windows_ui_write` defaults false;
3. `WindowsBackend::capabilities()` reports `send_open_chat=false` even in an
   all-feature build;
4. native target evidence is available only through an unqualified,
   target-bound candidate and cannot satisfy the production activation gate;
   and
5. the commit selector is `Unconfigured` and no InvokePattern is acquired.

Thus production stage/commit refuse before stdin or UI inspection in root
dispatch, and normal policy authorization using `WindowsBackend` cannot mint
an operation. Even a synthetic cross-backend approval is stopped by the
Windows sender's independently fresh target and selector evidence. These gates
must not be weakened merely to make a live test possible.

## Final non-live verification

The Rust and static-documentation rows below were rerun locally for the
target-boundary successor. Local native-assumption qualification remained
blocked by execution policy, while the successor's hosted Windows run reran it
successfully. No execution-policy bypass or trust-store change was made.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo test --locked --lib` | 208 passed; 1 bounded qualification child ignored |
| `cargo test --locked --lib --all-features platform::windows` | 121 passed; 1 bounded qualification child ignored |
| `cargo test --locked --bin openkakao-cli` | 179 passed |
| `cargo test --locked --test windows_backend` | 2 passed |
| `cargo test --locked --test windows_policy` | 24 passed |
| `cargo test --locked --test windows_cli` | 1 passed |
| `cargo test --locked --all-features --test windows_backend` | 2 passed |
| closed exact `cli_test` allowlist | 14 passed; 3 live/local-state cases excluded |
| `auth_flow_test` | 23 passed |
| `loco_client_test` | 13 passed |
| `loco_crypto_test` | 12 passed |
| `loco_packet_test` | 13 passed |
| `message_db_test` | 20 passed |
| disconnected executable-trust module | 36 passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | passed |
| debug build, default and all features | passed |
| release build, default and all features | passed |
| release all-feature Windows synthetic tests | 121 passed; 1 bounded qualification child ignored |
| fixture structure/SPKI and offline WinTrust lifetime | 2 passed; PE never executed |
| Windows-port Markdown local links and pinned-action policy | 52 files, 70 local links, 0 broken; 13 action refs pinned |
| `actionlint` 1.7.12 on all three non-release safe/qualification workflows | passed |
| final `git diff --check` | passed |
| successor `cargo test --locked --lib --no-run` | passed; test executable compiled only |
| successor `cargo clippy --locked --all-targets --all-features -- -D warnings` | passed |
| successor PowerShell parser and `actionlint` 1.7.12 | passed |
| successor native-assumption OS qualification | Windows `10.0.26200.0`/NTFS: strong hash and before/between/after timings passed |
| qualification Rust trust-test execution | local entry blocked by Smart App Control error 4551; hosted Windows run passed |
| hosted Windows safe CI at `caed3f2` | run `31996648242` passed every step, including qualification, lint, synthetic tests, debug/release builds, and optimized all-feature tests |
| hosted cross-platform CI at `caed3f2` | run `31996648201` passed Linux and macOS jobs |
| hosted Windows safe CI at `b7df418` | run `32000123935` passed every step |
| hosted cross-platform CI at `b7df418` | run `32000123938` passed Linux and macOS jobs |
| hosted Windows safe CI at `54c1381` | run `32004418562` passed every step |
| hosted cross-platform CI at `54c1381` | run `32004418502` passed Linux and macOS jobs |
| hosted Windows safe CI at `988fc0f` | run `32006211269` passed every step |
| hosted cross-platform CI at `988fc0f` | run `32006211297` passed Linux and macOS jobs |
| hosted Windows safe CI at `5b0591a` | run `32013457539` passed every step, including native qualification and optimized all-feature tests |
| hosted cross-platform CI at `5b0591a` | run `32013457513` passed Linux lint/tests and the macOS release build |

The initial successor push `2e298ee` passed its synthetic and macOS jobs but
exposed one Linux-only `dead_code` lint on the Windows worker-clone helper.
`5b0591a` scopes that helper to Windows; no Windows behavior changed.

The workflow syntax check used the official actionlint 1.7.12 Windows-amd64
archive under ignored `.target`. Its SHA-256
`6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9`
matched the release checksum manifest; the tool itself is not committed.

The excluded `cli_test` cases are
`doctor_json_outputs_valid_json`, `auth_status_json_outputs_valid_json`, and
`cache_stats_json_outputs_valid_json`; their legacy paths may load local-state
or credential diagnostics. No broad test command or product invocation was
substituted for them.

Windows CI pins all three third-party actions by full reviewed commit SHA,
uses read-only repository permissions, disables checkout credential
persistence, uploads no artifact, and runs default plus explicitly scoped
all-feature synthetic coverage in debug and release profiles. Its committed
inline documentation/action/toolchain validator and every newly added command
passed locally and in hosted run `32004418562`.

## Safety ledger for this implementation session

- live KakaoTalk/UIA doctor probes: 7;
- documented live before/after read-only guard snapshots: 12;
- KakaoTalk UI mutations: 0;
- production backend stage calls: 0;
- production backend commit/Invoke calls: 0;
- actual messages sent: 0;
- committed Authenticode fixture executable launches: 0;
- OS-supplied System32 loopback helper launches: 3, all stopped and waited;
- copied Rust unit-test harness launch attempts: 1, successful entries: 0
  (Smart App Control error 4551);
- qualification-helper network destinations: loopback only; no external
  destination was supplied;
- App Control, execution-policy, or trust-store changes: 0;
- executable-trust known-folder resolutions: 0;
- installed KakaoTalk files/databases read: 0;
- public official installer downloads: 2, both hash-only/static inspection;
- installer or target executable launches: 0;
- credential/token content reads: 0; browser/device authentication stored the
  credential through the platform credential manager;
- native COM cancellation calls during implementation/tests: 0;
- screenshots/UI dumps/process-memory reads/injection/hooks: 0;
- automatic retries: 0;
- GitHub forks created: 1 (`seon-hype5/openkakao-cli`);
- push attempts: 5 (unauthenticated HTTPS, strict-host-key SSH, authenticated
  upstream HTTPS rejected with 403, and two authenticated fork HTTPS pushes);
- successful pushes: 2 (fork branch `integration/windows-mvp`); and
- pull requests/releases: 0.

All mutation counts in automated tests belong to fake or in-memory synthetic
ports, never KakaoTalk or another desktop application.

## Remaining activation blockers and risks

[`ACTIVATION_RFC.md`](ACTIVATION_RFC.md) now defines proposed evidence,
privacy, durability, crash-recovery, executable-trust, and activation-order
contracts. It contains no selector values and authorizes no live work.
[`NATIVE_ACTIVATION_BOUNDARIES.md`](NATIVE_ACTIVATION_BOUNDARIES.md) freezes
the reviewed `windows` 0.62.2 feature/API/ownership inventory for offline
implementation; it likewise authorizes no probe or production wiring.

- The request/proof and fresh transaction gates for privacy-safe target
  binding are implemented synthetically, and the native port now keeps the
  approval-owned permit through fresh observation and final preflight. A
  closed state ensures only exact-unique selection can invoke that permit. The
  separately approved ephemeral UTF-16 observer is implemented and brackets
  each draft read with root-Name comparisons, but it still requires 20 positive
  and the complete direct/group/open/main/popup/duplicate/same-name-collision
  negative observations. No room/profile text may be exposed or retained.
- Measure and review an exact unique send-button selector and InvokePattern;
  no keyboard fallback is permitted.
- Review and complete the proposed privacy-safe durable replay ledger. Its
  fixed codec/controller/ordering/correlation and an explicit-temporary-base
  Windows DPAPI/protected-ACL/write-through store are synthetically tested.
  The LocalAppData/fixed-volume/parent-chain constructor is now connected to
  the native port through a lazy, side-effect-free factory. Executable trust is
  checked before the first ledger method. Normal production dispatch remains
  unreachable because `send_open_chat=false`; no real LocalAppData path has
  been resolved or written in this target-boundary work.
- Maintain architecture-specific target/signature/root evidence. The accepted
  x64 bundle requires the source-static complete target SHA-256, exact version,
  leaf SPKI, ProgramFiles64 relation, candidate identities, NTFS, SHA-2-only
  WinTrust policy, and exact `0x80003080` provider result. The wired native
  adapter hashes the guarded file, retains `CERT_STRONG_SIGN_PARA` through
  VERIFY/CLOSE, re-queries the process image path while the first candidate is
  locked, and rejects canonical/file-ID disagreement. x86, relocated, altered,
  and unknown-provider shapes fail closed.

  The public 26.7 x86/x64 installer hashes remain corroboration, while only the
  independently extracted x64 installed target has an accepted bundle. Windows
  `10.0.26200.0`/NTFS and the pinned hosted Windows image passed the strong-hash
  and before/between/after-query matrix. Activation still requires maintaining
  the declared OS/filesystem qualification matrix and isolated weak-signed
  refusal coverage for future profile changes.
- Generic Win32 owner-chain modal evidence cannot identify an unowned custom
  dialog or an overlay drawn inside the selected window. Future activation
  needs negative live measurements and a reviewed version-specific rule if
  either shape exists.
- A third-party UIA provider can hang. The read-only path now makes one pinned,
  zero-wait COM cancellation request, but custom marshaling may not expose a
  cancel object and provider-side work may continue. Single-flight still
  prevents worker accumulation, while one unsupported hung worker can block
  later probes until it returns or the process exits. Native cancellation
  compatibility and performance have not been measured against a live UIA
  provider.
- Live read-only observation proves that the v1 Edit triple is incompatible
  with the visible input. The v2 Document triple was then observed as one exact
  enabled writable composer in the selected window. The newly bracketed target
  Name binding and empty-draft proof have not been live-qualified; stage
  restoration and submission remain unmeasured.

## Next permissible step

The target-boundary successor `5b0591a` passes the fully executed hosted Windows
safe matrix in run `32013457539` and the paired Linux/macOS workflow in run
`32013457513`. GitHub authentication is stored through the platform credential
manager, the fork exists, and that commit is pushed on
`integration/windows-mvp`. No live KakaoTalk observation, UI mutation, or
submission was performed while producing this evidence.

After hosted CI, the next activation work is a newly approved, target-bound L10
against the exact successor default-feature release binary. It may collect one
redacted positive or negative observation for the bracketed Name/draft
candidate, but it may not stage, commit, or submit. Existing composer-only
results do not authorize that new private read boundary.

A future retry of DAG node L10, documented in
[`manuals/read-only-doctor-dry-run.md`](manuals/read-only-doctor-dry-run.md),
is a new live read-only KakaoTalk/UIA session and is **not authorized by this
handoff**. It requires environment/selector remediation followed by fresh user
approval naming L10, and must preserve focus, composer, clipboard, and all
user data.

L20 through L40 remain blocked both by sequence and by missing production
selectors. L20 modifies the composer, L30 reserves submission for the user,
and L40 requires a separate immediate approval for exactly one automatic
self-chat commit. `R00` cannot complete until those gates do; do not mark it
complete based on I20.
