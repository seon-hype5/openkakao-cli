# Windows port handoff after Wave 2 / I20

Date: 2026-08-17 KST

## Status

The non-live Windows release candidate is complete through DAG task `I20` on
branch `integration/windows-mvp`. The reviewed implementation tip is
`6a4012a6c541c3ebd3a2f8fdd4f5aa84f8f7136b`. The commit containing this
handoff is its clean successor and must be reported externally because a
commit cannot embed its own content-derived SHA.

Completed tasks: `B00`, `B10`, `B20`, `B30`, `C00`, `C10`, `P10`, `P20`,
`P30`, `I10`, `P40`, `P50`, `P60`, and `I20`.

`L10` was subsequently approved for one read-only session and attempted once;
it failed closed and is not complete. Not completed or authorized now: a new
`L10` attempt, `L20`, `L30`, `L40`, and final post-live task `R00`. A green I20
does not carry authority into any live gate.

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
  traversal: `6a4012a6c541c3ebd3a2f8fdd4f5aa84f8f7136b`.

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

## Offline remediation after the failed L10

The failed session retained only fixed booleans, so it did not preserve a raw
window count and does not prove a root cause. Offline source review identified
a conservative failure class: the read-only backend previously returned
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

This is not a self-chat selector and does not authorize a live retry. All
target-identity booleans remain false, `send_open_chat` remains false, and the
mutation path still requires raw enumeration to return exactly one top-level
window. No live KakaoTalk/UIA call was made while implementing or testing this
remediation.

The latest offline successor also closes the policy contract gap between a
configured requested label and independently observed target evidence. Every
policy inspection now uses a fresh opaque HMAC request; exact UTF-16 evidence
is bound to the complete redacted snapshot, never serialized, and retained as
a private approval permit. Fresh transaction state has a fourth independent
`target_binding_verified` gate. Production has no label observer, emits no
proof, and remains fail-closed. This is synthetic scaffolding, not target
profile measurement or live permission.
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
restricted to metadata-only inspection; mutation workers remain synchronous,
joined, and cancellation-disabled. Pure tests call no native COM or desktop
API, and no live provider compatibility was measured.

The current successor makes hosted Windows CI reproduce the complete local
safe release matrix. It adds the five synthetic compatibility targets,
default and all-feature release builds, and optimized all-feature Windows unit
tests. An inline PowerShell gate validates every Windows-port local Markdown
link, rejects out-of-repository targets and mutable action references, and
rechecks the exact Rust toolchain pin. Every Windows-port documentation change
now triggers the workflow. The exact-name CLI allowlist, read-only permissions,
no-artifact policy, and ban on product invocation remain unchanged. The
commands pass locally; the first GitHub-hosted run remains external evidence.

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
- Inspection is metadata-only and redacted. It does not read titles, UIA
  Name/Value, room/profile names, draft text, KakaoTalk data, or credentials.
- Modal evidence covers a disabled selected window plus visible same-process
  owned popups in its root-owner group. Positive evidence prevents composer
  traversal and is rechecked at final and actual mutation boundaries.
- Windows CLI provides `doctor --ui` and stdin-only/opened-only `local-send`,
  with generic parse failures that cannot echo a rejected positional message.
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
4. native `self_chat_verified`, target-binding, exact-target, and unique-target
   evidence are always false; and
5. the commit selector is `Unconfigured` and no InvokePattern is acquired.

Thus production stage/commit refuse before stdin or UI inspection in root
dispatch, and normal policy authorization using `WindowsBackend` cannot mint
an operation. Even a synthetic cross-backend approval is stopped by the
Windows sender's independently fresh target and selector evidence. These gates
must not be weakened merely to make a live test possible.

## Final non-live verification

All recorded final-matrix Rust commands used the ignored
`C:\Users\ihvna\source\openkakao-dev\repo\.target\wave2-root` directory.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo test --locked --lib` | 189 passed |
| `cargo test --locked --lib --all-features platform::windows` | 113 passed |
| `cargo test --locked --bin openkakao-cli` | 177 passed |
| `cargo test --locked --test windows_backend` | 2 passed |
| `cargo test --locked --test windows_policy` | 24 passed |
| `cargo test --locked --test windows_cli` | 2 passed |
| `cargo test --locked --all-features --test windows_backend` | 2 passed |
| closed exact `cli_test` allowlist | 14 passed; 3 live/local-state cases excluded |
| `auth_flow_test` | 23 passed |
| `loco_client_test` | 13 passed |
| `loco_crypto_test` | 12 passed |
| `loco_packet_test` | 13 passed |
| `message_db_test` | 20 passed |
| disconnected native executable-trust module | 26 passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | passed |
| debug build, default and all features | passed |
| release build, default and all features | passed |
| release all-feature Windows synthetic tests | 113 passed |
| fixture structure/SPKI and offline WinTrust lifetime | 2 passed; PE never executed |
| Windows-port Markdown local links and pinned-action policy | 48 files, 56 local links, 0 broken; 3 action refs pinned |
| final `git diff --check` | passed |

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
passed locally; the first GitHub-hosted run remains an external integration
check.

## Safety ledger for this implementation session

- live KakaoTalk/UIA doctor probes: 1;
- live before/after read-only guard snapshots: 2;
- KakaoTalk UI mutations: 0;
- production backend stage calls: 0;
- production backend commit/Invoke calls: 0;
- actual messages sent: 0;
- synthetic fixture executable launches: 0;
- executable-trust known-folder resolutions: 0;
- KakaoTalk files/databases read: 0;
- credential/token reads: 0;
- native COM cancellation calls during implementation/tests: 0;
- screenshots/UI dumps/process-memory reads/injection/hooks: 0;
- automatic retries: 0;
- pushes: 0; and
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
  closed state now ensures only exact-unique selection can invoke that permit.
  Design and measure the exact native self-chat selector, and add an ephemeral
  UTF-16 observer only if a separately approved RFC amendment permits it; no
  room/profile text may be exposed or retained.
- Measure and review an exact unique send-button selector and InvokePattern;
  no keyboard fallback is permitted.
- Review and complete the proposed privacy-safe durable replay ledger. Its
  fixed codec/controller/ordering/correlation and an explicit-temporary-base
  Windows DPAPI/protected-ACL/write-through store are synthetically tested.
  The LocalAppData/fixed-volume/parent-chain constructor is now connected to
  the native port through a lazy, side-effect-free factory. Executable trust is
  checked before the first ledger method; current unavailable trust therefore
  keeps every production locator/store call unreachable. No real LocalAppData
  path has been resolved or written.
- Complete executable-signature and canonical-installation-root evidence. The
  content-free decision seam, fakeable offline WinTrust policy, and a
  disconnected native handle/WinVerifyTrust/provider/SPKI adapter now exist.
  Its owned state/provider links and verified primary index are exact-checked.
  A typed domain-separated root-relation codec now accepts only reviewed root
  kinds and bounded portable relative components, so an observed absolute path
  cannot become a pin. The adapter has zero production references,
  has never been called against KakaoTalk, and now derives an evidence-only
  root relation from guarded known-folder/executable paths. A focused source/API
  audit closed the permissive-sharing ABA gap. The signed synthetic fixture,
  structural/SPKI checks, and a real offline VERIFY/CLOSE lifetime test now
  exist; that test also corrected the signature-settings in/out-flag invariant.
  Provider-owned SIP subject, effective offline/revocation flags, success error
  fields, and catalog-recall state are now exact-checked before signer
  extraction rather than inferred from caller input.
  Synthetic CoTaskMem success/failure/refusal/NULL paths now prove matching
  Shell-output release counts without resolving a known folder.
  Reviewed Kakao signer/root values, a second independent fixture/root unsafe
  review, and production wiring remain absent and fail closed.
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
- Run the committed workflow on a GitHub Windows runner and obtain reviewed
  macOS/Linux regression signals before upstream release work.
- No live selector compatibility, target identity, empty-draft proof, stage
  restoration, or submission result has been measured.

## Next permissible step

The offline multiple-window remediation, target-binding scaffold,
replay-ledger scaffold, explicit-synthetic-base native ledger store,
trust-ordered lazy production ledger factory, pure executable-trust decision
seam, disconnected native trust API adapter, focused source/API audit, and
repository-owned signed fixture with bounded structural/SPKI and offline
VERIFY/CLOSE tests, guarded root derivation, and exact Shell allocation-lifetime
tests, approval-owned native target-permit plumbing, a closed native
target-observation state, and an approval-owned monotonic deadline are
implemented. Conventional same-process owner-group popup evidence and repeated
mutation-boundary modal checks are now implemented as well. Read-only COM
cancellation now uses a pinned worker-thread handshake while preserving
single-flight fallback for unsupported providers. The committed Windows
workflow now mirrors the local safe compatibility and release matrix. All pass
locally. Provider-owned WinTrust subject/revocation/error/catalog state and the
complete helper-mediated primary signer/leaf SPKI traversal are now validated
synthetically as well. The next safe work is a second independent unsafe
review and a clean pinned-Windows hosted CI reproduction, followed separately
by reviewed production signer/root provenance. None of these tasks requires or
authorizes a real KakaoTalk path or signature, a live label probe, or a
trust-store change.
The failed L10 result does not authorize another live observation.

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
