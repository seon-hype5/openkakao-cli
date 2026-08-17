# Windows production-activation RFC

Status: **implemented behind the default-off `windows-ui-write` feature**

Applies after: I20 and the failed-closed first L10 attempt

Current default-build capability: `send_open_chat=false`

Current feature-build capability: guarded `send_open_chat=true`

## Purpose

This document turns the remaining activation blockers into reviewable
contracts. It changes no capability. A privacy-bounded target selector
candidate is now implemented but remains unqualified; submit metadata still
requires future live measurement. Durable replay and executable trust remain
independent activation requirements.

## Non-goals

- Do not persist or output a room title, profile name, message, draft, UI tree,
  or any KakaoTalk file, database, credential, token, cookie, or process memory.
- Do not read conversation history. The only candidate private reads are the
  selected root's UIA Name for an in-memory exact comparison and, only after
  that binding succeeds, the exact composer's Value reduced to an
  empty/nonempty bit. Both BSTR allocations are scrubbed before release.
- Do not infer self-chat from process, window class, composer presence, focus,
  screen position, or a caller-supplied boolean.
- Do not use global keyboard input, clipboard, focus/Z-order changes, OCR,
  hooks, injection, or a second submit attempt. The sole exception is the
  profile-bound synchronous Enter message in section B.

## A. Requested self-chat binding

Candidate status: implemented, synthetically covered, not measured or
activated. Each
policy inspection now creates an opaque request-scoped HMAC key/label tag. A
probe can produce nonserializing redacted evidence only from an exact observed
UTF-16 candidate, and the proof commits to the complete redacted snapshot.
The approval retains a private permit, and fresh mutation state independently
requires `target_binding_verified`. Wrong-case, whitespace, normalization,
surrogate, replay, and state-movement negatives are covered without live UI.
The native mutation port now carries that same approval into fresh observation
and final preflight. Its exact UTF-16 verifier always uses the approval's own
private snapshot, accepts no caller-selected snapshot, and retains no observed
label. Native selection is a closed state rather than an optional label plus
caller-chosen booleans; only an exact-unique state can invoke the verifier.

The candidate observer runs only for a target-bound `local-send` inspection;
plain `doctor --ui` still reads no Name or Value. Windows accepts no target
positional argument. Exactly one configured allowlist entry is HMAC-bound into
the request without copying it into the command line; configured and observed
labels are capped at 512 UTF-16 units. After executable trust,
one selected exact-profile top-level root, one exact v2 composer, no modal,
matching session/integrity, and pre-read revalidation, the worker reads only
the root element's `CurrentName` BSTR. It never decodes or formats that BSTR.
An exact UTF-16 match creates state-bound evidence; a mismatch retains only a
unique-inexact state. The same process instance, root, modal state, and composer
are revalidated while the BSTR is alive.

Only a successful binding can authorize one `CurrentValue` read from the same
exact composer. That BSTR is reduced to `draft_empty`, scrubbed, and the target
Name is independently read and bound again afterward. A mismatch discards the
draft bit and refuses; a match rebinds evidence to the complete changed
snapshot. The mutation observer and final preflight bracket their draft reads
with the same exact Name comparison, and actual SetValue/Invoke entry repeats
it once more through the approval-owned permit. No raw Name, Value, label,
handle, or fingerprint enters output or persistence.

This candidate still satisfies none of the positive/negative measurement
counts below. It does not establish that KakaoTalk's root Name is a stable
self-chat discriminator, and it grants no write authority. Synthetic absent,
mismatch, unique-inexact, ambiguous-inexact, and ambiguous-exact cases continue
to prove that non-exact/non-unique states cannot mint usable evidence.
Pre/post Name bracketing also cannot prove that an element changed away and
back between observations; activation review must either rule that transition
out with stronger identity/navigation evidence or retain it as a blocker.

An acceptable target profile must provide all of the following:

1. version-bound, case-sensitive selector fields and a bounded ancestor path;
2. an exact and unique result in 20 separately opened self-chat observations;
3. zero matches in negative observations covering ordinary direct, group,
   open-chat, main-window, popup, duplicate-window, and deliberately colliding
   same-display-name states;
4. a fresh run-local fingerprint bound to process creation time, HWND, and the
   composer selected by the same profile;
5. byte-exact binding to the configured requested target without Unicode,
   whitespace, case, or locale normalization; and
6. no raw label, title, UIA Name/Value, handle, runtime ID, or fingerprint in
   output or a persistent artifact.

The separate `target-label-in-memory-exact-compare` privacy boundary was
approved for implementation in the 2026-08-17 user session. This amendment
implements its UTF-16-only, scrub-before-release design. That approval does not
substitute for requirements 2 and 3 above, does not qualify the candidate, and
does not authorize stage, commit, or a send capability. Until the measurement
matrix passes and is reviewed, production activation remains false.

### A.1 Approval lifetime

Offline contract status: implemented synthetically, not activated. A write
approval carries a private process-local monotonic deadline derived from the
remaining validated snapshot lifetime. Policy dispatch and the guarded native
path require both that deadline and the existing wall-clock expiry to remain
fresh, with equality stale. Checks occur before sender/native entry,
correlation consumption, observation, final preflight, and the actual
Value/Invoke boundary. Clock rollback cannot extend an approval, while a clock
advance only fails closed earlier.

The deadline is omitted from Debug and serialization and cannot survive a
process restart independently of its nonserializing approval. Synthetic tests
use injected future instants and pure clock states only. This completed
contract supplies no selector or permission and does not authorize L10-L40.

### A.2 Process owner-group modal evidence

Offline contract status: implemented without live observation or activation.
After exact executable-name verification, the selected window is modal-blocked
when it is disabled or when desktop top-level enumeration finds a visible
same-process candidate that has an owner and shares the selected window's
`GA_ROOTOWNER`. A foreign-process, hidden, unowned, or different-root-owner
window does not block. Every matching owned popup blocks conservatively even
if it might be modeless, and missing relevant owner-chain metadata is a closed
error rather than modal absence.

The scan reads no candidate title/class, UIA Name/Value, room/profile text, or
draft. Its callback retains only fixed selected metadata and booleans; the
already selected window's exact class/PID is revalidated. Positive evidence
prevents composer traversal and suppresses composer identity and
input-availability evidence in the public snapshot. The mutation path repeats
the scan in fresh observation, final preflight, and immediately before the
actual Value/Invoke boundary. Pure synthetic classification and
snapshot-mapping tests call no desktop API.

This generic rule covers conventional Win32 owned dialogs but cannot detect an
unowned custom dialog or an overlay rendered inside the selected window.
Negative live measurement for those shapes remains part of future selector
qualification. This completed offline boundary supplies no Kakao selector,
does not authorize another L10 attempt, and changes no send capability.

### A.3 Read-only provider timeout containment

Offline contract status: implemented without live observation or activation.
The fresh MTA inspection worker enables COM call cancellation before native
inspection and publishes its OS thread ID through an internal readiness event.
Worker startup and inspection share one eight-second budget. After readiness,
the caller grants one inspection permit and the worker rechecks the budget
before native entry; closing that permit prevents a boundary-racing readiness
event from starting late work. Later expiry causes exactly one zero-wait
cancellation request while a release channel keeps that thread alive,
preventing thread-ID reuse from targeting an unrelated call. The caller still
returns a non-retryable timeout and ignores late results.

This mechanism does not prove provider-side termination. Standard marshaling
may unblock the client, but custom marshaling may expose no cancel object and a
server may continue processing. The worker therefore retains the process-wide
single-flight lease until the native call actually returns; unsupported hangs
still block later probes rather than accumulating threads. Cancellation is
restricted to bounded read-only inspection and is never enabled for the joined
mutation worker. Pure duration, HRESULT, and channel-order tests invoke no COM
or desktop API. This containment adds no selector, target evidence, send
capability, or live authorization.

## B. Exact submit selector

A metadata-only measurement found no send element or InvokePattern in the
supported `26.7.0.5255` profile. The exact composer remains fixed by class,
AutomationId, Document control type, native HWND/PID, bounded ancestry,
enabled/writable state, and executable profile.

After all normal target, draft, activity, modal, mutex, deadline, approval, and
ledger checks, the profile dispatches one synchronous
`WM_KEYDOWN/VK_RETURN` to that composer HWND with a one-second
`SendMessageTimeoutW`. Zero or multiple composers, an unreadable property,
provider timeout, process replacement, selector drift, or failed dispatch is
terminal refusal/uncertainty. There is no global key input, clipboard,
hit-test, coordinate, default-button fallback, key-up, or retry.

## C. Durable replay and crash-recovery ledger

Offline implementation status: the content-free inner record codec, strict
decoder, storage trait, and transition controller now exist behind synthetic
tests. The guarded transaction checks for an existing record before UI
observation, writes the stage boundary before its final SetValue preflight and
one-shot claim, advances the commit boundary before the final Invoke preflight,
and retains an indeterminate terminal state after every returned Invoke
outcome.
The policy now generates a nonzero random 128-bit correlation in a non-Clone,
non-serializing, zeroizing token; the backend can consume it exactly once into
the internal record form. An explicit-synthetic-base Windows store now
implements current-user DPAPI, protected exact-user ACLs, handle/reparse
checks, bounded exclusive I/O, write-through replacement/tombstones, reload
verification, and test-only fault injection. Its reviewed production
constructor resolves the current-user known folder, proves both
source/canonical parent chains reparse-free, requires an exact fixed
volume-GUID path, retains the canonical base handle, and accepts only the
fixed protected application directory.

`NativeMutationPort` now owns a lazy production-ledger factory. Constructing
the port performs no known-folder or file I/O. The transaction must verify
executable trust before its first ledger method. The accepted x64 observer can
pass only for the exact source-static profile, but no valid production approval
can yet be created because self-target evidence remains false; therefore the
lazy factory and production locator remain unreachable. Automated tests never
call that locator or write real LocalAppData. When a later approved gate reaches
the factory, any open error or unwind is consumed once and becomes fixed,
non-retryable `windows_ledger_state_uncertain`. This is activation scaffolding,
not live-write authorization.

### Threat model

The ledger prevents accidental duplicate work by multiple openkakao processes,
process restart, mutex abandonment, and a crash after mutation may have begun.
It does not defend against a malicious process already running as the same
Windows user and deliberately deleting or replacing application state. If that
stronger threat must be covered, automatic commit requires a privileged
service or another separately reviewed trust boundary and stays disabled.

### Location and record privacy

- Resolve `FOLDERID_LocalAppData` with `SHGetKnownFolderPath`; do not trust an
  environment-variable expansion or write under KakaoTalk directories.
- Use an application-owned, per-user directory and one versioned ledger file.
- The fixed-size record may contain only a magic/version, state enum, random
  128-bit transaction correlation, monotonic sequence, and integrity fields.
- It must never contain message bytes, requested/observed labels, PID, HWND,
  executable path, UIA identifiers, fingerprints, or KakaoTalk data.
- Protect the record with current-user DPAPI and
  `CRYPTPROTECT_UI_FORBIDDEN`; never use machine scope. Validate a strict inner
  schema and checksum after decrypting because decryption success alone is not
  treated as schema integrity.
- The opaque correlation is generated by the policy, is non-Clone and
  non-serializing in core types, and is the only value a future schema-v2 human
  recovery flow may display. Debug and ordinary reports continue to redact it.

### Atomic write protocol

All ledger operations occur while the existing named mutation mutex is held.

1. Open or create the per-user directory without following an unexpected
   reparse point; reject a network path, wrong owner, permissive ACL, or any
   metadata uncertainty.
2. Write the complete protected record to a random temporary file in the same
   directory with exclusive sharing and write-through semantics.
3. Call `FlushFileBuffers` on the temporary file and close it.
4. Install it with `MoveFileExW` using `MOVEFILE_REPLACE_EXISTING |
   MOVEFILE_WRITE_THROUGH`; cross-volume copy is forbidden.
5. Reopen, decrypt, and exact-compare the installed record before proceeding.

Do not rely on `REPLACEFILE_WRITE_THROUGH`; Microsoft's `ReplaceFileW`
documentation marks that flag unsupported. Any create, ACL, protect, write,
flush, rename, reopen, decrypt, parse, compare, or cleanup uncertainty blocks
the transaction and is non-retryable.

### State machine

```text
no ledger
  -> stage_may_have_started       (durable before first SetValue)

stage_may_have_started
  -> no ledger                    (stage-only: exact empty restored)
  -> commit_may_have_started      (commit: durable before sole Invoke)
  -> indeterminate                (crash, error, or unknown state)

commit_may_have_started
  -> indeterminate                (every returned or lost Invoke outcome)

indeterminate
  -> human resolution only
```

The absence of a ledger is the only automatically usable state. Before the
first `SetValue`, `stage_may_have_started` must be durable. Immediately before
the only `Invoke`, `commit_may_have_started` must be durable. After commit
entry, no result automatically deletes the record, including an apparent echo.
Stage may remove its record only after exact owned-value restoration and exact
empty readback; a crash during removal is safe only because restoration was
already proven.

At startup or authorization, any present record—including a terminal marker—
and every malformed, undecryptable, or unknown record refuses all Windows UI
writes. `WAIT_ABANDONED` also
refuses; the prior owner was required to write a pre-mutation record, so a
present record preserves its uncertainty. There is no age-based expiry,
garbage collection, automatic reset, or retry.

A future recovery command must be separate from send, require a typed opaque
correlation plus explicit human confirmation, expose no content, and only mark
resolution. It cannot infer that a message was not sent and cannot run during
ordinary CLI startup.

### Required synthetic tests

- crash/failure injection before and after every durable-write step;
- truncated, oversized, unknown-version, corrupt, wrong-user, wrong-ACL,
  reparse, and unexpected-state records;
- two processes contending on distinct and identical correlations;
- mutex abandonment with each ledger state;
- crash after SetValue entry and immediately before/after Invoke entry;
- exact restored stage clears once; changed/unknown draft never clears;
- process restart refuses every nonempty ledger state; and
- every journal/output/Debug path is canary-free and every uncertainty has
  `retry_safe=false`.

## D. Executable trust and canonical installation root

Offline implementation status: the accepted x64 bundle in
[`KAKAOTALK_X64_TRUST_PROFILE.md`](KAKAOTALK_X64_TRUST_PROFILE.md) fixes the
complete target SHA-256, target leaf SPKI, `ProgramFiles64` relation, exact
version, and provider flags. The native observer is now wired into read-only
inspection and transaction preflight. It still performs no call until a live
session is separately authorized, and `send_open_chat` remains false.
Synthetic adversarial tests cover every pure refusal and alternate installer
roots cannot satisfy the source-static relation.

The former basename/version-only check was insufficient. The accepted profile
now pins complete reviewed target bytes, target leaf SPKI, exact
version/machine, and one architecture-specific root. The observer must query
the process image path, hold the first candidate without write/delete sharing,
query again, independently guard the second candidate, and require canonical
path and file-identity agreement before trusting the verification handle.
Symlink/reparse resolution, non-NTFS or non-fixed volumes, path replacement, or
candidate disagreement fail closed. Because Windows does not document this
path query as an atomic backing-file identity, hosted adversarial qualification
on every supported Windows/NTFS image remains mandatory. Signed-PowerShell and
the committed Rust helper passed all three replacement timings on Windows 11
`10.0.26200`/NTFS and hosted Windows Server 2022 `10.0.20348`/NTFS.

`WinVerifyTrust` must run with no UI, cache-only URL retrieval, and a live
`CERT_STRONG_SIGN_PARA` selecting `szOID_CERT_STRONG_SIGN_OS_1`, so trust
checking cannot prompt, introduce network access, or accept MD5/SHA-1. Generic
Authenticode trust is not publisher identity: activation also needs a reviewed
Kakao target SPKI and exact canonical install root obtained from release
provenance. No value may be guessed from the current machine or printed.
Unknown target bytes/signer, weak signing, catalog ambiguity, offline revocation
uncertainty, or install-root mismatch disables writes.

The exact production strong-policy constructor has now been exercised through
`CertIsStrongHashToSign` with no certificate. On Windows `10.0.26200.0`, MD5
and SHA-1 were refused and SHA-256 was accepted. This hash-only OS result does
not stand alone: the accepted timestamped x64 target also completed the real
provider traversal on Windows 11 and hosted Windows Server 2022.

The dependency surface, unsafe ownership/lifetime audit, and synthetic verifier
tests are complete. Source wiring does not itself authorize a live
executable-signature observation.

The minimum binding feature set, native call order, allocation ownership, and
offline test boundary are now frozen in
[`NATIVE_ACTIVATION_BOUNDARIES.md`](NATIVE_ACTIVATION_BOUNDARIES.md). That
inventory does not authorize a native observation or capability activation.

A crate-private fakeable orchestration seam fixes the offline/no-UI WinTrust
policy, attempts one CLOSE after every returned VERIFY state, maps provider
errors/panics to closed refusal codes, and rejects catalog/secondary signature
ambiguity before the existing pure verifier can succeed. Its profile-bound
Windows adapter retains stable boxed WinTrust state, binds guarded candidate
file identities to process creation time, validates no-follow NTFS/fixed-volume
paths,
retains the canonical file and parent directories under read-only sharing to
exclude version/path write-delete ABA races, and hashes bounded DER-encoded
leaf SPKI and the complete guarded file. It also resolves only the profile's
source-static known-folder kind,
retains the canonical root/ancestor handles, and hashes only a bounded
same-volume relative relation. Post-VERIFY extraction now exact-
checks every caller-owned policy/pointer field, the provider's data/action/
signature-settings links, SIP subject choice, effective offline/revocation
flags, zero provider errors, catalog-recall state, primary verified-signature
index zero, exact helper-returned signer/leaf pointers, and zero nested signer
and leaf errors. A private raw-pointer helper seam with one unsafe extraction
boundary now exercises the complete successful provider-to-signer-to-leaf
SPKI path and pointer substitution refusals with retained synthetic
structures; it does not qualify a real Windows provider image.

The provider high-word check is deliberately exact. Positive x64 target
qualification established `0x80003080`, so the accepted policy requires the
caller low word plus only `CPD_USE_NT5_CHAIN_FLAG`. CPD revocation high bits,
RFC3161, lower-quality-chain, unknown flags, or any attempt to relax
offline/no-UI/strong-sign policy remain refusals.

The version-1 installation-root codec accepts only a reviewed root kind
(`ProgramFilesX86`, `ProgramFiles64`, or `CurrentUserLocalAppData`) plus one to
eight bounded printable-ASCII relative components. It rejects separators,
alternate-data-stream syntax, dot/space ambiguity, non-ASCII normalization,
reserved DOS device names, and absolute prefixes; ASCII case is folded before a
length-delimited,
domain-separated SHA-256 digest. `ExecutableTrustProfile` accepts only this
typed root digest, a `ReviewedExecutableDigest`, and a `ReviewedSignerDigest`
constructed from source-embedded static bytes; runtime file/SPKI/root
observations remain evidence types and cannot be passed as expected pins by
accident. Production configures only the accepted x64 target bytes,
`ProgramFiles64` components, and signer value; the observer is reachable only
from read-only inspection or transaction preflight. Capability and selector
gates remain closed.

[`TRUST_PROVENANCE.md`](TRUST_PROVENANCE.md) now freezes the evidence bundle,
synthetic signed-fixture, and canonical-root derivation plan. The repository
fixture now exists with bounded structural/SPKI and cache-only VERIFY/CLOSE
tests; it supplies no production signer pin, root relation, or live
authorization.

## E. Activation order

1. Review and accept this RFC without changing capability.
2. Complete the ledger and executable-verifier seams with only synthetic
   files, fake trust results, and default-off/all-feature CI. The pure ledger
   state machine, policy correlation handoff, pure executable-trust decision
   seam, and a disconnected synthetic-base Windows DPAPI/ACL store are
   implemented. The LocalAppData/volume constructor is now wired through a
   side-effect-free lazy factory strictly after executable-trust verification;
   accepted trust must complete before its production initialization. The
   native executable API adapter, hosted NTFS/provider qualification, accepted
   architecture-specific target/signer/root provenance, and source wiring are
   complete while capability remains false.
3. Obtain a new, narrowly named privacy approval to measure target metadata;
   accept or reject a self-target profile without mutation.
4. Separately measure the submit selector without invoking it.
5. Re-run L10 under fresh approval, then L20 and L30 under their own approvals.
6. Enable `send_open_chat` only after every blocker is implemented, audited,
   measured, and covered by adversarial negatives.
7. L40 still requires a new immediate approval for exactly one commit.

No step inherits authorization from an earlier step.

## Official Windows references

- [CoEnableCallCancellation](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coenablecallcancellation)
- [CoDisableCallCancellation](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-codisablecallcancellation)
- [CoCancelCall](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocancelcall)
- [Canceling Method Calls](https://learn.microsoft.com/en-us/windows/win32/com/canceling-method-calls)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
- [WINTRUST_FILE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
- [CRYPT_PROVIDER_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data)
- [CRYPT_PROVIDER_SGNR](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr)
- [CRYPT_PROVIDER_CERT](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert)
- [WTHelperProvDataFromStateData](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata)
- [WTHelperGetProvSignerFromChain](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain)
- [WTHelperGetProvCertFromChain](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovcertfromchain)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
