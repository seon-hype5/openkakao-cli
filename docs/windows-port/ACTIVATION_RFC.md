# Windows production-activation RFC

Status: **proposal only; no live gate or production write is authorized**

Applies after: I20 and the failed-closed first L10 attempt

Current production capability: `send_open_chat=false`

## Purpose

This document turns the remaining activation blockers into reviewable
contracts. It deliberately supplies no guessed KakaoTalk selector and changes
no capability. Target identity and submit metadata require future live
measurement under new explicit approval; durable replay and executable trust
can be implemented and tested offline only after this RFC is accepted.

## Non-goals

- Do not read or persist a room title, profile name, message, draft, UI tree,
  KakaoTalk file, database, credential, token, cookie, or process memory.
- Do not infer self-chat from process, window class, composer presence, focus,
  screen position, or a caller-supplied boolean.
- Do not use keyboard input, Enter, clipboard, focus/Z-order changes, OCR,
  window messages, hooks, injection, or a second submit attempt.
- Do not activate stage or commit merely because this proposal is merged.

## A. Requested self-chat binding

Offline contract status: implemented synthetically, not activated. Each
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

The production Windows observer remains deliberately disconnected: it reads
no title/Name/label, passes no candidate to the verifier, produces no proof,
leaves target binding false, and cannot read draft Value. Synthetic absent,
mismatch, unique-inexact, ambiguous-inexact, and ambiguous-exact cases cover
the permit seam and prove that non-exact/non-unique states never call the
verifier. This scaffold satisfies no measurement requirement below and grants
no live or write authority.

The current policy checks that a requested label occurs exactly once in the
configured allowlist, while the native snapshot independently leaves
`self_chat_verified=false`. A future implementation must bind the exact
allowlist entry to independently observed live target evidence; setting the
three target booleans together is not a proof.

An acceptable target profile must provide all of the following:

1. version-bound, case-sensitive selector fields and a bounded ancestor path;
2. an exact and unique result in 20 separately opened self-chat observations;
3. zero matches in negative observations covering ordinary direct, group,
   open-chat, main-window, popup, and duplicate-window states;
4. a fresh run-local fingerprint bound to process creation time, HWND, and the
   composer selected by the same profile;
5. byte-exact binding to the configured requested target without Unicode,
   whitespace, case, or locale normalization; and
6. no raw label, title, UIA Name/Value, handle, runtime ID, or fingerprint in
   output or a persistent artifact.

If no stable non-content property can distinguish self-chat, reading a label
only for an in-memory exact comparison is a new privacy boundary. It needs a
separate named approval and RFC amendment; ordinary L10 does not authorize it.
The buffer would have to remain UTF-16/zeroizing, never become a Rust `String`,
and be scrubbed before COM release. Until that design is approved and measured,
target identity remains false.

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

## B. Exact submit selector

A submit profile may be proposed only after target binding is accepted. Its
measurement session is metadata-only: it must not call `Invoke`.

The profile must fix the exact class, AutomationId, control type, bounded
ancestor relation to the already selected composer window, enabled state, and
`InvokePattern` availability for one supported KakaoTalk file version. It must
produce one candidate in 20 positive observations and zero in wrong-room,
disabled, modal, popup, duplicate, absent, and version-mismatch negatives.

Zero or multiple candidates, an unreadable property, provider timeout, process
replacement, or selector drift disables commit. There is no Enter, key-input,
clipboard, hit-test, coordinate, or default-button fallback.

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
executable trust before its first ledger method, and current production trust
always returns `windows_executable_trust_unavailable`; therefore the lazy
factory and production locator remain unreachable. Automated tests never call
that locator or write real LocalAppData. If future trust wiring reaches the
factory, any open error or unwind is consumed once and becomes fixed,
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

Offline implementation status: a content-free verifier profile/evidence seam
now models handle-derived final-path provenance, normalized local fixed-volume
status, reparse refusal, process-creation binding, three-way file-identity
agreement, exact version, no-UI/cache-only Authenticode behavior, catalog
ambiguity, exact signer cardinality/digest, and exact install-root digest.
Synthetic adversarial tests cover each refusal independently and redact every
opaque identity. A disconnected native adapter now contains the reviewed
process/file/WinTrust API sequence, but no automated test or production path
calls it, no real executable has been observed, and no real signer/root digest
is present. Production uses `UnavailableExecutableTrust` before ledger or UI
observation, so this remains an additional activation barrier rather than a
trust claim.

The current basename/version check is insufficient for activation. A future
profile must open the executable itself, obtain its final normalized path from
that handle with `GetFinalPathNameByHandleW`, and bind the handle's file
identity to the process instance already checked immediately before mutation.
Symlink/reparse resolution, network paths, unexpected volume types, path
replacement, or handle/path disagreement fail closed.

`WinVerifyTrust` must run with no UI and cache-only URL retrieval so trust
checking cannot prompt or introduce network access. Generic Authenticode trust
is not publisher identity: activation also needs a reviewed Kakao release
signer certificate/public-key digest and an exact allowed canonical install
root obtained from signed release provenance. Neither value may be guessed
from the current machine or printed. Unknown signer, catalog ambiguity,
offline revocation uncertainty, or install-root mismatch disables writes.

Adding this boundary requires a dependency-feature RFC for the minimum
`windows` namespaces, an unsafe ownership/lifetime audit, and synthetic tests
around a verifier trait. No live executable-signature observation is
authorized by this proposal.

The minimum binding feature set, native call order, allocation ownership, and
offline test boundary are now frozen in
[`NATIVE_ACTIVATION_BOUNDARIES.md`](NATIVE_ACTIVATION_BOUNDARIES.md). That
inventory does not authorize a native observation or capability activation.

A crate-private fakeable orchestration seam fixes the offline/no-UI WinTrust
policy, attempts one CLOSE after every returned VERIFY state, maps provider
errors/panics to closed refusal codes, and rejects catalog/secondary signature
ambiguity before the existing pure verifier can succeed. Its disconnected
Windows adapter retains stable boxed WinTrust state, binds three file identity
observations to process creation time, validates no-follow fixed-volume paths,
retains the canonical file and parent directories under read-only sharing to
exclude version/path write-delete ABA races, and hashes bounded DER-encoded
leaf SPKI. It also resolves only the profile's source-static known-folder kind,
retains the canonical root/ancestor handles, and hashes only a bounded
same-volume relative relation. Post-VERIFY extraction now exact-
checks every caller-owned policy/pointer field, the provider's data/action/
signature-settings links, and primary verified-signature index zero.

The version-1 installation-root codec accepts only a reviewed root kind
(`ProgramFilesX86`, `ProgramFiles64`, or `CurrentUserLocalAppData`) plus one to
eight bounded printable-ASCII relative components. It rejects separators,
alternate-data-stream syntax, dot/space ambiguity, non-ASCII normalization,
reserved DOS device names, and absolute prefixes; ASCII case is folded before a
length-delimited,
domain-separated SHA-256 digest. `ExecutableTrustProfile` accepts only this
typed root digest and a `ReviewedSignerDigest` constructed from source-embedded
static bytes; runtime SPKI/root observations remain unreviewed evidence types
and cannot be passed as expected pins by accident. Generic runtime root
derivation is implemented, but no production root kind/components or signer
value is configured and the native adapter has zero production references.
Production therefore remains
`UnavailableExecutableTrust`.

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
   current unavailable trust makes its production initialization unreachable.
   The native executable API adapter remains disconnected. Repository-owned
   signed-fixture evidence and generic runtime root derivation now exist, while
   independent unsafe/root review, signer/root provenance, and the trust
   production-wiring decision remain incomplete.
3. Obtain a new, narrowly named privacy approval to measure target metadata;
   accept or reject a self-target profile without mutation.
4. Separately measure the submit selector without invoking it.
5. Re-run L10 under fresh approval, then L20 and L30 under their own approvals.
6. Enable `send_open_chat` only after every blocker is implemented, audited,
   measured, and covered by adversarial negatives.
7. L40 still requires a new immediate approval for exactly one commit.

No step inherits authorization from an earlier step.

## Official Windows references

- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
- [WINTRUST_FILE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
