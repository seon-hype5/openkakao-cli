# Windows native activation boundaries

Status: accepted implementation inventory; no live authorization

Binding baseline: `windows = 0.62.2`
The mutation portions apply only behind the default-off
`windows-ui-write` feature; owner-group modal inspection is also present in
the default read-only build.

## Purpose and non-authorization

This document freezes the minimum Windows namespaces, native call ordering,
ownership rules, and synthetic-test seams for five activation boundaries:

- read-only COM call cancellation;
- process owner-group modal evidence;
- the approval-owned native target-binding permit;
- the trust-ordered lazy production ledger; and
- the accepted x64 executable-trust observer.

It configures only the public x64 signer, target, and installation-root digest.
It does not advertise a send capability, authorize inspection of the installed
KakaoTalk executable/window, mutate a composer, or authorize any live gate.
All selector and approval barriers remain in place.

## Dependency-feature decision

The repository already enables `Win32_Foundation`, `Win32_Security`,
`Win32_Storage_FileSystem`, `Win32_System_Com`, and
`Win32_System_Threading`. The native implementations may add exactly these
`windows` features:

| Feature | Required binding surface |
|---|---|
| `Win32_Security_Authorization` | handle-based `GetSecurityInfo` for owner/DACL verification |
| `Win32_Security_Cryptography` | current-user DPAPI, certificate structures, SPKI DER encoding |
| `Win32_Security_Cryptography_Catalog` | generated `windows` 0.62.2 gate on WinTrust provider-data helpers |
| `Win32_Security_Cryptography_Sip` | generated `windows` 0.62.2 gate on WinTrust provider-data helpers |
| `Win32_Security_WinTrust` | `WinVerifyTrust`, state/provider/signature structures |
| `Win32_System_IO` | synchronous `ReadFile` and `WriteFile` bindings |
| `Win32_UI_Shell` | `FOLDERID_LocalAppData`, `FOLDERID_ProgramFilesX86`, `FOLDERID_ProgramFilesX64`, and `SHGetKnownFolderPath` |

No new crate is required. `sha2`, `rand`, and `zeroize` are already direct
dependencies. `Win32_Security_Cryptography_UI` is deliberately excluded. No
registry, networking, credential, process-memory, or UI-input namespace is
part of this inventory.

This list was checked against the locally resolved generated source for
`windows` 0.62.2. In that version, `WTHelperProvDataFromStateData` and
`WTHelperGetProvSignerFromChain` are gated by both Catalog and Sip, while
`WTHelperGetProvCertFromChain` is gated by Cryptography.
The modal boundary uses `EnumWindows`, `GetWindowThreadProcessId`,
`IsWindowVisible`, `GetWindow(GW_OWNER)`, and
`GetAncestor(GA_ROOTOWNER)` from the already enabled
`Win32_UI_WindowsAndMessaging` feature, so it adds no dependency feature.
The read-only cancellation boundary uses `CoEnableCallCancellation`,
`CoDisableCallCancellation`, and `CoCancelCall` from the already enabled
`Win32_System_Com` feature plus `GetCurrentThreadId` from the already enabled
`Win32_System_Threading` feature. It likewise adds no dependency feature.

## Approval lifetime boundary

Offline status: implemented and still fail-closed. Policy captures a
process-local `Instant` alongside the approved wall-clock reading and stores a
private deadline computed from the snapshot's remaining lifetime. The deadline
is nonserializing and absent from Debug. The effective expiry is the earlier of
the existing wall-clock gate and this monotonic gate; equality refuses.

The policy checks the monotonic deadline before sender dispatch. The Windows
path checks it before scoped-worker/native entry, again before consuming the
one-shot ledger correlation, at the start of every native observation, at
final native revalidation, and immediately before `SetValue` or `Invoke`.
Wall-clock expiry remains checked alongside it. Synthetic tests pass explicit
future monotonic values and pure clock-state booleans; no test sleeps, changes
the system clock, opens a live UI, or invokes a native mutation API.

This boundary closes the previously recorded clock-rollback lifetime risk. It
does not make approvals durable across restart, because approvals are already
nonserializing in-process capabilities. It adds no Windows dependency,
selector, label observer, trust value, send capability, or live authorization.

## Read-only COM cancellation boundary

Offline status: implemented without a live UI call. A fresh windowless MTA
worker calls `CoEnableCallCancellation(NULL)` before inspection and reports
its nonzero `GetCurrentThreadId` value only after enable succeeds. Startup,
readiness, and inspection consume one eight-second budget. The caller issues
one inspection permit only after receiving readiness in time, and the worker
rechecks the deadline before native entry. A timeout closes that permit, so a
readiness event racing the boundary cannot start late work. A normal result
disables cancellation while the apartment is initialized, releases the worker,
and joins it before returning.

On expiry after readiness, the caller retains the only release sender while it
initializes or reuses its own COM apartment and calls
`CoCancelCall(worker_thread_id, 0)` exactly once. Holding the release sender
pins the OS thread ID through that native call. A post-readiness Rust unwind is
caught, converted to a fixed error, and held under the same protocol. The
caller then releases and detaches the worker and returns the existing
non-retryable timeout; it never consumes a late result. Expiry before readiness
drops the readiness receiver and inspection permit, causing the worker to
refuse before inspection even if readiness races the timeout.

Only `S_OK`, `RPC_E_CALL_COMPLETE`, and `RPC_E_CALL_CANCELED` are terminal
request outcomes. Absence of a cancel object, disabled cancellation, or any
other failure does not release the single-flight lease: the worker owns that
lease until its native call really returns or unwinds. COM may unblock a
standard-marshaled client without stopping server work, and custom marshaling
may not support cancellation. This remains bounded to non-mutating inspection;
any private Name/Value BSTR stays inside the worker and is scrubbed before
release. The joined mutation worker never enables cancellation and its outcome
rules do not change.

Enabling cancellation can degrade synchronous marshaled-call performance, so
its lifetime is restricted to one bounded read-only probe and balanced with
one disable attempt. `CoUninitialize` resets the fresh thread's cancellation
state if disable itself fails. Unit tests exercise only saturated duration
arithmetic, pre-readiness permit closure, HRESULT classification, and a
channel-coordinated synthetic thread release; they invoke no COM, UIA, window
enumeration, or application process.

## Process owner-group modal boundary

Offline status: implemented in read-only inspection and the inactive,
feature-gated mutation path. Read-only enumeration begins only after exact
executable-name verification. A disabled selected window is blocking.
Otherwise a second top-level HWND blocks only when it is visible, reports the
selected PID, has a non-null owner, and resolves to the same root-owner HWND as
the selected window. Hidden, foreign-process, unowned, and different-root-owner candidates
are ignored. A visible owned popup is conservatively blocking even if it is
modeless. An owner/root-owner query failure after relevant PID and visibility
evidence is stale uncertainty, not absence.

The enumeration callback catches Rust unwind, retains no candidate collection,
and reads no title, class, UIA property, or content. It carries only selected
HWND/PID/root-owner metadata and output booleans for the synchronous call. The
selected HWND/class/PID is revalidated after enumeration, and its enabled state
is reread. Positive evidence prevents UIA composer traversal and causes public
mapping to suppress composer identity and input-availability claims.

Fresh mutation observation uses the same helper. Final native preflight and
the actual `SetValue`/`Invoke` methods each rescan under the transaction mutex;
at the actual boundary the scan is followed by the two-clock check and native
call. Before the execution claim, a positive scan is a `ModalPresent` refusal.
After claim and Value/Invoke method entry, the existing conservative
`SubmissionUncertain` normalization remains in force even if the last scan
stops before the OS call. Pure tests cover self/foreign/hidden/unowned/
different-group/matching/uncertain shapes and modal snapshot suppression
without calling a desktop API. Generic owner chains cannot detect unowned
custom or in-window overlays, so future activation measurement must retain
those negative cases.

This boundary introduces no selector, Kakao content read, write authority, or
live-session permission.

## Native target-binding permit boundary

Candidate status: the mutation port borrows the same `ApprovedSend` used by
the guarded transaction for the whole synchronous stage or commit call. Fresh
target observation and final native target revalidation invoke an exact UTF-16
comparison through that approval. The comparison is fixed to the private
policy-bound snapshot stored in the approval; native callers cannot substitute
another snapshot.

An observer must classify selection through a closed state: absent, unique but
inexact, ambiguous inexact, ambiguous exact, or exact unique. Only the exact-
unique state can carry an ephemeral label slice to the comparison callback;
all target booleans are derived from the state, so contradictory caller-chosen
combinations cannot be represented. Neither `TargetEvidence` nor
`NativeMutationPort` retains the label. The same four-way conjunction gates
draft Value access and the final preflight before `SetValue` or `Invoke`.

The current profile has a privacy-bounded target path. Only a target-bound
inspection with exactly one configured allowlist entry can read
the selected root's `CurrentName`. The BSTR remains UTF-16, is never decoded or
formatted, and is scrubbed before the root/automation interfaces are released.
The process instance, exact root, modal state, and exact v2 composer are checked
before and after the read. An exact match mints opaque evidence; mismatch emits
no label and remains unique-inexact. Plain `doctor --ui` supplies no binding
request and therefore still reads neither Name nor Value.

After exact binding only, the same worker reopens exactly one v2 composer,
rechecks PID/HWND/fingerprint/enabled/writable/unfocused state, reads
`CurrentValue`, reduces it to one empty/nonempty bit, and scrubs that BSTR. It
then reads and binds the root Name a second time; mismatch discards the bit and
refuses. Because target evidence commits the complete snapshot, the second Name
observation rebinds it after the draft bit changes. The mutation observer and
final preflight bracket their Value reads, and SetValue/Invoke entry repeats the
Name check through the approval-owned permit.

For this exact profile, an empty composer may expose a UI-chrome placeholder as
provider Value. The boundary accepts empty only when a bounded native
`WM_GETTEXTLENGTH` query returns zero or the scrubbed UTF-16 Value matches the
source-static domain-separated placeholder digest. SetValue ownership accepts
only the exact requested UTF-16 value or that value plus one provider carriage
return; control characters are forbidden in authorized messages. No content,
length-derived text, or digest input is emitted.

Raw exact-class enumeration may include helper windows. Mutation observation
and final preflight require exactly one raw HWND to match both the approved PID
and run-scoped window fingerprint. Zero or multiple matches refuse; unrelated
helpers cannot become the target or dilute the target permit.

Pure synthetic tests exercise every closed target state, mismatches, state
movement, draft-read authorization, placeholder/normalized readback, and raw
helper-window selection. General activation still requires the remaining
positive/negative live matrix—including a deliberately colliding same-display-
name non-self chat—and a fresh one-shot approval.
The two Name observations do not make the Value read atomic with room identity:
an away-and-back transition between them is not observable. A stronger native
identity/navigation invariant or explicit proof that this transition cannot
occur remains an activation blocker.

## Durable ledger boundary

Implemented location status: the fixed current-user known-folder, source and
canonical parent-chain no-reparse, volume-GUID/fixed-local,
retained-base-handle, and fixed child-directory protocol below is implemented.
`NativeMutationPort` references it only through a lazy factory. Port
construction performs no I/O, transaction ordering checks executable trust
before the first ledger method, and the accepted x64 trust profile is exact.
The default build remains read-only. The default-off write build can open this
store only after runtime opt-in and policy approval.

The factory is consumed before its first open attempt. An error or unwind can
never trigger an automatic second attempt in the same transaction object and
maps to fixed `SubmissionUncertain` / `windows_ledger_state_uncertain` with
`retry_safe=false`.

An `Indeterminate` sequence-2 record is the only recoverable shape because it
can arise only from `StageMayHaveStarted`; stage-only contains no submit call.
A recovery-marked commit must prove the exact live message and all fresh
target/window/composer/trust/inactivity gates, then durably promote the record
to terminal sequence 3 before one submit. It performs no SetValue or clear.
Normal approvals, every other record shape, and every sequence-3 record fail
closed without a retry edge.

### Fixed location and bounds

1. Resolve the current user's `FOLDERID_LocalAppData` with
   `SHGetKnownFolderPath(KF_FLAG_DEFAULT, None)`. Environment variables,
   registry guesses, and KakaoTalk-owned directories are forbidden.
2. Append one compile-time ASCII application directory and one compile-time
   ledger filename. Reject embedded NUL, relative components, alternate data
   stream syntax, or a path that exceeds the chosen fixed UTF-16 bound.
3. The decrypted inner record is exactly `ENCODED_RECORD_LEN` bytes. The
   encrypted outer file is nonempty and at most 64 KiB. Size uncertainty,
   truncation, trailing bytes, or growth while reading is an invalid record.
4. The directory may contain only the ledger plus implementation-owned random
   temporary/tombstone names. Any malformed or unexpected implementation-owned
   artifact blocks automatic use; it is never silently aged out.

### Directory and file security

Obtain the current process token's `TokenUser` SID with
`OpenProcessToken(TOKEN_QUERY)` and two-call `GetTokenInformation`. Validate
the returned buffer, SID pointer range, and `IsValidSid` before use. The SID is
never rendered or persisted by the application.

Create the application directory with an absolute security descriptor passed
to `CreateDirectoryW`, not by creating it permissively and repairing it later.
The descriptor has:

- current token user as owner;
- a present, protected, non-null DACL;
- exactly one allow ACE for that same SID;
- no deny, object, callback, inherited, or unknown ACE; and
- only the reviewed full-control mask needed by this private directory.

Create ledger and temporary files with an equally explicit, protected,
current-user-only descriptor. Reopen every directory/file handle with
`FILE_FLAG_OPEN_REPARSE_POINT`, query `FileAttributeTagInfo`, and reject any
reparse attribute or non-file/non-directory type mismatch. `GetSecurityInfo`
must then reproduce the exact owner/DACL shape from the opened handle. A
path-only ACL check is insufficient.

Administrators can ultimately take ownership; this boundary protects against
accidental sharing and cooperative-process mistakes, not a malicious
administrator or a malicious process already running as the same user.

### DPAPI ownership and privacy

Use `CryptProtectData` and `CryptUnprotectData` with:

- `CRYPTPROTECT_UI_FORBIDDEN`;
- no `CRYPTPROTECT_LOCAL_MACHINE`;
- no prompt structure;
- no description string; and
- no optional entropy unless a later wire-version RFC defines it.

DPAPI output `CRYPT_INTEGER_BLOB.pbData` is owned by the caller and must be
wrapped immediately. On every success/error/unwind path, zero its full
reported allocation before `LocalFree`. Decrypted bytes move directly into a
fixed-size zeroizing buffer; they are never formatted or copied into an
unbounded `Vec`. The input/output blob lengths are checked before every pointer
conversion. A non-null description returned by a future API change is also
freed and treated as a refusal.

The `PWSTR` returned by `SHGetKnownFolderPath` is freed with `CoTaskMemFree` on
all paths, including an error path that returned a non-null pointer. It must
not be freed with `LocalFree`.

### Compare-and-replace protocol

All calls occur while the existing zero-wait named mutation mutex is owned.
The store still performs an exact load-and-compare immediately before each
change; the mutex is not a substitute for the store contract.

For `durable_replace(expected, next)`:

1. Open the directory and installed ledger without following a reparse point.
2. Load/decrypt/decode it and exact-compare it with `expected`.
3. Create a 128-bit-random temporary name in the same verified directory with
   `CREATE_NEW`, no sharing, explicit ACL, and `FILE_FLAG_WRITE_THROUGH`.
4. DPAPI-protect the exact 48-byte inner record, write it once synchronously,
   verify the exact byte count, call `FlushFileBuffers`, and close the handle.
5. Reopen the temporary file without following reparse points and exact-check
   identity, ACL, bounded ciphertext, decrypted schema, and `next`.
6. Call `MoveFileExW(temp, ledger, MOVEFILE_REPLACE_EXISTING |
   MOVEFILE_WRITE_THROUGH)`. `MOVEFILE_COPY_ALLOWED` is forbidden, so a
   cross-volume fallback cannot occur.
7. Reopen the installed file and repeat the exact handle/ACL/decrypt/record
   comparison before returning success.

Any failure returns `IoUncertain`; no mutation may follow that return. Any
temporary or tombstone artifact left by a failure is detectable on the next
load. Cleanup is best effort only and never converts uncertainty into success.

For `durable_remove(expected)`, exact-load `expected`, rename the ledger to a
random same-directory tombstone with `MOVEFILE_WRITE_THROUGH`, prove the
ledger path absent, and delete the tombstone. A crash before the rename leaves
the nonempty ledger. A crash after the rename happens only after exact stage
restoration was already proven; any surviving tombstone blocks later automatic
work. Successful removal still reloads and proves absence.

### Ledger native API inventory

- Shell: `SHGetKnownFolderPath`, `FOLDERID_LocalAppData`, `KF_FLAG_DEFAULT`.
- Token/security: `OpenProcessToken`, `GetTokenInformation`, `IsValidSid`,
  `InitializeSecurityDescriptor`, `InitializeAcl`, `AddAccessAllowedAceEx`,
  `SetSecurityDescriptorOwner`, `SetSecurityDescriptorDacl`, and
  `SetSecurityDescriptorControl`.
- Handle ACL audit: `GetSecurityInfo`, `GetSecurityDescriptorControl`,
  `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`,
  `GetAclInformation`, `GetAce`, `EqualSid`.
- File: `CreateDirectoryW`, `CreateFileW`, `GetFileInformationByHandleEx`,
  `GetFileSizeEx`, `ReadFile`, `WriteFile`, `FlushFileBuffers`,
  `MoveFileExW`, `DeleteFileW`, and bounded `FindFirstFileExW`/
  `FindNextFileW` enumeration with `FindClose` ownership.
- Protection/freeing: `CryptProtectData`, `CryptUnprotectData`, `LocalFree`,
  `CoTaskMemFree`, and the existing `CloseHandle` wrapper.

## Executable-trust observer boundary

Offline adapter status: the crate-private orchestrator fixes the exact call
policy and guarantees VERIFY/extract/CLOSE/post-CLOSE-reopen ordering across
ordinary errors and panics. A disconnected native adapter now implements the
process/HWND/creation binding, no-follow file and ancestor checks, normalized
volume-GUID path, NTFS/fixed-volume classification, redacted file identity,
complete-file SHA-256, SHA-2-only WinTrust provider extraction, bounded SPKI
DER hashing, and an exactly-once RAII CLOSE fallback. It is compiled but has
no production constructor call,
and automated tests never invoke the production observer or open an installed
executable. A bounded repository-fixture test now invokes WinTrust only with
the frozen cache-only/noninteractive policy and closes its state exactly once;
a separate in-memory test validates PE structure, certificate DER, and SPKI.
The adapter now also resolves only the source-static profile root kind through
the known-folder API, retains canonical no-follow root/ancestor handles, and
reduces the handle-derived relative executable relation to the existing digest.
It receives no expected component text and cannot promote an observation into
a reviewed profile. Reviewed target/signer/root values, hosted NTFS adversarial
qualification, a trusted timestamped provider fixture, and production wiring
remain activation blockers. Native code
avoids dynamic panic payloads because `catch_unwind` does not suppress the
process-wide panic hook.

A focused successor audit found that identity comparisons alone did not close
an ABA race around the path-only Windows version API. Discovery remains
non-disruptive, but the canonical verification file and every canonical parent
directory are now retained with read sharing only through VERIFY, CLOSE, and
the final identity reopen. Any pre-existing writer/deleter conflict refuses;
later write, delete, and rename opens remain excluded while the guards live.

### Path guards and process binding

The observer runs on the same joined mutation MTA worker and under the same
named mutex as final validation. It receives the already selected HWND, PID,
process creation time, and process handle. It must not perform a separate
best-effort scan.

1. Requery HWND ownership and process creation time.
2. Obtain the process image path through `QueryFullProcessImageNameW`. This is
   only a path query; it does not return the process's backing-file handle.
   Open the first no-follow candidate, canonicalize it, then open the
   verification candidate with read access and `FILE_SHARE_READ` only. Failure
   caused by an existing writer or deleter is a closed refusal.
3. Obtain the normalized final path from the file handle with
   `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)` using a
   bounded two-call buffer protocol.
4. Require an absolute volume-GUID path, derive its volume root, require
   `GetDriveTypeW(root) == DRIVE_FIXED`, and require the guarded file's
   `GetVolumeInformationByHandleW` filesystem name to be exactly `NTFS`
   (ASCII-case-insensitive). Unknown, ReFS, remote, removable, RAM-disk,
   CD-ROM, or unmounted results refuse.
5. While the first candidate is still held without write/delete sharing,
   query the process image path a second time, independently open that second
   candidate with the same share restrictions, and require exact canonical
   path and file-identity agreement. The evidence flag is named
   `process_image_path_requeried_and_guarded`; it never claims possession of a
   kernel process-image backing handle.
6. Open and inspect every existing path component with
   `FILE_FLAG_OPEN_REPARSE_POINT`; any reparse tag or inspection uncertainty
   refuses. Retain canonical parent handles with `FILE_SHARE_READ` only through
   verification and final reopen so a component cannot be renamed or replaced.
   Never follow an alternate path after such a refusal.
7. Derive a redacted `FileIdentity` from volume serial/file ID plus the
   already required process-creation binding. Compare the initial candidate,
   guarded verification candidate, second-query candidate, and post-VERIFY
   reopen identities exactly.
8. Hash every byte of the guarded file with SHA-256, then query the fixed file
   version while the canonical file and parent share
   guards remain live, immediately reopen and rebind the file identity, and
   require `FileVersion::KNOWN`. `GetFileVersionInfoW` is path-only; without
   those guards, before/after identities alone do not exclude replace/restore.

An NTFS experiment in the ignored repository target directory demonstrated
that a running synthetic PE can be source-renamed and replaced. A successor
qualification on Windows `10.0.26200.0` exercised all three timings: completed
before the first query, between the first query and guarded open, and after the
second query. Both path queries followed the renamed backing file, the shared
production requery helper refused the between-query impostor shape by exact
canonical-path/file-ID comparison, and the retained read-only guard denied the
after-query rename until drop.

The committed `scripts/qualify-windows-trust-assumptions.ps1` repeats the OS
contract with a byte-exact copy of the OS-supplied System32 `ping.exe` and
loopback only. A
Windows Rust unit test uses a copied exact ignored test-harness helper to call
the production requery function directly. Smart App Control on the current
host refused the newly linked unsigned Rust test executable before entry, so
that binary was compile/lint checked but the Rust parent test was not bypassed
or locally executed. The signed-PowerShell equivalent passed; the hosted
Windows test remains the independent executable result.

Microsoft documents `QueryFullProcessImageNameW` as returning a path, not an
atomic backing-file identity. Activation therefore still requires the three
timings to pass on every supported Windows/NTFS image, including the pinned
hosted runner. Supported builds must be limited to that matrix; a long-term
stronger design would retain a backing-file handle at launch or use another
documented kernel-backed identity mechanism.

Raw paths, file IDs, PIDs, HWNDs, volume identifiers, creation times, or target
digests never enter `UiError`, output, fixtures, or `Debug`.

The complete-file hash uses a bounded 64-KiB zeroizing buffer, rejects empty
or larger-than-512-MiB files, reads exactly the handle-reported length, and
rewinds the shared handle on every path before WinTrust consumes it. A
production profile must supply a source-static `ReviewedExecutableDigest` from
the accepted target bundle. The installer hash, the target's Authenticode PE
digest, and a runtime observation cannot satisfy this exact-byte pin.

### Authenticode and signer pin

Use `WINTRUST_ACTION_GENERIC_VERIFY_V2` with `WINTRUST_FILE_INFO` bound to the
opened file handle and its final path. Initialize every structure with
`Default`, then overwrite every required size/pointer field. Configure:

- `hwnd = INVALID_HANDLE_VALUE` and `dwUIChoice = WTD_UI_NONE`;
- `dwUnionChoice = WTD_CHOICE_FILE` only (never a catalog choice);
- `dwStateAction = WTD_STATEACTION_VERIFY`;
- `dwProvFlags` containing `WTD_CACHE_ONLY_URL_RETRIEVAL`,
  `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, and `WTD_DISABLE_MD2_MD4`;
- `fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN`; and
- `WINTRUST_SIGNATURE_SETTINGS.dwFlags = WSS_GET_SECONDARY_SIG_COUNT`; and
- `WINTRUST_SIGNATURE_SETTINGS.pCryptoPolicy` pointing to a live
  `CERT_STRONG_SIGN_PARA` with `CERT_STRONG_SIGN_OID_INFO_CHOICE` and
  `szOID_CERT_STRONG_SIGN_OS_1` (SHA-2 only).

Treat only the integer return value `0` as trusted. Missing cached revocation
evidence, provider/policy uncertainty, any secondary signature, catalog use,
or a null/inconsistent provider state refuses. There is no online fallback and
no retry with weaker flags.

While the verify state is live, use `WTHelperProvDataFromStateData`, require
exactly one primary signer, and obtain its first certificate with
`WTHelperGetProvSignerFromChain` and `WTHelperGetProvCertFromChain`. Pointers
are borrowed from WinTrust state and must never be freed individually or used
after close. DER-encode the leaf `SubjectPublicKeyInfo` with a bounded two-call
`CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, ...)`, hash the
exact returned byte count with SHA-256, and reduce it to `TrustDigest`. Do not
hash a display name or print certificate metadata.

The expected profile signer uses a distinct `ReviewedSignerDigest` constructor
that accepts only a source-embedded static 32-byte array. Runtime certificate
extraction produces only `TrustDigest`; it cannot be promoted to the expected
profile signer without an explicit source change and review.

Before consuming provider pointers, exact-check the still-live caller-owned
action, `WINTRUST_DATA`, file info, signature settings, policy flags, union,
file/path/settings pointers, and null-reserved fields. Provider
`pWintrustData`, `pgActionID`, and `pSigSettings` must point to those exact
allocations. The provider-owned state must also report `CPD_CHOICE_SIP`, the
exact caller low-word flags plus
`CPD_USE_NT5_CHAIN_FLAG`, and zero low-level/final errors.
`fRecallWithState` is independent catalog-state evidence and any true value is
catalog ambiguity. With zero secondary signatures, `dwVerifiedSigIndex` must
be zero. After exact primary cardinality one, the signer helper must return the
provider's exact `pasSigners` allocation and that signer's `dwError` must be
zero. The leaf helper must return the signer's exact `pasCertChain` allocation
and that provider certificate's `dwError` must also be zero before its context
or SPKI is consumed. Any drift is provider uncertainty and refuses before
certificate extraction. A private raw-pointer helper seam with one unsafe
extraction boundary exercises this complete provider-to-signer-to-leaf
traversal with retained Rust-owned structures and the committed public fixture
certificate, without calling WinTrust.
`WINTRUST_SIGNATURE_SETTINGS.dwFlags` is an in/out field: the input-mask bits
must still equal exactly `WSS_GET_SECONDARY_SIG_COUNT`, only documented
`WSS_OUT_*` bits may be added, and any other input or unknown bit refuses. This
distinction is covered by both pure drift tests and the real fixture call.

The production `CERT_STRONG_SIGN_PARA` constructor is also passed directly to
`CertIsStrongHashToSign` with no certificate. The Windows OS semantic test
requires MD5 and SHA-1 to return false and SHA-256 to return true. The same
contract passed through signed PowerShell on Windows `10.0.26200.0`; hosted
Rust execution is still required because local Smart App Control blocked the
new unsigned test binary before entry. This hash-only result does not replace
a trusted timestamped WinTrust/provider success fixture.

Positive trusted timestamped target qualification on Windows 11
`10.0.26200.9168` and hosted Windows Server 2022 `10.0.20348` established
provider flags `0x80003080`: the exact caller low word plus only the documented
`CPD_USE_NT5_CHAIN_FLAG`. The provider check requires that exact result. The
caller low-word `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT` and separate
`WTD_REVOKE_WHOLECHAIN` remain mandatory; CPD revocation high bits,
`CPD_RFC3161v21`, `CPD_RETURN_LOWER_QUALITY_CHAINS`, and unknown bits refuse.

Every `WTD_STATEACTION_VERIFY` attempt that produced state is paired with
exactly one `WTD_STATEACTION_CLOSE`, including trust failure, extraction
failure, and unwind. The close result cannot turn an earlier refusal into
success; a close failure is itself a refusal.

### Canonical installation-root pin

The profile must define a source-embedded signed-release-provenance root kind and exact
relative directory before any digest is populated. Version 1 admits only
`ProgramFilesX86`, `ProgramFiles64`, or `CurrentUserLocalAppData`, followed by
one to eight relative printable-ASCII components of at most 64 bytes each and
512 bytes total. Components reject slash/backslash, colon/ADS, Windows-reserved
punctuation, leading/trailing dot or space, dot segments, controls, and
reserved DOS device names (including names with extensions), and non-ASCII.
The public profile constructor accepts only static source components. ASCII
case is folded and every component is length-delimited before
domain-separated SHA-256. The runtime digest must use the same canonical final
handle-derived relation, never a user-specific absolute prefix or text learned
from the current installation.

The disconnected adapter now implements that runtime half. The profile exposes
only its reviewed `InstallRootKind`; it never exposes expected components to the
observer. The adapter maps the kind exactly to `FOLDERID_ProgramFilesX86`,
`FOLDERID_ProgramFilesX64`, or `FOLDERID_LocalAppData`, owns and frees every
Shell path allocation, and opens the source and canonical known-folder chains
without following reparse points. The canonical root handle and all ancestors
remain read-share-only through VERIFY, CLOSE, root revalidation, and executable
reopen.

The raw Shell result is moved into an owner before HRESULT interpretation.
A synthetic `CoTaskMemAlloc` test injects a counting matching release function
and proves one release for success, failure HRESULT, and later path refusal,
with no release for NULL. Raw decoder/construction/release calls retain explicit
`unsafe` allocation/string contracts. The test never calls
`SHGetKnownFolderPath`.

Both root and executable must be normalized volume-GUID paths on the same fixed
local volume. Their handle-derived prefix is compared with ASCII-only case
folding and exact non-ASCII units; the executable must be a strict descendant
at a component boundary. Only one to eight relative components enter temporary
zeroizing ASCII buffers. The existing codec rejects separators, ADS syntax,
dot/space ambiguity, reserved devices, nonportable bytes, and size overflow,
then emits only an evidence `TrustDigest`. Absolute/root/component text never
enters evidence, errors, formatting, or the reviewed profile type.

No implementation may inspect the current KakaoTalk installation and then
declare that observed value trusted. Production uses only the independently
reviewed x64 target whole-file digest/length, signer SPKI, root-relation digest,
and Windows qualification matrix recorded in
[`KAKAOTALK_X64_TRUST_PROFILE.md`](KAKAOTALK_X64_TRUST_PROFILE.md).

### Trust native API inventory

- Existing process/file APIs plus `CreateFileW`,
  `GetFinalPathNameByHandleW`, `GetFileInformationByHandleEx`,
  `GetVolumePathNameW`, `GetVolumeInformationByHandleW`, `GetDriveTypeW`,
  `GetFileSizeEx`, `SetFilePointerEx`, and `ReadFile`.
- `SHGetKnownFolderPath` with the three exact folder IDs above and
  `CoTaskMemFree` for every non-null returned allocation.
- `WinVerifyTrust`, `WINTRUST_DATA`, `WINTRUST_FILE_INFO`,
  `WINTRUST_SIGNATURE_SETTINGS`, `WTHelperProvDataFromStateData`,
  `WTHelperGetProvSignerFromChain`, and `WTHelperGetProvCertFromChain`.
- `CERT_STRONG_SIGN_PARA` with `szOID_CERT_STRONG_SIGN_OS_1`, plus
  `CryptEncodeObjectEx` with `X509_PUBLIC_KEY_INFO`; SHA-256 remains the
  existing Rust `sha2` implementation.

## Unsafe ownership table

| Resource | Owner | Required release/lifetime rule |
|---|---|---|
| Read-only COM apartment/cancellation state | probe worker | every successful `CoInitializeEx` is balanced by `CoUninitialize`; every successful cancellation enable receives one disable attempt while the apartment is live |
| Published probe thread ID | probe worker plus caller release channel | worker remains alive through the caller's single cancellation request; never persist or expose the ID |
| Known-folder `PWSTR` | Shell allocator | `CoTaskMemFree` exactly once |
| DPAPI output/description | Local allocator | zero sensitive span, then `LocalFree` exactly once |
| `GetSecurityInfo` descriptor | Local allocator | `LocalFree`; owner/DACL/ACE pointers borrow it |
| Process/candidate-file/directory handles | caller | existing RAII `CloseHandle` wrapper, exactly once; the queried path is not a process backing-file handle; candidate file/parent read-share guards outlive complete hashing, VERIFY, CLOSE, and final reopen |
| Token-information bytes | Rust allocation | pointer/range validation; drop after copied SID use |
| ACL/security descriptor | Rust-owned aligned storage | all embedded pointers remain valid through synchronous create call |
| WinTrust file/data/settings | stack owner | path/handle/settings outlive VERIFY and CLOSE calls |
| WinTrust provider/signer/cert pointers | WinTrust state | borrow only between VERIFY and CLOSE; never free individually |
| SPKI DER buffer | zeroizing Rust allocation | hash exact returned length, then zeroize |
| Ledger plaintext/correlation | fixed zeroizing storage | no formatting, serialization outside inner codec, or heap remnants |

No native pointer may be converted to a slice until null, alignment, count,
overflow, and containing-allocation bounds are validated. Catching an unwind
does not make leaked native ownership acceptable; each wrapper's `Drop` must
be independently correct.

## Required offline tests before activation

Ledger tests use only a newly created synthetic temporary directory and a
synthetic 48-byte record. Trust tests use fake evidence or a repository-owned
synthetic signed fixture whose provenance is separately reviewed; they never
open the installed KakaoTalk binary.

- feature-default and all-feature compile/lint;
- DPAPI exact round trip, wrong-user simulation seam, corrupt/truncated/
  oversized ciphertext, and UI-forbidden flag assertion;
- exact owner/DACL, inherited/permissive/wrong-owner, reparse directory/file,
  unexpected artifact, and network/removable-volume fake refusals;
- injected failure before/after create, write, flush, close, rename, reopen,
  compare, tombstone rename, and delete;
- restart after every injected point; only proven absence is automatically
  usable;
- two-process or injected-store contention with exactly one successful
  compare-and-replace;
- WinTrust zero/nonzero return handling, secondary-signature refusal,
  state-close on every path, null/malformed provider chain, and SPKI bound
  checks through a fake native adapter;
- fixed fixture/build-script/source/certificate/SPKI hashes, bounded PE32+
  security-directory and single-`WIN_CERTIFICATE` structure, and in-memory DER
  SPKI extraction without executing the fixture;
- an actual cache-only/noninteractive fixture VERIFY followed by exactly one
  CLOSE, accepting either trust result and opening no installed executable;
- signer/root/profile mismatch and identity/path replacement with zero UI
  calls and zero execution claims;
- exact discovery-versus-verification share modes; verification excludes write,
  delete, and rename sharing;
- `CertIsStrongHashToSign` hash-only semantics: MD5/SHA-1 false and SHA-256
  true under the exact production `CERT_STRONG_SIGN_PARA`;
- three NTFS process-image substitution timings using only a copied synthetic
  test harness in Rust and an OS-supplied loopback helper in the standalone
  OS qualification script;
- root-relation kind/component/order/case domain separation plus every
  ambiguous, nonportable, oversized, or absolute-like component refusal;
- exact known-folder GUID routing, same-volume strict-descendant derivation,
  sibling-prefix/volume/ADS/device/non-ASCII/depth refusal, and equality with
  the source-static reviewed relation digest without observed-value promotion;
- synthetic Shell allocation success/failure/path-refusal/NULL ownership with
  exact matching-release counts and no known-folder call;
- canaries absent from `Debug`, stdout, stderr, JSON, test names, and failure
  messages;
- pure modal owner-group classification plus snapshot suppression, with no
  `EnumWindows`, owner query, UIA call, or desktop enumeration in tests;
- saturated read-only timeout arithmetic, pre-readiness permit closure,
  cancellation HRESULT classification, and channel-coordinated proof that the
  synthetic worker is still pinned when cancellation is requested, with no
  native COM call.

Automated native/transaction tests must not run the product binary, enumerate
desktop windows, call the production native observer, or access KakaoTalk
files. Within the two general safe CI workflows, the only automated
product-binary executions are the fourteen exact help/version/usage parser
cases named in both workflows; broad or newly discovered CLI tests are
forbidden. The separate tag/manual release workflow remains outside this
claim. The separate artifact-qualification workflow may download and install
only the pinned public installer in fresh network-isolated runners while IFEO
prevents product execution; it uploads nothing. Synthetic trust qualification
may launch only its owned copied unit-test harness or OS-supplied loopback
helper. Live L10 and all later gates still require a fresh, explicitly named
approval.

## Implementation order

1. Land only the dependency-feature delta and compile checks.
2. Implement the DPAPI/ACL store behind an internal constructor that accepts
   an explicit synthetic base directory for tests. Complete.
3. Complete fault injection and implement the fixed LocalAppData constructor
   as a separate disconnected change. Both are complete.
4. Implement the trust observer behind a fakeable native adapter without a
   real KakaoTalk probe. Complete: the call policy and lifetime orchestration
   are wired to the accepted x64 profile while capability remains false.
5. Wire the production ledger through a side-effect-free lazy factory only
   after trust verification, with one-shot non-retryable initialization
   failure. Complete; only accepted trust can reach native location/file calls,
   and no live store has been opened.
6. Obtain signed release provenance, add a repository-owned reviewed fixture,
   independently audit the unsafe adapter, and review signer/root profile
   material. The fixture, reproducible build record, structural/SPKI test, and
   cache-only VERIFY/CLOSE test now exist as described in
   [`TRUST_PROVENANCE.md`](TRUST_PROVENANCE.md). Independent code review,
   hosted OS qualification, x64 production provenance, and exact source values
   are complete. The adapter has not been invoked against this user's live
   application; that first read-only session is L10 and requires fresh approval.
7. Only after every remaining selector and live gate passes may capability
   activation be considered in a separate change.

## Primary references

- [CoEnableCallCancellation](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coenablecallcancellation)
- [CoDisableCallCancellation](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-codisablecallcancellation)
- [CoCancelCall](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocancelcall)
- [Canceling Method Calls](https://learn.microsoft.com/en-us/windows/win32/com/canceling-method-calls)
- [EnumWindows](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows)
- [GetWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindow)
- [GetAncestor](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getancestor)
- [IsWindowVisible](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-iswindowvisible)
- [Window ownership overview](https://learn.microsoft.com/en-us/windows/win32/learnwin32/what-is-a-window-)
- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [GetFileVersionInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
- [WINTRUST_SIGNATURE_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
