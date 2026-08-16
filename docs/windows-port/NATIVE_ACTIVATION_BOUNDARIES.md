# Windows native activation boundaries

Status: accepted implementation inventory; no live authorization

Binding baseline: `windows = 0.62.2`
Applies only behind the default-off `windows-ui-write` feature

## Purpose and non-authorization

This document freezes the minimum Windows namespaces, native call ordering,
ownership rules, and synthetic-test seams for the two activation boundaries:

- the trust-ordered lazy production ledger; and
- `UnavailableExecutableTrust`.

It does not configure a signer or installation-root digest, advertise a send
capability, inspect the installed KakaoTalk executable, observe a KakaoTalk
window, mutate a composer, or authorize any live gate. Implementing these
boundaries must leave all existing activation barriers in place until their
separate evidence is reviewed.

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
| `Win32_UI_Shell` | `FOLDERID_LocalAppData` and `SHGetKnownFolderPath` |

No new crate is required. `sha2`, `rand`, and `zeroize` are already direct
dependencies. `Win32_Security_Cryptography_UI` is deliberately excluded. No
registry, networking, credential, process-memory, or UI-input namespace is
part of this inventory.

This list was checked against the locally resolved generated source for
`windows` 0.62.2. In that version, `WTHelperProvDataFromStateData` and
`WTHelperGetProvSignerFromChain` are gated by both Catalog and Sip, while
`WTHelperGetProvCertFromChain` is gated by Cryptography.

## Durable ledger boundary

Offline location status: the fixed current-user known-folder, source and
canonical parent-chain no-reparse, volume-GUID/fixed-local,
retained-base-handle, and fixed child-directory protocol below is implemented.
`NativeMutationPort` references it only through a lazy factory. Port
construction performs no I/O, transaction ordering checks executable trust
before the first ledger method, and current production trust always refuses.
Consequently tests and reachable production flows never call
`SHGetKnownFolderPath` or write real LocalAppData.

The factory is consumed before its first open attempt. An error or unwind can
never trigger an automatic second attempt in the same transaction object and
maps to fixed `SubmissionUncertain` / `windows_ledger_state_uncertain` with
`retry_safe=false`.

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
volume-GUID path, fixed-volume classification, content-free file identity,
WinTrust provider extraction, bounded SPKI DER hashing, and an exactly-once
RAII CLOSE fallback. It is compiled but has no production constructor call,
and automated tests never invoke WinTrust or open an installed executable.
The adapter intentionally emits no installation-root digest, so even direct
construction cannot satisfy the pure trust verifier. Reviewed signer and root
profile material, fixture-backed API integration evidence, independent unsafe
review, and production wiring remain activation blockers. Native code avoids
dynamic panic payloads because `catch_unwind` does not suppress the
process-wide panic hook.

### Handle and process binding

The observer runs on the same joined mutation MTA worker and under the same
named mutex as final validation. It receives the already selected HWND, PID,
process creation time, and process handle. It must not perform a separate
best-effort scan.

1. Requery HWND ownership and process creation time.
2. Obtain the process image path through the opened process handle, then open
   that file with read/data and attribute access plus read/write/delete sharing
   so the running application is not disturbed.
3. Obtain the normalized final path from the file handle with
   `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)` using a
   bounded two-call buffer protocol.
4. Require an absolute volume-GUID path, derive its volume root, and require
   `GetDriveTypeW(root) == DRIVE_FIXED`. Unknown, remote, removable, RAM-disk,
   CD-ROM, or unmounted results refuse.
5. Open and inspect every existing path component with
   `FILE_FLAG_OPEN_REPARSE_POINT`; any reparse tag or inspection uncertainty
   refuses. Never follow an alternate path after such a refusal.
6. Derive a content-free `FileIdentity` from volume serial/file ID plus the
   already required process-creation binding. Compare the process-bound,
   verification-handle, and immediately reopened identities exactly.
7. Query the existing fixed file version from the same verified handle/path
   boundary and require `FileVersion::KNOWN`.

Raw paths, file IDs, PIDs, HWNDs, volume identifiers, or creation times never
enter `UiError`, output, fixtures, or `Debug`.

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
- `WINTRUST_SIGNATURE_SETTINGS.dwFlags = WSS_GET_SECONDARY_SIG_COUNT`.

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
allocations. With zero secondary signatures, `dwVerifiedSigIndex` must be zero.
Any drift is provider uncertainty and refuses before certificate extraction.

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

No implementation may inspect the current KakaoTalk installation and then
declare that observed value trusted. Until an independently reviewed signer
SPKI digest and root-relation digest exist, production continues to use
`UnavailableExecutableTrust`.

### Trust native API inventory

- Existing process/file APIs plus `CreateFileW`,
  `GetFinalPathNameByHandleW`, `GetFileInformationByHandleEx`,
  `GetVolumePathNameW`, and `GetDriveTypeW`.
- `WinVerifyTrust`, `WINTRUST_DATA`, `WINTRUST_FILE_INFO`,
  `WINTRUST_SIGNATURE_SETTINGS`, `WTHelperProvDataFromStateData`,
  `WTHelperGetProvSignerFromChain`, and `WTHelperGetProvCertFromChain`.
- `CryptEncodeObjectEx` with `X509_PUBLIC_KEY_INFO`; SHA-256 remains the
  existing Rust `sha2` implementation.

## Unsafe ownership table

| Resource | Owner | Required release/lifetime rule |
|---|---|---|
| Known-folder `PWSTR` | Shell allocator | `CoTaskMemFree` exactly once |
| DPAPI output/description | Local allocator | zero sensitive span, then `LocalFree` exactly once |
| `GetSecurityInfo` descriptor | Local allocator | `LocalFree`; owner/DACL/ACE pointers borrow it |
| Process/file/directory handles | caller | existing RAII `CloseHandle` wrapper, exactly once |
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
- signer/root/profile mismatch and identity/path replacement with zero UI
  calls and zero execution claims; and
- root-relation kind/component/order/case domain separation plus every
  ambiguous, nonportable, oversized, or absolute-like component refusal; and
- canaries absent from `Debug`, stdout, stderr, JSON, test names, and failure
  messages.

Automated tests must not run the product binary, enumerate desktop windows,
call the production native observer, or access KakaoTalk files. Live L10 and
all later gates still require a fresh, explicitly named approval.

## Implementation order

1. Land only the dependency-feature delta and compile checks.
2. Implement the DPAPI/ACL store behind an internal constructor that accepts
   an explicit synthetic base directory for tests. Complete.
3. Complete fault injection and implement the fixed LocalAppData constructor
   as a separate disconnected change. Both are complete.
4. Implement the trust observer behind a fakeable native adapter without a
   real KakaoTalk probe; keep production wiring unavailable. The call-policy,
   state-lifetime orchestration, and disconnected native API adapter are
   complete; no real executable was opened or verified.
5. Wire the production ledger through a side-effect-free lazy factory only
   after trust verification, with one-shot non-retryable initialization
   failure. Complete; current trust refusal leaves all native location/file
   calls unreachable and no live store has been opened.
6. Obtain signed release provenance, add a repository-owned reviewed fixture,
   independently audit the unsafe adapter, and review signer/root profile
   material. The current adapter deliberately returns no root digest.
7. Only after every remaining selector and live gate passes may capability
   activation be considered in a separate change.

## Primary references

- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
- [WINTRUST_SIGNATURE_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
