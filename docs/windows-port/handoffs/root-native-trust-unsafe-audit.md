# Root native executable-trust audit handoff

Date: 2026-08-17 KST

Status: focused source/API audit completed with one offline remediation;
fixture-backed and independent-review evidence remains incomplete

Reviewed predecessor: `aaac7be`. The atomic successor containing this handoff
must be reported externally because a commit cannot contain its own identifier.

## Audit scope

The review covered the disconnected executable-trust adapter, its pure decision
seam, WinTrust VERIFY/extract/CLOSE ownership, process/file identity binding,
canonical path handling, version-resource lookup, SPKI encoding, and the frozen
native activation contract. Microsoft API contracts were checked for
`CreateFileW`, `GetFinalPathNameByHandleW`, `GetFileVersionInfoW`,
`WinVerifyTrust`, `WINTRUST_DATA`, the WinTrust provider helpers, and
`CryptEncodeObjectEx`.

No native adapter constructor was called. No installed executable, KakaoTalk
path, signature, process, window, database, credential, or UI state was read.

## Finding and remediation

The adapter originally opened every executable and directory handle with read,
write, and delete sharing. File identities were compared before and after the
path-based version call, but `GetFileVersionInfoW` ignores its legacy handle
parameter and accepts only a filename. A replace/read/restore or in-place-write
race could therefore escape the identity comparisons.

The successor keeps discovery permissive, then opens the canonical verification
file and every canonical parent directory with only `FILE_SHARE_READ`. Windows
sharing rules make this open fail when an existing writer/deleter conflicts and
prevent later write/delete/rename opens until the guards drop. These guards
remain owned by `WindowsPathState` through WinTrust VERIFY, provider extraction,
CLOSE, and the final reopen/identity comparison. Existing no-follow, fixed-volume,
path, process-creation, and three-identity checks remain mandatory.

The implementation is still disconnected and returns no install-root digest.
The remediation changes no capability or reachable production behavior.

## Ownership findings

- boxed WinTrust action/file/settings/data allocations stay stable through the
  single CLOSE attempt;
- provider, signer, certificate, and nested certificate pointers are borrowed
  only while the state is live and are never freed individually;
- null, alignment, structure-size, cardinality, pointer-link, and SPKI length
  checks precede each bounded copy or hash;
- the WinTrust LONG result is accepted only when exactly zero;
- noninteractive HWND, `WTD_UI_NONE`, cache-only retrieval, exact revocation
  flags, embedded-file choice, and no-secondary-signature rules remain fixed;
- path/SPKI buffers are zeroizing and owned kernel handles close once; and
- a CLOSE error or panic cannot turn an earlier result into success.

## Verification

- formatting passed;
- focused all-feature native executable-trust tests: 18 passed;
- the new pure share-mode test proves verification omits write/delete sharing;
- no native file, trust, process, or UI API was called by the tests.

The full safe regression matrix is recorded in the integration handoff after it
runs for the successor commit.

## Remaining blockers

1. The native WinTrust/provider pointer path still lacks a repository-owned
   signed-fixture integration run.
2. A second reviewer must independently audit the unsafe pointer and lifetime
   reasoning against that fixture.
3. No production signer SPKI or installation-root relation has accepted
   provenance.
4. Runtime known-folder-to-executable relation derivation is not implemented;
   the native adapter still returns no root digest.
5. Target/submit selectors and all live gates remain separately blocked.

[`../TRUST_PROVENANCE.md`](../TRUST_PROVENANCE.md) freezes the fixture and
production-provenance acceptance plan without supplying any production value.
