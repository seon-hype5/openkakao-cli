# Windows executable-trust provenance plan

Date: 2026-08-17 KST

## Status and non-authorization

This document defines the evidence required before a KakaoTalk target
executable digest, signer, or installation-root value may enter source. It
contains no production target digest, signer digest, install path, selector,
or capability activation. Public installer acquisition is recorded separately;
it does not authorize inspecting an installed application or live KakaoTalk
state.

[Kakao's public notice](https://pc.kakao.com/talk/notices/ko/2882?agent=win32)
identifies the Kakao corporate service page and Microsoft Store as official
Windows distribution channels. That proves where a release artifact may be
acquired; it does not prove a runtime signer SPKI, filesystem root, relative
install path, exact target bytes, or version-specific UI profile.

The independently reproduced public 26.7 x86/x64 installer snapshot is in
[`handoffs/root-public-kakao-installer-provenance.md`](handoffs/root-public-kakao-installer-provenance.md).
Those hashes are preliminary installer acquisition evidence only. No
architecture or runtime profile is selected.

## Production provenance bundle

A production trust profile requires one reviewed bundle per exact target
executable and architecture. The bundle must be committed separately from
native wiring and contain only public, non-user evidence:

1. a schema/profile identifier plus exact `stable`/`beta` channel and
   `x86`/`x64` architecture;
2. the official distribution URL, UTC retrieval time, response metadata, and
   any immutable public metadata snapshot used only as corroboration;
3. the complete installer/package SHA-256 and byte length;
4. the target executable filename, PE machine, exact file/product version,
   byte length, digest kind `whole-file-sha256-v1`, and complete-file SHA-256;
5. the **target executable** leaf SubjectPublicKeyInfo SHA-256 derived
   independently by two reviewed tools; installer signer evidence is separate
   and can never satisfy this item;
6. the target's embedded primary/secondary signature cardinality,
   Authenticode content-digest algorithm, timestamp type/presence/semantics,
   and exact `szOID_CERT_STRONG_SIGN_OS_1` SHA-2-only policy result;
7. the complete offline/no-UI/cache-only/whole-chain-excluding-root WinTrust
   inputs and provider-owned outputs used during review;
8. one exact known-folder root kind and portable relative components,
   established from signed package metadata or reproducible installer behavior
   in a disposable network-isolated test VM, never from an existing user
   installation, plus proof that root overrides cannot select another root;
9. reviewer identities, review date, independent tool versions, acceptance
   source tag, and a one-to-one UI-profile identifier; and
10. the previous profile it supersedes plus an explicit rollback decision.

Raw user-specific paths, volume IDs, certificate display names, serial numbers,
and installer telemetry do not belong in the bundle. The signer pin is the DER
leaf SPKI digest, not a mutable display name. The exact release pin is the
complete target file SHA-256, not an Authenticode PE digest: Authenticode
intentionally excludes the checksum, certificate table, and some trailing
regions and therefore cannot by itself identify every reviewed byte. The root
is represented only by `InstallRootKind` and the portable relative-component
codec in `executable_trust.rs`.

Two reviewers must reproduce the installer hash, target whole-file hash and
length, target version/machine, target signer SPKI, signature policy, and root
relation independently. A disagreement, unavailable revocation evidence,
unexpected signature cardinality, catalog-only signing, weak digest, or an
installer capable of selecting more than one root blocks the profile.

## Canonical installation-root and process-image rule

No production root kind or components are selected now. A future profile may
choose exactly one of `ProgramFilesX86`, `ProgramFiles64`, or
`CurrentUserLocalAppData` only when the same architecture-specific bundle
establishes it.

At runtime the observer must:

1. resolve the selected known folder through the Windows known-folder API,
   never an environment variable;
2. open and retain no-follow handles for the known-folder root and every
   executable parent component;
3. require one NTFS fixed local volume-GUID namespace and exact handle-derived
   ancestry; ReFS, FAT, network, removable, and unknown filesystems refuse;
4. derive relative components only after subtracting the validated known-folder
   handle path from the validated executable handle path;
5. reject non-ASCII, alternate names, reparse points, mount-point changes,
   parent traversal, unexpected depth, or any component outside the reviewed
   relation; and
6. compute the version-1 relation digest without retaining or formatting the
   absolute prefix.

`QueryFullProcessImageNameW` returns a path, not a caller-owned backing-file
handle. A synthetic NTFS experiment proved that an executing PE can be source
renamed and replaced while it keeps running; both `QueryFullProcessImageNameW`
and `GetMappedFileNameW` then reported the renamed backing filename. The native
adapter therefore opens the first candidate without write/delete sharing,
queries the process image again while that lock is held, independently opens
the second candidate with the same guards, and requires exact canonical path
and file-identity agreement. If the first path was replaced during the race,
the held impostor cannot be removed and the second process query resolves the
renamed backing file, so the comparison refuses.

That observed NTFS rename behavior is not a documented kernel identity
contract. Production wiring remains blocked until the adversarial rename and
replacement test is reproduced on the exact supported Windows/NTFS image and
the two-query/guard protocol receives independent review. Merely repeating a
path query without the held no-delete candidate is not sufficient.

The expected root relation is source-static. Observed paths and components are
evidence only; no API can promote them into a profile. Automated tests use
synthetic volume-GUID paths and CoTaskMem buffers and never resolve a real
executable-trust known folder.

## Exact target-byte and strong-signature binding

`ReviewedExecutableDigest` accepts only a source-static 32-byte SHA-256 from an
accepted bundle. Runtime evidence streams the complete guarded target file
through a zeroizing 64-KiB buffer, rejects zero or over-512-MiB files, and
restores the shared WinTrust file pointer on every success or failure path. The
verification handle excludes write/delete sharing for the complete hash,
WinTrust VERIFY/extract/CLOSE, and final identity-reopen lifetime. Version,
target digest, target leaf SPKI, root relation, and every initial/requeried/
verification/reopen file identity must match independently.

`WINTRUST_SIGNATURE_SETTINGS.pCryptoPolicy` points to a stable boxed
`CERT_STRONG_SIGN_PARA` using `CERT_STRONG_SIGN_OID_INFO_CHOICE` and
`szOID_CERT_STRONG_SIGN_OS_1`. Microsoft documents that policy as SHA-2-only,
excluding MD2, MD4, MD5, and SHA-1 and enforcing minimum RSA/ECDSA key sizes.
The exact policy allocation and NUL-terminated OID pointer remain live and
unchanged through the same VERIFY/CLOSE state. See the Microsoft documentation
for [`WINTRUST_SIGNATURE_SETTINGS`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings)
and [`CERT_STRONG_SIGN_PARA`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para).

Pure tests refuse a missing/wrong complete-file digest or absent strong-policy
evidence. Native inert-state tests refuse null, substituted, wrong-size,
wrong-choice, or wrong-OID crypto-policy state without calling WinTrust. Before
activation, an isolated Windows qualification must additionally prove OS
semantic rejection of MD5/SHA-1 and acceptance of the reviewed SHA-2 target;
synthetic pointer tests alone do not establish operating-system behavior.
The same positive trusted timestamped qualification must record
`CRYPT_PROVIDER_DATA.dwProvFlags`: the low word must preserve the caller flags,
the revocation high-word choice must remain chain-excluding-root, and any
RFC3161/lower-quality-chain bit must receive an explicit reviewed policy.
Unknown bits and `CPD_USE_NT5_CHAIN_FLAG` are activation refusals.

## Repository-owned signed fixture

The repository contains an inert synthetic PE and public certificate under
`tests/fixtures/windows-authenticode`. They validate bounded PE/signature
structure, complete-file hashing, SPKI encoding, strong-policy pointer
lifetime, and WinTrust VERIFY/CLOSE state. They can never provide Kakao pins.

The canonical build script creates a one-purpose in-memory 2048-bit RSA key and
self-signed code-signing certificate, builds the PE from adjacent source, signs
once with SHA-256 and no timestamp, stores the PFX only below ignored
`.target`, then removes the PFX, clears its bytes, and disposes the key. Only
the public certificate is retained. The manifest records source/tool hashes,
unsigned/signed PE hashes, public certificate/SPKI hashes, signature count,
timestamp status, and tool versions.

Normal CI never installs a certificate, changes a trust store, contacts a
revocation server, or executes the fixture. One structural test parses only
committed bytes. One Windows test opens only that file with no-follow guards,
checks its complete-file SHA-256 through the guarded handle, calls WinTrust
with no UI, cache-only retrieval, whole-chain revocation excluding root, and
the SHA-2-only strong-sign policy, accepts trust or refusal, and attempts CLOSE
exactly once. A retained synthetic provider chain exercises exact
provider-to-primary-signer-to-leaf pointer identity, SPKI extraction, and
nested error refusal without WinTrust.

The fixture proves local structure and lifetime only. A positive trusted,
timestamped provider-path qualification on a clean pinned Windows image,
explicit weak-signature rejection, and the real target bundle remain separate
activation gates.

## Review and activation gates

The following remain separate decisions:

1. accept the synthetic fixture provenance and reproduce clean pinned-Windows
   structure/lifetime tests;
2. independently audit the native unsafe, strong-policy, hashing, and
   process-image revalidation paths;
3. reproduce the NTFS rename/replacement adversarial case on the supported
   hosted image and confirm fail-closed behavior;
4. accept one architecture-specific Kakao target provenance bundle;
5. independently audit runtime root-relation derivation;
6. connect the native observer while capability remains false;
7. complete target and submit-selector measurements under their own approvals;
8. only then consider capability activation.

Failure or staleness at any gate keeps `UnavailableExecutableTrust`, every
production target/signer/root value absent, and `send_open_chat=false`.
