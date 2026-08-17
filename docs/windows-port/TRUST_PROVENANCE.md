# Windows executable-trust provenance plan

Date: 2026-08-17 KST

## Status and non-authorization

This document defines the evidence required before a KakaoTalk target
executable digest, signer, or installation-root value may enter source. The
accepted x64 bundle is recorded in
[`KAKAOTALK_X64_TRUST_PROFILE.md`](KAKAOTALK_X64_TRUST_PROFILE.md). Its public
values may be wired separately while capability remains false; it does not
authorize inspecting a live KakaoTalk UI or activating message submission.

[Kakao's public notice](https://pc.kakao.com/talk/notices/ko/2882?agent=win32)
identifies the Kakao corporate service page and Microsoft Store as official
Windows distribution channels. That proves where a release artifact may be
acquired; it does not prove a runtime signer SPKI, filesystem root, relative
install path, exact target bytes, or version-specific UI profile.

The independently reproduced public 26.7 x86/x64 installer snapshot is in
[`handoffs/root-public-kakao-installer-provenance.md`](handoffs/root-public-kakao-installer-provenance.md).
The x64 architecture and exact runtime profile were subsequently selected by
the accepted bundle above. x86 remains unselected.

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
   installation, plus explicit observation of root overrides and proof that
   every non-selected root/relation fails the source-static runtime profile;
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

Two independent reviewed reproductions must reproduce the installer hash,
target whole-file hash and length, target version/machine, target signer SPKI,
signature policy, and root relation. A disagreement, unavailable revocation
evidence, unexpected signature cardinality, catalog-only signing, weak digest,
or inability to make every non-selected installer root fail closed blocks the
profile. Merely supporting a documented installer override does not weaken an
exact known-folder/relation runtime pin.

## Canonical installation-root and process-image rule

The accepted x64 profile selects `ProgramFiles64` and exact relative
components `Kakao`, `KakaoTalk`, `KakaoTalk.exe`. No other root or x86 profile
is selected.

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
contract. Independent review of the two-query/guard protocol is complete, and
a structured signed-PowerShell qualification passed before/between/after-query
replacement on Windows `10.0.26200.0`. The committed
[`qualify-windows-trust-assumptions.ps1`](../../scripts/qualify-windows-trust-assumptions.ps1)
and a Rust test now gate the same assumption. Production wiring remains
blocked until the test also passes on the pinned hosted image and every exact
supported Windows/NTFS build. Merely repeating a path query without the held
no-delete candidate is not sufficient.

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
wrong-choice, or wrong-OID crypto-policy state without calling WinTrust. The
production policy now reaches
[`CertIsStrongHashToSign`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certisstronghashtosign)
with no certificate;
the signed-PowerShell equivalent on Windows `10.0.26200.0` rejected MD5/SHA-1
and accepted SHA-256. Local Smart App Control blocked the newly linked unsigned
Rust test before entry, so its hosted execution remains required. This
hash-only OS result does not prove trusted timestamped WinTrust acceptance of
the reviewed target.
The positive trusted timestamped x64 qualification recorded
`CRYPT_PROVIDER_DATA.dwProvFlags=0x80003080` on Windows 11 and hosted Windows
Server 2022. The low word exactly preserved the caller flags; the only high
bit was the SDK-documented `CPD_USE_NT5_CHAIN_FLAG`. The accepted provider
policy requires that exact value. CPD revocation high bits, RFC3161,
lower-quality-chain, and unknown bits remain activation refusals.

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

The following are separate decisions:

1. accept the synthetic fixture provenance and reproduce clean pinned-Windows
   structure/lifetime tests;
2. retain the completed independent audit of native unsafe, strong-policy,
   hashing, and process-image revalidation paths;
3. reproduce the now-automated NTFS rename/replacement and strong-hash cases on
   the supported hosted image and every declared Windows build;
4. accept one architecture-specific Kakao target provenance bundle;
5. independently audit runtime root-relation derivation;
6. connect the native observer while capability remains false;
7. complete target and submit-selector measurements under their own approvals;
8. only then consider capability activation.

Items 1–6 are complete for the accepted x64 profile. Failure or staleness in
the runtime observer refuses before UI inspection; items 7–8 remain incomplete
and keep `send_open_chat=false`. Rollback removes the accepted source values and
restores `UnavailableExecutableTrust` rather than weakening any match.
