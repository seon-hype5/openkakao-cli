# Windows executable-trust provenance plan

Date: 2026-08-17 KST

## Status and non-authorization

This document defines the evidence required before a KakaoTalk signer or
installation-root value may enter source. It contains no signer digest, install
path, selector, or capability activation. It does not authorize inspecting the
installed application, the downloaded installer, or any live KakaoTalk state.

Kakao's public notice identifies the Kakao corporate service page and Microsoft
Store as official Windows distribution channels. That proves where a future
release artifact may be acquired; it does not prove a signer SPKI, filesystem
root, relative install path, or version-specific UI profile. None of those
values may be inferred from this machine.

Official distribution reference:

- <https://pc.kakao.com/talk/notices/ko/2882?agent=win32>

## Production provenance bundle

A production trust profile requires one reviewed bundle per supported exact
file version. The bundle must be committed separately from native wiring and
contain only public, content-free evidence:

1. the official distribution URL and retrieval time;
2. the complete installer/package SHA-256 and byte length;
3. the exact executable version resource expected by the profile;
4. the leaf SubjectPublicKeyInfo SHA-256 derived independently by two reviewed
   tools from the signed release artifact;
5. signature cardinality, timestamp presence, and the certificate-chain policy
   used during review;
6. the installer-declared root kind and relative components, established from
   signed package metadata or reproducible installer behavior in a disposable
   test VM—not from an existing user installation;
7. the reviewer identities, review date, tool versions, and signed source tag
   that accepted the bundle; and
8. the previous profile it supersedes plus an explicit rollback decision.

Raw user-specific paths, volume IDs, certificate display names, serial numbers,
and installer telemetry do not belong in the bundle. The signer pin is the DER
leaf SPKI digest, not a mutable display name. The root is represented only by
`InstallRootKind` and the portable relative-component codec in
`executable_trust.rs`.

Two reviewers must reproduce the installer hash, version, signer SPKI, and root
relation independently. A disagreement, unavailable revocation evidence,
multiple embedded signatures, catalog-only signing, or an installer capable of
selecting more than one root blocks the profile.

## Canonical installation-root rule

No production root kind or components are selected now. A future profile may
choose exactly one of `ProgramFilesX86`, `ProgramFiles64`, or
`CurrentUserLocalAppData` only when the provenance bundle establishes it for
the same signed release.

At runtime the observer must:

1. resolve the selected known folder through the Windows known-folder API,
   never an environment variable;
2. open and retain no-follow handles for the known-folder root and every
   executable parent component;
3. require one fixed local volume-GUID namespace and exact handle-derived
   ancestry;
4. derive relative components only after subtracting the validated known-folder
   handle path from the validated executable handle path;
5. reject non-ASCII, alternate names, reparse points, mount-point changes,
   parent traversal, unexpected depth, or any component outside the reviewed
   relation; and
6. compute the existing version-1 relation digest without retaining or
   formatting the absolute prefix.

The expected relation is source-static. The observed relation is runtime
evidence. There is no API that can promote an observed absolute path into the
expected profile.

## Repository-owned signed fixture

The fixture validates native API shape and lifetime only; it can never provide
Kakao production pins. Its visible product, company, file, and certificate
names use `OPENKAKAO_SYNTHETIC_*` canaries.

The future fixture directory is fixed as:

```text
tests/fixtures/windows-authenticode/
  README.md
  LICENSE.txt
  fixture.exe
  fixture.exe.sha256
  signer.cer
  source/
  build-manifest.toml
```

`README.md` records source commit, compiler/linker versions, exact build and
signing commands, PE hash before and after signing, certificate DER hash, leaf
SPKI hash, signature count, and license. `build-manifest.toml` contains only
synthetic values and hashes. A dedicated test key must never be reused for a
release or accepted by a production profile. If a private fixture key is kept
for reproducibility, it is conspicuously test-only and the test profile remains
crate-private; otherwise the manifest records that the one-purpose key was
destroyed after signing.

Normal CI must not install a certificate, alter a trust store, contact a
revocation server, or weaken the production WinTrust policy. Because the
production policy is cache-only, a real fixture's zero/nonzero trust result may
depend on runner cache state. Therefore:

- deterministic success/refusal decisions remain covered by the fake native
  adapter;
- a repository fixture test may assert bounded parsing, state cleanup, pointer
  shape, SPKI extraction, and fail-closed handling without requiring trust
  success; and
- a positive real-WinTrust fixture run is a separate reviewed Windows image
  qualification, never a reason to add online fallback or weaker flags.

The fixture test must use its repository path only, run serially, produce no
certificate/path dump, and verify that every VERIFY state receives exactly one
CLOSE attempt. It must not enumerate windows or open any installed application.

## Review and activation gates

The following remain separate decisions:

1. accept the synthetic fixture provenance;
2. pass fixture-backed native lifetime tests on the pinned Windows image;
3. accept a Kakao release provenance bundle;
4. implement and audit runtime root-relation derivation;
5. connect the native observer while capability remains false;
6. complete target and submit-selector measurements under their own approvals;
7. only then consider capability activation.

Failure or staleness at any gate keeps `UnavailableExecutableTrust`, the absent
root digest, and `send_open_chat=false` unchanged.
