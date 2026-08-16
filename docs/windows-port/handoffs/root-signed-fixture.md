# Root signed Authenticode fixture handoff

Date: 2026-08-17 KST

Status: repository fixture and local offline WinTrust lifetime coverage
complete; independent unsafe review and production provenance remain blocked

Reviewed predecessor: `27f50c8`. The atomic successor containing this handoff
must be reported externally because a commit cannot contain its own identifier.

## Delivered boundary

- Added an inert, repository-owned PE built from committed C/resource source.
- Signed it exactly once without a timestamp using a dedicated self-signed
  code-signing certificate.
- Retained only the public certificate; the temporary PFX was removed, its byte
  buffer cleared, and the in-memory certificate/key disposed; the repository
  retains no private key.
- Recorded build-script/source/unsigned/signed/certificate/SPKI hashes and exact
  compiler, linker, resource compiler, SDK, and signing-tool versions.
- Added an embedded-byte test for the manifest, hashes, bounded PE32+ security
  directory, one `WIN_CERTIFICATE`, DER parsing, and exact SPKI encoding.
- Added a repository-path test that retains no-follow fixed-volume guards,
  calls WinTrust only with cache-only/noninteractive production flags, accepts
  either trust result, and makes exactly one native CLOSE attempt.

The fixture is never executed. No certificate is installed or enumerated, no
trust store is changed, no network fallback or UI is permitted, and no
installed application or KakaoTalk state is opened.

## Changed files

- `.gitattributes` pins fixture text inputs to LF and PE/certificate artifacts
  as binary.
- `scripts/build-windows-authenticode-fixture.ps1` owns generation, signing,
  validation, hashing, and private-key non-retention.
- `tests/fixtures/windows-authenticode/` contains source, license, manifest,
  signed PE, checksum, and public certificate.
- `src/platform/windows/executable_trust_native.rs` contains the two fixture
  tests and WinTrust in/out-flag correction.
- `.github/workflows/windows.yml` and current Windows-port contract, security,
  provenance, decision, CI, and handoff documents record the new boundary.

## Native finding and remediation

The first real fixture VERIFY showed that WinTrust adds documented
`WSS_OUT_*` result bits to `WINTRUST_SIGNATURE_SETTINGS.dwFlags`. The prior
byte-for-byte invariant therefore refused every real result before provider
extraction. The successor now requires the input-mask bits to remain exactly
`WSS_GET_SECONDARY_SIG_COUNT`, permits only the documented output mask, and
rejects changed input or unknown bits. Pure adversarial tests cover all three
cases, and the real fixture call covers the platform behavior.

## Verification

The full safe matrix is recorded in [`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md).
Default library tests pass 173/173; all-feature and release Windows tests pass
99/99; binary tests pass 177/177. Focused fixture structure/SPKI, offline
VERIFY/CLOSE, and flag-drift tests pass. Clippy with all targets/features and
warnings denied, default/all-feature debug and release builds, compatibility
suites, 14 exact safe CLI cases, Markdown links, action pins, fixture hashes,
and final diff checks all pass. No fixture or product executable was launched.

Skipped by design: the process/HWND-bound production observer, any installed
executable, positive trust-store qualification, live L10, every L20-L40
mutation gate, legacy local-state/credential CLI tests, and product commands.

## Remaining blockers

1. A second reviewer must independently audit the unsafe provider-pointer and
   state-lifetime reasoning against the committed fixture.
2. A clean pinned Windows CI image must reproduce the fixture and regression
   gates; trust success is not required.
3. No Kakao signer SPKI, signed release hash, or installation-root relation has
   accepted provenance.
4. Runtime known-folder-to-executable relation derivation is not implemented;
   the native adapter still returns no root digest and has no production caller.
5. Target/submit selectors and all live gates remain separately blocked.

[`../TRUST_PROVENANCE.md`](../TRUST_PROVENANCE.md) defines the evidence and
review order. This handoff supplies no live permission, production pin, path,
selector, or capability activation.
