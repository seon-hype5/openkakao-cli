# Synthetic Windows Authenticode fixture

This directory contains a repository-owned, inert PE used only to validate
bounded Authenticode fixture structure. It does not access files, the network,
the registry, a certificate store, a window, or KakaoTalk. Tests never execute
`fixture.exe`.

The fixture is compiled from the adjacent C/resource source with MSVC, signed
once without a timestamp by a dedicated self-signed code-signing certificate,
and expected to be untrusted by Windows policy. The certificate public half is
committed as `signer.cer`; the generated PFX is removed, its byte buffer is
cleared, and the one-purpose key objects are disposed after signing. No private
key is retained by the repository. This signer must never appear in a
production trust profile.

Regenerate from the repository root on the reviewed Windows toolchain:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-windows-authenticode-fixture.ps1
```

`build-manifest.toml` records build-script and source hashes; unsigned PE,
signed PE, certificate, and leaf-SPKI hashes; signature/timestamp properties;
and exact compiler, linker, resource-compiler, SDK, and signing-tool versions.
Regeneration intentionally creates a new test key and therefore changes the
certificate, SPKI, signature, and final PE hashes. Review all changed hashes,
the embedded signature, and the Rust review-anchor constants before accepting a
replacement.

Normal tests first validate the manifest, hashes, bounded PE security directory,
single `WIN_CERTIFICATE`, certificate DER, and SPKI from committed bytes. A
separate Windows test opens only this fixture and performs one cache-only,
noninteractive WinTrust VERIFY/CLOSE lifetime without requiring trust success.
Neither test executes the PE or changes a certificate store.

The fixture supplies no evidence about Kakao's signer, installer, install root,
or UI profile. See [`../../../docs/windows-port/TRUST_PROVENANCE.md`](../../../docs/windows-port/TRUST_PROVENANCE.md).
