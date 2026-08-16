# Root handoff: independent CI and executable-trust safety review

Date: 2026-08-17 KST

## Outcome

Three independent read-only reviews covered branch-push CI, public release
provenance, and the disconnected native executable-trust boundary. The current
working change is suitable to merge only while production remains wired to
`UnavailableExecutableTrust` and `send_open_chat=false`. It is not an
activation decision.

The CI review found that the legacy cross-platform workflow would have run a
broad test target, including three local-state diagnostic cases, whenever the
integration branch was pushed. It also used mutable action tags, persisted
checkout credentials, and had no explicit permissions. The Windows CLI test
had one extra product subprocess beyond the fourteen approved parser cases.
Both non-release workflows now use read-only permissions, nonpersistent
checkout, full-SHA actions, a pinned Rust toolchain, locked dependencies,
explicit synthetic suites, and the same exact fourteen-case parser allowlist.
macOS builds but never executes the product. The redaction assertion moved to
a pure binary-unit helper, leaving `windows_cli` fully in-memory.

The unsafe review found two trust gaps in the previous profile: it pinned only
version/signer/root rather than the complete reviewed target bytes, and its
WinTrust signature settings supplied no strong-sign policy. The profile now
requires a source-static `whole-file-sha256-v1` target digest. Native evidence
hashes the complete guarded file and requires exact agreement. WinTrust now
retains a `CERT_STRONG_SIGN_PARA` selecting
`szOID_CERT_STRONG_SIGN_OS_1` through VERIFY/CLOSE, and both pure and inert
tests refuse missing, weak, or pointer-drift evidence.

## NTFS rename/replacement finding

A bounded experiment compiled and launched only a harmless synthetic sleep PE
under ignored `.target`. While it was running, the source file was renamed and
a different synthetic PE was copied to the original path. NTFS allowed the
rename; the process continued, and both process-image path queries reported the
renamed backing filename on this host. The process was then stopped and the
temporary object accidentally emitted at repository root was removed. No
KakaoTalk process, file, UI, credential, or user data was touched.

The adapter now accepts only NTFS on a fixed local volume, holds the first path
candidate without write/delete sharing, queries the process image path again,
independently guards the second candidate, and requires exact canonical path
and file-ID agreement. Evidence names describe this as a guarded path requery;
they do not claim a process backing-file handle.

Independent review agreed that this closes rename/replacement during the
observation sequence. It does not prove that every Windows build returns a
fresh renamed path, because `QueryFullProcessImageNameW` documents a path but
not an atomic backing-file identity. Activation therefore remains blocked
until before-query, between-query, and after-query substitutions pass on every
supported Windows/NTFS image.

## Remaining activation gates

- Accept one architecture-specific bundle containing installer corroboration,
  target whole-file length/SHA-256, PE machine/version, target leaf SPKI,
  exact root relation, signature algorithm/timestamp semantics, and two-reviewer
  reproduction. Public installer facts alone are insufficient.
- On an isolated pinned Windows image, prove SHA-2 acceptance and MD5/SHA-1
  rejection under the exact `CERT_STRONG_SIGN_PARA` policy.
- Use a trusted timestamped positive fixture to qualify the real provider
  traversal and `CRYPT_PROVIDER_DATA.dwProvFlags`. The current full-DWORD exact
  comparison is fail-closed but may reject a legitimate RFC3161 high-word bit.
- Run the NTFS adversarial timing matrix and restrict supported Windows builds
  to the passing matrix, or replace the path protocol with a documented
  kernel-backed image identity.
- Keep native production construction disconnected until a separate wiring
  review, then measure target and submit selectors under their own approval.

No live observation, UI mutation, message send, installer execution, trust-
store change, credential access, or production executable launch occurred in
this review.
