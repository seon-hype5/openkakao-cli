# Root handoff: offline executable-trust scaffold

## Outcome

This change implements the content-free decision portion of the Windows
executable signer and canonical-installation-root boundary. It performs no
native path, file, certificate, catalog, or network operation and does not
activate Windows writes.

The pure verifier requires all of these facts at once:

- the final path came from an opened process-image handle, not text;
- it was independently classified as absolute, normalized, local, and on a
  fixed volume;
- every relevant component was proven free of reparse points;
- the handle is bound to the expected process and creation time;
- process, verified, and reopened file identities are all present and equal;
- the exact supported file version is unchanged;
- Authenticode returned trusted with UI forbidden and cache-only URL
  retrieval;
- catalog selection is unambiguous;
- exactly one signer matches an exact reviewed digest; and
- the canonical install root matches a distinct exact reviewed digest.

Zero, missing, unknown, changed, ambiguous, network, removable, reparse, or
mismatched evidence fails closed. There is no path normalization fallback,
generic "signed is enough" rule, online revocation fallback, or signer/root
guess.

## Privacy properties

The seam contains no path string, volume label, certificate subject, account,
publisher name, serial number, file ID, PID, HWND, UIA identifier, message,
target label, KakaoTalk data, or credential. File identities and expected
signer/root values are opaque 32-byte digests with redacted `Debug` output.
Evidence `Debug` exposes only bounded enums, booleans, presence, and
zero/one/multiple cardinality.

No trust evidence type implements serialization. Unknown error inputs map to
fixed allowlisted operation codes before Windows CLI rendering.

## Production boundary

`MutationPort` now requires an `ExecutableTrustBoundary` before ledger
preflight or any UI observation. The native port embeds
`UnavailableExecutableTrust`, so an all-feature build returns
`windows_executable_trust_unavailable` before:

- durable-ledger access;
- UIA observation or `CurrentValue`;
- final SetValue/Invoke preflight;
- the one-shot execution claim; or
- any `SetValue`/`Invoke` call.

The existing `UnavailableLedger`, false write capability, default-off build
feature/configuration, false native target identity, and unconfigured submit
selector remain independent later barriers.

## Synthetic coverage

Tests cover exact acceptance and independent refusals for text/unknown path
source, non-normalized path, network/removable/unknown volume, present/unknown
reparse state, missing process/creation binding, absent/changed three-way file
identity, version mismatch, untrusted/unknown signature, UI-enabled trust,
network-enabled retrieval, catalog ambiguity, zero/multiple/wrong signer,
wrong root, zero/colliding profile digests, and unavailable production trust.

The transaction test proves trust refusal occurs before ledger/UI/claim and
that accepted synthetic trust preserves the previously verified ledger,
preflight, one-shot, SetValue, restore, and sole-Invoke ordering.

## Verification

All Rust commands used the isolated `.target/wave2-root` directory.

- formatting and warnings-denied all-target/all-feature Clippy: passed;
- default library tests: 138 passed;
- all-feature Windows unit subtree: 57 passed in debug and release;
- binary unit tests: 177 passed;
- Windows backend/policy/CLI integration targets: 2 + 23 + 2 passed;
- all-feature Windows backend contract target: 2 passed;
- exact safe CLI compatibility allowlist: 14 passed;
- compatibility targets: 23 + 13 + 12 + 13 + 20 passed;
- default/all-feature debug and release builds: passed;
- Windows-port Markdown: 27 files, 18 local links, 0 broken; and
- workflow static audit: 3 full 40-hex action pins, no artifact upload,
  contents-write permission, or persisted checkout credential.

## Still blocked

Native implementation needs a separately reviewed dependency-feature RFC and
unsafe audit for the minimum APIs, including:

1. opening and retaining the process image file handle;
2. `GetFinalPathNameByHandleW` plus local-volume and reparse-chain checks;
3. stable file identity comparison across process, verification, and reopen;
4. `WinVerifyTrust` with no UI and cache-only retrieval;
5. exact signer public-key/certificate digest extraction;
6. reviewed signer and canonical-root digests from signed Kakao release
   provenance, never from this machine; and
7. injected native-facade tests for replacement races and every OS error.

No live executable inspection or signature observation is authorized by this
handoff. Target/submit selectors and the durable DPAPI/ACL store remain blocked
separately.

## Safety ledger

- Live KakaoTalk/UIA/native trust inspection or mutation: not run.
- Current installation path, file identity, certificate, signer, or root read:
  0.
- `CurrentValue`, `SetValue`, or `Invoke` against a live provider: 0 calls.
- Messages sent: 0.
- KakaoTalk data/database/credential/token access: 0.
- Network requests/writes, pushes, PRs, and releases: 0.
