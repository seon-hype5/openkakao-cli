# Root handoff: disconnected native executable-trust adapter

Date: 2026-08-16 KST

## Status

Complete as an offline, disconnected activation scaffold. The atomic commit is
the clean successor of `86fb67cf0eea41f3cb56f3485111230fd3b13f78`; its final
SHA is recorded in the external checkpoint because a commit cannot embed its
own content-derived identifier.

Production behavior is unchanged. `NativeMutationPort` still constructs
`UnavailableExecutableTrust`, and `WindowsBackend` still advertises
`send_open_chat=false`. Repository-wide search shows no production reference
to `WindowsNativeExecutableTrustApi` or its constructor.

## Delivered boundary

`src/platform/windows/executable_trust_native.rs` now contains a real Windows
implementation of the existing fakeable adapter seam:

- duplicates the already selected process handle and rechecks HWND, PID, and
  process creation time before and after path/signature phases;
- obtains the process image path from that handle, opens the file and every
  parent without following the final reparse component, and rejects any
  reparse/type uncertainty;
- derives a normalized volume-GUID path from an owned file handle, requires the
  exact fixed local volume root, and retains both process-image and
  verification handles;
- hashes volume serial, 128-bit file ID, and process creation time with a fixed
  domain to obtain a content-free identity, then requires agreement before
  verification and after the path-based version query;
- constructs `WINTRUST_FILE_INFO`, `WINTRUST_SIGNATURE_SETTINGS`, action GUID,
  and `WINTRUST_DATA` in stable owned allocations;
- calls only the frozen noninteractive, no-UI, cache-only embedded-file policy,
  treats only LONG zero as trusted, and makes exactly one CLOSE attempt;
- keeps a DROP fallback between VERIFY return and orchestrator ownership so an
  unwind cannot leak provider state, while marking before CLOSE entry prevents
  a duplicate attempt;
- validates provider/signer/certificate pointer alignment, structure sizes,
  exact one-signer cardinality, and zero secondary signatures before use;
- DER-encodes only the leaf `SubjectPublicKeyInfo` through a bounded two-call
  `CryptEncodeObjectEx` protocol and hashes the exact bytes with SHA-256; and
- keeps path buffers and DER allocations zeroizing and exposes only fixed
  content-free error operations.

The native adapter intentionally sets `install_root_digest=None`. It cannot
pass the pure verifier even if an internal caller constructs it. This prevents
the current machine's installation from becoming its own trust anchor.

## Verification

All Rust artifacts stay under `.target/wave2-root`. The focused suite is pure:
it type-checks the native adapter and tests parser/hash/bounds/provider-shape
helpers without constructing the adapter, opening a file, or calling
WinVerifyTrust.

- `cargo check --locked --all-features`: passed.
- focused executable-trust-native tests: 15 passed.
- default library suite: 161 passed.
- debug and release all-feature Windows unit subtree: 88 passed each.
- binary unit suite: 177 passed.
- default/all-feature Windows backend tests: 2 passed each.
- Windows policy tests: 23 passed; Windows CLI tests: 2 passed.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- default/all-feature debug and all-feature release builds: passed.

## Unsafe ownership review

- Every duplicated process/file handle has one `OwnedNativeHandle` owner and
  one `CloseHandle` in `Drop`.
- WinTrust action, file path, file handle, file info, signature settings, and
  data remain at stable addresses through VERIFY and CLOSE.
- Provider, signer, certificate, context, and certificate-info pointers are
  borrowed only while the state is live and before CLOSE; none is freed by the
  application or returned from the module.
- Raw provider-pointer helpers are `unsafe`, bind returned references to the
  live state borrow, and check null/alignment/size before consuming fields.
- SPKI output is bounded before allocation and zeroized after hashing.
- No pointer-derived value, raw path, file ID, PID, HWND, signer bytes, or
  certificate metadata reaches Debug, errors, JSON, fixtures, or docs.

## Remaining blockers and assumptions

- No reviewed Kakao signer SPKI or canonical installation-root profile exists.
- A repository-owned signed fixture with reviewed provenance is needed before
  the actual WinTrust call can receive automated integration coverage.
- An independent unsafe review is required before any production reference is
  added.
- The version-resource API is path-based; the adapter reopens and exact-checks
  identity immediately after it, while the held verification handle remains
  authoritative. A malicious same-user process that continuously swaps and
  restores files remains outside the documented threat model.
- The production ledger is now wired lazily behind this still-unavailable
  trust boundary; target identity, submit selector, trust provenance/wiring,
  and every live gate remain independent blockers.

## Safety ledger

- Native adapter/WinTrust production calls: 0.
- KakaoTalk executable or data file access: 0.
- Live KakaoTalk/UIA inspection or mutation: 0.
- Actual messages sent: 0.
- Credential/token/process-memory access: 0.
- Network writes, pushes, PRs, or releases: 0.
