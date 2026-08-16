# Root handoff: native trust state and provenance hardening

Date: 2026-08-16 KST

## Status

Complete as a non-live, synthetic-only trust hardening step. The final commit
is recorded in the external checkpoint because a commit cannot contain its own
content-derived identifier.

Production remains unchanged: the native observer is disconnected,
`UnavailableExecutableTrust` refuses before ledger/UI observation,
`send_open_chat=false`, self-target evidence is false, and the submit selector
is unconfigured.

## WinTrust state hardening

After VERIFY and before provider extraction, the adapter now proves that:

- action GUID and every fixed `WINTRUST_DATA` policy field retain the exact
  offline/no-UI/cache-only values;
- callback, SIP, URL, known-subject, and crypto-policy pointers remain null;
- file info, file path, file handle, union, and signature-settings pointers
  still target the exact caller-owned stable allocations;
- structure sizes, signature flags, and requested index remain exact;
- provider `pWintrustData`, `pgActionID`, and `pSigSettings` link back to those
  same allocations; and
- zero secondary signatures implies `dwVerifiedSigIndex == 0`.

Any drift maps to fixed signature-trust refusal before certificate/SPKI use.
VERIFY state still receives exactly one CLOSE attempt on every path.

## Installation-root relation codec

`ExecutableTrustProfile` no longer accepts an arbitrary root `TrustDigest`.
Its signer must be a distinct wrapper created from a source-static 32-byte
array, so an observed runtime SPKI digest cannot become an expected signer by
accident. The typed version-1 root codec accepts only source-static components
and requires one reviewed root kind—Program Files x86,
Program Files 64-bit, or current-user LocalAppData—and one to eight bounded
relative printable-ASCII components. It rejects absolute/path separators,
ADS colon, Windows-reserved punctuation, controls, dot/space ambiguity,
reserved DOS device names, non-ASCII normalization, empty/oversized components,
and oversized relations.

ASCII case is folded; the root-kind tag, component count, and each component's
length are hashed with a fixed domain. Debug is always redacted. The codec has
no production values and cannot infer a root from this machine.

## Verification and residual blockers

Focused synthetic tests cover policy/pointer drift, verified-index mismatch,
root-kind/component/order separation, ASCII case folding, malformed
components, and redaction. They do not construct the native adapter or call a
Windows trust/file API.

The complete non-live regression matrix passed: 165 default library tests; 95
all-feature Windows tests in both debug and release; 177 binary tests; 29
Windows default/all-feature contract tests; 81 compatibility tests; the exact
14-test safe CLI allowlist; all-target/all-feature Clippy with warnings denied;
default/all-feature debug and release builds; and 34 Windows-port Markdown
files with 31 local links and zero broken links.

Still required before production wiring:

- independently reviewed signed-release provenance selecting exact root
  kind/components and signer SPKI;
- a repository-owned signed fixture with documented source/hash/license;
- independent review of the unsafe FFI boundary against that fixture;
- native derivation of the observed root relation from separately validated
  known-folder and final-handle paths; and
- all target/selector/live gates in their documented order.

## Safety ledger

- WinVerifyTrust/file/signature calls: 0.
- Real installation-path or signer observations: 0.
- KakaoTalk executable/data access: 0.
- KakaoTalk/UI observation or mutation: 0.
- Actual messages sent: 0.
- Credential/token/process-memory access: 0.
- Pushes, PRs, releases, or external writes: 0.
