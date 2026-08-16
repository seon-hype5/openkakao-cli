# Root handoff: WinTrust provider-owned policy state

Date: 2026-08-17 KST

## Status

Implemented on `integration/windows-mvp` as the clean successor to reviewed
commit `6bbb4efbe7d280d8b1cdbf0af623c0060880f6aa`. The atomic commit containing
this handoff must be reported externally because it cannot embed its own
content-derived SHA.

No native adapter constructor, installed executable, KakaoTalk process/path,
UI API, product command, credential, database, push, or external mutation was
used.

## Finding and change

The adapter already exact-checked caller-owned WinTrust input structures and
the provider's three back-pointers. Its catalog flag, however, was derived
from the caller's fixed `WTD_CHOICE_FILE` union, so it was not independent
provider evidence. It also did not validate the provider's effective subject,
revocation flags, or success error fields before signer-pointer traversal.

Successful provider extraction now requires:

- exact provider back-pointers to the live `WINTRUST_DATA`, action GUID, and
  signature-settings allocations;
- `dwSubjectChoice == CPD_CHOICE_SIP`;
- `dwProvFlags` equal to the exact caller low-word flags plus
  `CPD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`;
- zero `dwError` and `dwFinalError`; and
- `fRecallWithState == false`, with true mapped to catalog ambiguity and
  refused by the pure verifier before signer extraction.

The comparison is content-free and retains no provider pointer or value.
Production still uses `UnavailableExecutableTrust`; no signer/root value or
constructor reference was added.

## Changed files

- `src/platform/windows/executable_trust_native.rs`;
- the Windows activation/security/CI/decision documents;
- `docs/windows-port/NEXT_HANDOFF.md`;
- the handoff index; and
- this handoff.

## Verification

- focused provider-state test: 1 passed;
- disconnected native executable-trust module: 25 passed, including the two
  repository-fixture tests;
- library, all-feature Windows, binary, Windows contract, and guarded backend
  suites: 188, 112, 177, 2/24/2, and 2 passed;
- exact CLI allowlist: 14 passed, with the same 3 legacy local-state or
  credential diagnostic cases excluded;
- grouped compatibility suites: 23/13/12/13/20 passed;
- warnings-denied all-target/all-feature Clippy and formatting: passed;
- default/all-feature debug and release builds: passed;
- release all-feature Windows tests: 112 passed;
- inline documentation/action/toolchain validator: 47 Markdown files, 55
  local links, 0 broken/out-of-repository links, and 3 action refs pinned; and
- pre-commit diff, frozen-ancestry, and expected change-set checks: passed;
  the containing commit's post-commit clean status and ancestry are reported
  externally because this file cannot attest to its own content-derived SHA.

The new test mutates every provider pointer/policy/error field and catalog
recall only in an inert Rust-owned `CRYPT_PROVIDER_DATA`. It calls no WinTrust
helper, filesystem, process, window, COM, or UI function.

## Skipped, assumptions, and residual risks

No independently trusted fixture was introduced, so the successful native
provider path remains unqualified on a clean Windows image. The exact provider
flag mapping follows the Windows SDK contract that the low word is initialized
from `WINTRUST_DATA.dwProvFlags` and the effective revocation choice is carried
by the CPD high-word flag; any platform/provider deviation will fail closed
until independently reviewed.

A second reviewer must still audit the complete unsafe provider/root path and
reproduce a clean pinned-Windows run. Reviewed Kakao signer/root provenance,
process-bound production wiring, target/submit selectors, and every live gate
remain separate blockers.

## Contract and dependency RFCs

ADR-039 records this provider-state rule. No dependency, manifest, public
interface, capability, selector, or activation authorization changed.
