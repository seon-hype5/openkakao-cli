# Root handoff: WinTrust provider-chain traversal

Date: 2026-08-17 KST

## Status

Implemented on `integration/windows-mvp` as the clean successor to
`6a4012a6c541c3ebd3a2f8fdd4f5aa84f8f7136b`. The atomic commit containing
this handoff must be reported externally because it cannot embed its own
content-derived SHA.

No native adapter constructor, WinTrust call, file open, installed executable,
KakaoTalk process/path, UI API, product command, credential, database, push,
or external mutation was used by the new provider-chain test.

## Finding and change

The native extraction path already required an exact provider, primary signer
cardinality one, helper pointer identity, a bounded nonempty leaf chain, and an
exact fixture SPKI. Two provider-owned failure signals were still consumed
without an explicit check: `CRYPT_PROVIDER_SGNR.dwError` and the selected leaf
`CRYPT_PROVIDER_CERT.dwError`. The successful native traversal also depended
directly on three WTHelper calls, so a self-signed cache-dependent refusal
could leave the complete success branch unexecuted.

The three helper operations now sit behind one private raw-pointer trait, and
the single consuming extraction function is unsafe. Its call contract requires
every non-null returned provider structure to remain live and readable until
the owning VERIFY state closes. The production implementation delegates to the
same three WTHelper functions. The extraction path additionally requires zero
signer and leaf errors before certificate context or SPKI consumption.

An inert test implementation retains boxed provider, signer, and leaf
structures and a certificate context created only from the committed public
fixture DER. It proves the exact provider-to-primary-signer-to-leaf SPKI path,
both nested error refusals, and signer/leaf helper pointer-substitution
refusals. Its synthetic VERIFY-state wrapper clears the attempt bit before
inner Drop even during unwind, so it cannot accidentally call CLOSE.

Production still uses `UnavailableExecutableTrust`; no signer/root value,
constructor reference, selector, or capability changed.

## Changed files

- `src/platform/windows/executable_trust_native.rs`;
- the Windows activation/security/CI/provenance/decision documents;
- `docs/windows-port/NEXT_HANDOFF.md`;
- the handoff index; and
- this handoff.

## Verification

- focused provider-chain traversal test: 1 passed;
- disconnected native executable-trust module: 26 passed, including the two
  repository-fixture tests;
- library, all-feature Windows, binary, Windows contract, and guarded backend
  suites: 189, 113, 177, 2/24/2, and 2 passed;
- exact CLI allowlist: 14 passed, with the same 3 legacy local-state or
  credential diagnostic cases excluded;
- grouped compatibility suites: 23/13/12/13/20 passed;
- warnings-denied all-target/all-feature Clippy and formatting: passed;
- default/all-feature debug and release builds: passed;
- release all-feature Windows tests: 113 passed;
- inline documentation/action/toolchain validator: 48 Markdown files, 56
  local links, 0 broken/out-of-repository links, and 3 action refs pinned; and
- pre-commit diff, frozen-ancestry, and expected change-set checks: passed;
  the containing commit's post-commit clean status and ancestry are reported
  externally because this file cannot attest to its own content-derived SHA.

The new test calls certificate-context/SPKI encoding APIs only over committed
public DER bytes. It calls no WinTrust helper, filesystem, process, window,
COM, UI, product, or installed-application API.

## Skipped, assumptions, and residual risks

This seam qualifies the local call shape, pointer identity checks, nested error
handling, and SPKI traversal. It does not reproduce successful provider output
or qualify the WTHelper ABI on a clean Windows image. The unsafe extraction
boundary relies on its two private callers retaining the documented pointer
lifetime; the production implementation remains disconnected.

A second reviewer must still audit the complete unsafe provider/root path and
reproduce a clean pinned-Windows run. Reviewed Kakao signer/root provenance,
process-bound production wiring, target/submit selectors, and every live gate
remain separate blockers.

## Contract and dependency RFCs

ADR-040 records the helper lifetime and nested-error rule. No dependency,
manifest, public interface, capability, selector, or activation authorization
changed.
