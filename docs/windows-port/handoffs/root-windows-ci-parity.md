# Root handoff: Windows hosted-CI safe-matrix parity

Date: 2026-08-17 KST

## Status

Implemented on `integration/windows-mvp` as the clean successor to reviewed
commit `34227b4b68d1b0ec3e6b13c844ed4de2e9970eb7`. The commit containing this
handoff must be reported externally because it cannot embed its own
content-derived SHA.

No live KakaoTalk/UIA call, product command, external write, push, pull
request, artifact upload, or release occurred.

## Changed files

- `.github/workflows/windows.yml`;
- `docs/windows-port/CI.md`;
- `docs/windows-port/DECISIONS.md`;
- `docs/windows-port/NEXT_HANDOFF.md`;
- `docs/windows-port/handoffs/README.md`; and
- this handoff.

## Changed contract

- Every change below `docs/windows-port` now triggers the Windows workflow.
- An inline PowerShell gate checks every local Markdown link below that tree,
  refuses resolved targets outside the repository, requires every third-party
  action reference to use a lowercase 40-hex commit SHA, and confirms the exact
  `rust-toolchain.toml` channel.
- The hosted job now runs the five synthetic compatibility targets used by the
  local final matrix.
- Default and all-feature release builds, plus the release all-feature Windows
  unit-test subtree, are now required alongside the existing debug gates.
- The fourteen-name CLI compatibility allowlist is unchanged. The three
  legacy local-state/credential diagnostic cases remain excluded.
- Repository permission remains read-only, checkout credentials remain
  disabled, no product executable is invoked, and no artifact is uploaded.

The validator is inline intentionally. A temporary standalone-script form was
rejected by the host's existing PowerShell execution policy; no bypass or
policy change was attempted, and that uncommitted file was removed. The exact
inline body was then exercised as a command block.

## Verification

The ignored `.target/wave2-root` directory contained all Rust artifacts.

- formatting and warnings-denied all-target/all-feature Clippy: passed;
- library, all-feature Windows, binary, Windows contract, and guarded backend
  suites: 187, 111, 177, 2/24/2, and 2 passed;
- exact CLI compatibility allowlist: 14 passed, with the same 3 unsafe legacy
  cases excluded;
- grouped synthetic compatibility targets: 23/13/12/13/20 passed;
- default/all-feature debug and release builds: passed;
- release all-feature Windows tests: 111 passed;
- repository fixture structure/SPKI and offline WinTrust lifetime: 2 passed;
- inline documentation/action/toolchain validator: 46 Markdown files, 54
  local links, 0 broken/out-of-repository links, and 3 action refs pinned; and
- `git diff --check`, ancestry, and expected change-set checks: passed before
  the containing commit.

## Skipped and residual evidence

The workflow was not pushed or dispatched, so a clean GitHub-hosted
`windows-2022` result remains external integration evidence. No package was
installed merely to add a YAML parser; the edited workflow was reviewed by
diff/indentation checks and its exact PowerShell and Cargo commands were run
locally. The remaining environment assumption is that the pinned hosted image
provides its documented `pwsh`/.NET path APIs and completes the expanded job
within the existing 45-minute timeout; only the first hosted run can establish
that integration evidence.

This CI change supplies no Kakao signer/root provenance, native target or
submit selector, self-chat proof, live UI compatibility measurement, or
production executable-trust wiring. `send_open_chat` remains false, production
trust remains unavailable, and `L10` retry plus `L20` through `L40` remain
unauthorized.

## Contract and dependency RFCs

ADR-038 records the CI parity and static-validation contract. No manifest,
dependency, common runtime type, product capability, selector, or activation
RFC changed.
