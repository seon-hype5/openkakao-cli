# Child C Wave 2 P60 handoff

## Status

- Complete on `agent/docs-ci-w2` from Wave 1 tip
  `fed2bb1558b4e07878f17f4c8140aab5ead682b2`.
- Atomic commit SHA: the single commit containing this handoff; its immutable
  SHA is reported immediately after commit creation because a commit cannot
  contain its own final SHA.
- Scope is documentation and CI only; no product source, manifest, common
  contract, or existing non-Windows workflow was changed.

## Changed files

- `.github/workflows/windows.yml`
- `docs/windows-port/CI.md`
- `docs/windows-port/manuals/README.md`
- `docs/windows-port/manuals/read-only-doctor-dry-run.md`
- `docs/windows-port/manuals/stage-only.md`
- `docs/windows-port/manuals/user-manual-submit.md`
- `docs/windows-port/manuals/one-shot-automatic-smoke.md`
- `docs/windows-port/manuals/abort-rollback-troubleshooting.md`
- `docs/windows-port/manuals/artifact-privacy.md`
- `docs/windows-port/handoffs/child-c-wave2.md`

## Delivered P60 surface

- Windows 2022 CI using the repository-pinned Rust 1.95.0 toolchain.
- All external actions pinned to reviewed full-length commit SHAs, with major
  tags retained only as comments.
- Formatting, warnings-denied Clippy, explicit synthetic-safe unit/integration
  selections, and a locked Windows build.
- Read-only repository permissions, no secret injection, no live product
  commands, and no artifact upload.
- Linux and macOS regression plan that preserves the root-owned existing
  workflow and separates build confidence from live UI claims.
- Separate L10 read-only, L20 stage-only, L30 user-manual-submit, and L40
  one-shot automatic manuals, plus common abort/recovery and artifact privacy
  manuals.
- Every L10+ document explicitly states that it is not authorization for the
  current session and requires fresh user approval at its own gate.

## Static validation

- Exact top-level, `agent/docs-ci-w2`, clean starting status, and `fed2bb1`
  ancestry were verified before editing.
- Workflow indentation contains no tabs; required runner/toolchain/gate
  commands are present; live/local-state commands and artifact-upload actions
  are absent.
- Every `uses:` reference matches an exact reviewed official-repository action
  and a full 40-hex commit SHA; moving or abbreviated refs are absent.
- All relative Markdown links resolve across `CI.md` and the seven manual
  documents.
- Manual marker scan confirms explicit non-authorization language for L10,
  L20, L30, L40, abort/recovery, and artifact handling.
- Final staged `git diff --check` is required immediately before commit.

## Skipped execution

- The GitHub Actions workflow was not dispatched or pushed.
- No Cargo command was needed for documentation/workflow-only changes, so no
  build lease was requested.
- No live UI probe, stage, commit, submission, application-data read,
  credential/token access, screenshot, private fixture, network login, push,
  pull request, or installation occurred.
- Linux/macOS regressions were documented but not executed on this Windows
  host.

## Assumptions and residual risks

- GitHub-hosted `windows-2022` provides PowerShell and supports the reviewed
  full-SHA-pinned action inputs.
- Wave 1's integrated non-mutating verification establishes the initial safe
  test allowlist. Future test additions require a new safety review before CI
  inclusion.
- The workflow was structurally validated without installing `actionlint` or a
  YAML parser; its first remote run remains an integration check.
- Compiler output is cached but never uploaded. This remains safe only while
  all executed tests are synthetic and no runtime capture is added.
- Extra macOS AX regression execution remains a root-owned workflow decision;
  P60 documents the required plan without changing existing non-Windows CI.
- L20 through L40 remain blocked by absent product capability and unproven
  privacy-preserving identity/draft evidence.

## RFCs

- No dependency, manifest, product-code, or frozen-contract RFC is requested.
- Adding persistent CI/manual artifacts requires a separate privacy RFC with a
  field allowlist, automated leak test, finite retention, and root-owned ignore
  policy review.
- Implementing the documented Linux/macOS regression expansion requires a
  root-owned update to the existing non-Windows workflow.
