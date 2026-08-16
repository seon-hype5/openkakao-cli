# Windows port handoff after Phase 0 and Wave 1

Date: 2026-08-16 KST

## Status

The user-requested Phase 0 and Wave 1 scope is complete on
`integration/windows-mvp`. The root integration commit is
`a2c9cb1cf4ddc1f210dbc2afac8e52bcc265b0fe`. The commit containing this handoff
is the next branch-tip commit; its exact SHA must be reported outside this file
because a commit cannot contain its own content-derived SHA.

Completed DAG tasks: `B00`, `B10`, `B20`, `B30`, `C00`, `C10`, `P10`, `P20`,
`P30`, and `I10`.

Execution used the requested topology: root plus exactly three
`gpt-5.6-sol` children at `reasoning=max`, with child subdelegation disabled.
At most two Rust builds were allowed concurrently.

Not started: Wave 2 (`P40`, `P50`, `P60`, `I20`), live validation (`L10` through
`L40`), and release-candidate task `R00`. None is implied by completion of this
handoff.

## Source and commit provenance

- pinned upstream: `be6edd442c803de8e4f06bfc4446d166ac474952`
- frozen contract: `d974c0597528e079919d4c45ee0893fa61d4335d`
- root UIA property-condition RFC on this branch: `bdf56d0`
- Child B safety source: `6963c73067cc3beb77783a49dd422a2d7fa26f52`
  -> integration cherry-pick `941d54a`
- Child A backend source: `2b70e3b73c8d9c409d4186324a651b8c02e4ebb1`
  -> integration cherry-pick `fba97d0`
- Child C CLI/output source: `02fb7d85bfa52c117f3b803b5d971be741df70c4`
  -> integration cherry-pick `b8a624d`
- root Wave 1 wiring and reconciliation:
  `a2c9cb1cf4ddc1f210dbc2afac8e52bcc265b0fe`

Intake used the required policy -> backend -> CLI order. Each child commit had
the frozen contract as an ancestor, stayed inside its assigned ownership, and
passed `git diff --check`. The three child worktrees were clean at handoff.

## Delivered behavior

- A Windows MSVC toolchain and isolated development workspace are documented
  in `TOOLCHAIN.md`; the repository no longer requires SQLCipher/OpenSSL merely
  to compile the Windows UI-only target.
- `PlatformProbe`, sealed `ApprovedSend`, stable snapshot/error/outcome types,
  a fake backend, and exact-and-unique matching form the frozen contract.
- The Windows backend performs read-only exact top-level discovery, limited
  process/path/version/session/integrity checks, and bounded metadata-only UIA
  composer selection on a dedicated windowless MTA thread.
- The safety policy is self-chat-only and deny-by-default, with an exact
  allowlist, five-second maximum snapshot TTL, 1,000-scalar/4,000-byte input
  bounds, one-shot hashed nonces, and a process-local non-Send approval lease.
- Windows CLI dispatch adds `doctor --ui` and stdin-only, opened-only
  `local-send`. Dry-run is the default. Stage/commit are refused before stdin
  or UI inspection, and rejected positional message text is not echoed.
- Reports use schema version 1, fixed allowlisted evidence, stable exit codes,
  separated stdout/stderr, execution-scoped fingerprints, and no raw message,
  room/profile name, HWND, or UIA runtime ID.
- A successful policy dry-run retains and reports the same validated redacted
  snapshot, avoiding a second-probe race. Secret input buffers are zeroized on
  failure and the final `SecretMessage` is zeroized on drop.

## Intentional fail-closed limitation

The production backend does not read window titles, UIA Name or Value
properties, room/profile names, or draft contents. Therefore it never claims
`exact_match`, `unique_match`, `self_chat_verified`, or `draft_empty`.
`doctor --ui` can return redacted metadata, but a production `local-send`
dry-run currently reaches policy refusal rather than a successful plan. Only
synthetic fake snapshots exercise the successful orchestration path.

This is deliberate: process/window/composer metadata alone cannot prove the
target is self-chat or that no draft would be overwritten. Do not weaken these
fields or infer them from process identity in Wave 2.

## Final non-mutating verification

All commands used the ignored `.target/integration` directory.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo test --lib` | 84 passed |
| `cargo test --bin openkakao-cli` | 170 passed |
| `cargo test --test windows_backend` | 2 passed |
| `cargo test --test windows_policy` | 16 passed |
| `cargo test --test windows_cli` | 2 passed |
| safe `cargo test --test cli_test` selection | 14 passed, 3 excluded |
| `cargo clippy --all-targets --all-features -- -D warnings` | passed |
| `cargo build` | passed |
| final staged `git diff --check` | passed |

Additional synthetic compatibility suites passed during integration:
`auth_flow_test` 23, `loco_client_test` 13, `loco_crypto_test` 12,
`loco_packet_test` 13, and `message_db_test` 20.

The three excluded `cli_test` cases were
`doctor_json_outputs_valid_json`, `auth_status_json_outputs_valid_json`, and
`cache_stats_json_outputs_valid_json`, because the legacy paths may load
credential or local-database diagnostics. No full live-dependent test command
was substituted for them.

## Safety ledger

- KakaoTalk UI mutations: 0
- stage calls against the production backend: 0
- commit calls against the production backend: 0
- actual messages sent: 0
- live UIA probes: 0
- KakaoTalk data/database reads: 0
- credential/token reads: 0
- process-memory reads, injection, or hooks: 0
- pushes: 0
- pull requests: 0

KakaoTalk inspection during Phase 0 was limited to running-process and
executable file metadata needed to record version `26.7.0.5255`. Package
installation and the upstream clone used normal network access; no KakaoTalk
network operation was performed.

## Residual risks and open work

- A privacy-preserving way to prove self-chat identity and empty draft is not
  designed. Wave 2 mutation work cannot safely become usable without it.
- The selector profile was not exercised against live KakaoTalk UI. Provider
  changes will fail closed, but compatibility is unconfirmed.
- Executable signing and canonical installation-root verification are absent.
- Modal evidence is limited to the selected top-level window being disabled.
- An eight-second UIA caller timeout cannot cancel a blocked COM provider call;
  a detached read-only worker may remain until the provider returns.
- Replay protection and mutual exclusion are process-local, not cross-process
  or durable.
- Windows CI and macOS/Linux regression execution are deferred to `P60`;
  macOS AX behavior cannot be executed on this host.

## Next session

Start by reading this file, `SECURITY_MODEL.md`, `DECISIONS.md`, and the three
child handoffs. Verify the branch tip and clean worktrees. Wave 2 requires a new
explicit user request and should begin with the identity/draft evidence design,
the adversarial audit, and Windows CI/manual documentation. Do not run `L10`
or any later live-validation task merely because `I10` is complete. `L20`
through `L40` have separate manual gates, and `L40` requires fresh explicit
approval for exactly one automatic self-chat commit.
