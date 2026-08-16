# Windows CI and cross-platform regression plan

## Scope

`.github/workflows/windows.yml` is a non-live Windows compile and synthetic-test
gate. It does not launch a UI probe, execute `doctor`, stage input, submit
anything, inspect application data, or load credentials. The runner receives
read-only repository permission and no project secrets.

The workflow uses `windows-2022` and the repository pin in
`rust-toolchain.toml` (`1.95.0` with rustfmt and Clippy). The explicit action
input and a preflight check must match that file. A toolchain update therefore
requires one reviewed change to the repository pin and a matching workflow
change.

Every third-party action reference is pinned to a reviewed full 40-hex commit
SHA. A trailing comment records the corresponding reviewed major tag for
maintainer readability, but the tag is never used as the executable ref. Any
action update requires provenance review in the action's official repository
and a static check that rejects moving tags, branches, abbreviated SHAs, and
non-hex refs.

## Automated Windows gates

The job runs in this order and stops on the first failure:

| Gate | Command | Safety basis |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Source-only formatting check |
| Lint | `cargo clippy --locked --all-targets --all-features -- -D warnings` | Compiles/lints targets; does not execute the product |
| Library | `cargo test --locked --lib` | Unit tests use synthetic values and pure mappings |
| Guarded transaction | `cargo test --locked --lib --all-features platform::windows` | Runs only the named synthetic Windows unit-test subtree with the default-off write feature compiled |
| Binary unit | `cargo test --locked --bin openkakao-cli` | Parser and unit coverage; no command dispatch against a live app |
| Windows contracts | `cargo test --locked --test windows_backend --test windows_policy --test windows_cli` | Capability, fake, policy, redaction, and zero-mutation coverage |
| Guarded backend contract | `cargo test --locked --all-features --test windows_backend` | Verifies the feature-enabled production backend remains fail-closed without calling `inspect`, `stage`, or `commit` |
| CLI compatibility | Fourteen individually named `cli_test` cases, each run with `--exact` | Closed allowlist of help/version/usage parsing only |
| Builds | `cargo build --locked` and `cargo build --locked --all-features` | Builds both the default read-only artifact and the feature-gated artifact using the committed lockfile; neither is executed |

The CLI compatibility step is a closed allowlist. It deliberately excludes
these cases because they can enter legacy local-state or credential diagnostic
paths:

- `doctor_json_outputs_valid_json`
- `auth_status_json_outputs_valid_json`
- `cache_stats_json_outputs_valid_json`

Do not replace the exact-name allowlist with a skip-based denylist or an
unreviewed full binary integration command: a future test must not become
executable merely by being added to `cli_test.rs`. A new Windows test may enter
the allowlist only after confirming that it uses synthetic/fake inputs,
performs no UI mutation, and cannot read user or application state.

## Why the workflow is non-live

- No step runs the built executable with `doctor --ui` or `local-send`.
- The production-backend integration target checks only advertised
  capabilities and redacted formatting; it does not call `inspect`.
- Stage and commit are exercised only as policy/fake states with mutation
  counters fixed at zero, plus a synthetic in-memory transaction port. The
  production backend contract test never calls either mutation method.
- There is no service container, desktop session preparation, application
  installation, account setup, network login, or secret injection.
- `RUST_BACKTRACE=0` prevents failure backtraces from becoming accidental
  diagnostic artifacts. Test failures must remain synthetic and redacted.

`windows-ui-write` is a real, default-off build boundary rather than an
authorization switch. Enabling it compiles the reviewed transaction and
native call sites, but the production profile still advertises
`send_open_chat=false` because no privacy-safe self-target proof or measured
send-button selector is configured. All-feature CI is compile and synthetic
behavior coverage only; it must never be interpreted as permission to run a
live UI command.

## Cache and artifact policy

The workflow has no `upload-artifact` step. Its cache is limited to the Cargo
registry, Cargo git checkout cache, and `.target/windows-ci`. Those locations
contain dependencies and compiler outputs only because every executed test is
synthetic. Do not add screenshots, UI trees, runtime traces, command stdout,
environment manifests, crash dumps, or arbitrary workspace paths to the
cache.

Detailed handling rules are in
[`manuals/artifact-privacy.md`](manuals/artifact-privacy.md). A workflow change
that persists any new artifact needs a privacy review, an explicit finite
retention period, and proof that forbidden fields cannot be produced.

Action pins are part of the workflow trust boundary. Cache or artifact policy
must not be weakened by replacing a full action SHA with a moving tag.

## Linux regression plan

The existing `.github/workflows/openkakao-cli-ci.yml` remains root-owned and is
not modified by P60. Its Ubuntu test and lint jobs currently provide the
primary Linux regression signal. Before `I20` or a release candidate, root
should confirm:

1. formatting and warnings-denied Clippy pass with the pinned toolchain;
2. library, binary-unit, and synthetic integration tests pass;
3. the unsupported desktop-platform facade builds and refuses mutation;
4. no Windows-only dependency leaks into an unconditional target; and
5. no live diagnostic or local-state CLI case is added to CI.

Any expansion of the Linux job must preserve the same explicit safe-test rule
used by the Windows workflow.

## macOS regression plan

The existing CI builds the macOS release binary and runs `--version`; the
release workflow also retains both supported macOS architectures. Before
`I20`, root should additionally run or arrange a reviewed macOS job for:

1. the existing AX unit/fake tests and exact-and-unique matcher regression;
2. library and parser tests that do not open local data stores or credentials;
3. a release build on the pinned toolchain; and
4. `--version`/`--help` smoke checks only.

Automated macOS CI must not drive Accessibility UI, open a chat, invoke legacy
database diagnostics, or submit anything. Live AX validation is a separately
approved manual activity and is not implied by a green build.

## Gate interpretation

A green workflow proves compilation, formatting, lint, synthetic policy, fake
orchestration, redaction, and fail-closed behavior. It does not prove selector
compatibility with a live application, self-chat identity, empty-draft
evidence, stage safety, echo detection, or submission correctness. Those
claims belong to the separately approved manuals under
[`manuals/`](manuals/README.md); none is authorized by CI success.
