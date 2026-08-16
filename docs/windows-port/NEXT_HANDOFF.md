# Windows port handoff after Wave 2 / I20

Date: 2026-08-16 KST

## Status

The non-live Windows release candidate is complete through DAG task `I20` on
branch `integration/windows-mvp`. The reviewed implementation tip is
`272c8cb70c716066e22b9d5a6cf8e2d8da3a3d43`. The commit containing this
handoff is its clean successor and must be reported externally because a
commit cannot embed its own content-derived SHA.

Completed tasks: `B00`, `B10`, `B20`, `B30`, `C00`, `C10`, `P10`, `P20`,
`P30`, `I10`, `P40`, `P50`, `P60`, and `I20`.

`L10` was subsequently approved for one read-only session and attempted once;
it failed closed and is not complete. Not completed or authorized now: a new
`L10` attempt, `L20`, `L30`, `L40`, and final post-live task `R00`. A green I20
does not carry authority into any live gate.

The requested topology was used: root plus Child A/B/C, with isolated
worktrees and no child subdelegation. Rust builds were kept within the stated
concurrency limit.

## Provenance

- pinned upstream: `be6edd442c803de8e4f06bfc4446d166ac474952`;
- frozen contract: `d974c0597528e079919d4c45ee0893fa61d4335d`;
- Wave 1 integration ancestor:
  `fed2bb1558b4e07878f17f4c8140aab5ead682b2`;
- P50 child source: `f9ca1964942276fa3fb0a4305a5408afb5599e2d`,
  integrated and reconciled beginning at `cd0faf4`;
- P60 child source: `f09fc19bb05e11b0d4659a726e662e414c1e1408`,
  integrated at `b6b4c7b` and hardened at `fb51d1f`;
- P40 child source: `47452d8327d4ce52929de17523a6fc4f971d4293`,
  integrated at `280a35e`;
- root guarded orchestration and contract chain: `ebc9368`, `5550384`,
  `8a89431`, `658b541`, `a61b3d7`, `f60876c`, and `60adc01`; and
- final root adversarial reconciliation, CI, tests, and documentation:
  `272c8cb70c716066e22b9d5a6cf8e2d8da3a3d43`.

The Child A native unsafe audit and Child B adversarial audit were followed by
a focused re-audit of root's fixes. The re-audit found no correctness blocker
for merging the default-off scaffold.

## L10 read-only attempt: failed closed

The user approved one L10 session and confirmed the self-chat was manually
opened with no recording, screenshot, or output redirection. Root rebuilt the
exact `1c358db` commit with default features, kept every child idle, and ran
one guarded `doctor --ui` plus one synthetic stdin dry-run. The session ended
at approximately `2026-08-16T19:57:34+09:00`.

- `doctor --ui` exited 0 and produced a valid redacted schema-v1 report with
  19 fixed evidence codes, no attempted action, and `not_submitted`.
- The report did not establish a supported UI profile.
- Independent before/after guards could not establish an exact unique
  KakaoTalk top-level window or composer, so composer length remained
  unobserved. L10 therefore did not pass.
- The synthetic dry-run was refused before UI inspection with fixed
  `invalid_input` / `policy_allowlist_config`, exit 2. Neither the synthetic
  target nor canary was echoed.
- Foreground, focus, Z-order neighbors, clipboard sequence, visibility, and
  enabled-state observations were unchanged across the session.
- Raw doctor/dry-run output, HWNDs, PIDs, labels, draft material, and
  fingerprints were not emitted or persisted.

No retry, weaker selector, alternate live probe, stage, or commit followed the
failure. The troubleshooting runbook permits only offline source/synthetic
work now. L20 is blocked.

## Offline remediation after the failed L10

The failed session retained only fixed booleans, so it did not preserve a raw
window count and does not prove a root cause. Offline source review identified
a conservative failure class: the read-only backend previously returned
ambiguous as soon as more than one exact `EVA_Window_Dblclk` window existed,
before determining whether only one contained the exact known-profile
composer.

The successor to this handoff adds bounded diagnostic narrowing. A probe now
inspects at most eight exact-class candidates and selects one only if exactly
one candidate has exactly one `RICHEDIT50W` / `1006` / Edit composer and every
other candidate has none. Duplicate composers, an internally ambiguous
composer, too many windows, or any native/UIA inspection error still fail
closed. Synthetic tests cover the unique, duplicate, internally ambiguous,
unsupported, and absent-composer shapes.

This is not a self-chat selector and does not authorize a live retry. All
target-identity booleans remain false, `send_open_chat` remains false, and the
mutation path still requires raw enumeration to return exactly one top-level
window. No live KakaoTalk/UIA call was made while implementing or testing this
remediation.

## Delivered release-candidate behavior

- Windows process/window/version/session/integrity/process-creation and exact
  composer metadata discovery runs on a dedicated windowless MTA thread.
- Read-only discovery examines at most eight exact-class windows and narrows to
  one only under the exact unique-composer rule; writes retain stricter raw
  top-level uniqueness.
- Read-only UIA work is process-wide single-flight. A timed-out provider keeps
  the lease until it returns, further probes create no worker, and the timeout
  is non-retryable.
- Inspection is metadata-only and redacted. It does not read titles, UIA
  Name/Value, room/profile names, draft text, KakaoTalk data, or credentials.
- Windows CLI provides `doctor --ui` and stdin-only/opened-only `local-send`,
  with generic parse failures that cannot echo a rejected positional message.
- Input stops at 4,001 raw bytes, accepts at most 4,000 valid UTF-8 bytes and
  1,000 Unicode scalars, rejects dangerous controls/whitespace forms, and
  zeroizes secret buffers.
- The exact allowlist is checked before stdin. Windows has its own default-off
  `safety.allow_windows_ui_write` flag; macOS `allow_ax_send` cannot authorize
  it.
- Dry-run is inspection-only by type and reuses one policy snapshot.
- Write execution uses a consumed approval lease, a sealed sender, an atomic
  one-shot claim, exact mode/outcome compatibility, and no retry edge.
- `windows-ui-write` is a real default-off compile boundary. All-feature builds
  compile the native Value/Invoke path without granting authority.
- The guarded transaction binds PID/HWND/path/process creation/session/UIA
  evidence, half-open TTL, a named cross-process mutex, final native preflight,
  exact stage readback, owned-value-only restore, and at most one Invoke.
- Same-process foreground popups count as user activity. Mutex contention,
  abandonment, wait failure, and every error/panic after SetValue entry are
  `SubmissionUncertain`, exit 21, and never retry-safe.
- Secret UTF-16 is written directly into a presized zeroizing allocation;
  outbound and CurrentValue BSTR allocations are scrubbed before release.
- Reports remain schema v1 and allowlist action/profile/evidence/operation
  codes. Unknown strings are redacted in human and JSON streams.

## Intentional production refusal

The transaction code exists for review and synthetic verification, but a live
write is not reachable:

1. `windows-ui-write` defaults off;
2. `allow_windows_ui_write` defaults false;
3. `WindowsBackend::capabilities()` reports `send_open_chat=false` even in an
   all-feature build;
4. native `self_chat_verified`, exact-target, and unique-target evidence are
   always false; and
5. the commit selector is `Unconfigured` and no InvokePattern is acquired.

Thus production stage/commit refuse before stdin or UI inspection in root
dispatch, and normal policy authorization using `WindowsBackend` cannot mint
an operation. Even a synthetic cross-backend approval is stopped by the
Windows sender's independently fresh target and selector evidence. These gates
must not be weakened merely to make a live test possible.

## Final non-live verification

All Rust commands used the ignored
`C:\Users\ihvna\source\openkakao-dev\repo\.target\wave2-root` directory.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo test --locked --lib` | 155 passed |
| `cargo test --locked --lib --all-features platform::windows` | 82 passed |
| `cargo test --locked --bin openkakao-cli` | 177 passed |
| `cargo test --locked --test windows_backend` | 2 passed |
| `cargo test --locked --test windows_policy` | 23 passed |
| `cargo test --locked --test windows_cli` | 2 passed |
| `cargo test --locked --all-features --test windows_backend` | 2 passed |
| closed exact `cli_test` allowlist | 14 passed; 3 live/local-state cases excluded |
| `auth_flow_test` | 23 passed |
| `loco_client_test` | 13 passed |
| `loco_crypto_test` | 12 passed |
| `loco_packet_test` | 13 passed |
| `message_db_test` | 20 passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | passed |
| debug build, default and all features | passed |
| release build, default and all features | passed |
| release all-feature Windows synthetic tests | 82 passed |
| Markdown local links and pinned-action policy | passed |
| final `git diff --check` | passed |

The excluded `cli_test` cases are
`doctor_json_outputs_valid_json`, `auth_status_json_outputs_valid_json`, and
`cache_stats_json_outputs_valid_json`; their legacy paths may load local-state
or credential diagnostics. No broad test command or product invocation was
substituted for them.

Windows CI pins all three third-party actions by full reviewed commit SHA,
uses read-only repository permissions, disables checkout credential
persistence, uploads no artifact, and runs default plus explicitly scoped
all-feature synthetic coverage. The workflow itself was statically validated;
its first GitHub-hosted run remains an external integration check.

## Safety ledger for this implementation session

- live KakaoTalk/UIA doctor probes: 1;
- live before/after read-only guard snapshots: 2;
- KakaoTalk UI mutations: 0;
- production backend stage calls: 0;
- production backend commit/Invoke calls: 0;
- actual messages sent: 0;
- KakaoTalk files/databases read: 0;
- credential/token reads: 0;
- screenshots/UI dumps/process-memory reads/injection/hooks: 0;
- automatic retries: 0;
- pushes: 0; and
- pull requests/releases: 0.

All mutation counts in automated tests belong to fake or in-memory synthetic
ports, never KakaoTalk or another desktop application.

## Remaining activation blockers and risks

[`ACTIVATION_RFC.md`](ACTIVATION_RFC.md) now defines proposed evidence,
privacy, durability, crash-recovery, executable-trust, and activation-order
contracts. It contains no selector values and authorizes no live work.
[`NATIVE_ACTIVATION_BOUNDARIES.md`](NATIVE_ACTIVATION_BOUNDARIES.md) freezes
the reviewed `windows` 0.62.2 feature/API/ownership inventory for offline
implementation; it likewise authorizes no probe or production wiring.

- Design and measure a privacy-safe exact self-chat identity selector without
  exposing room/profile text.
- Measure and review an exact unique send-button selector and InvokePattern;
  no keyboard fallback is permitted.
- Review and complete the proposed privacy-safe durable replay ledger. Its
  fixed codec/controller/ordering/correlation and an explicit-temporary-base
  Windows DPAPI/protected-ACL/write-through store are synthetically tested.
  A disconnected LocalAppData/fixed-volume/parent-chain constructor is now
  compiled and retains its canonical base handle, but native-port wiring
  remains absent and fail closed.
- Complete executable-signature and canonical-installation-root evidence. The
  content-free decision seam, fakeable offline WinTrust policy, and a
  disconnected native handle/WinVerifyTrust/provider/SPKI adapter now exist.
  The adapter has zero production references, deliberately returns no
  install-root digest, and has never been called against KakaoTalk. Reviewed
  signer/root provenance, signed-fixture evidence, independent unsafe review,
  and production wiring remain absent and fail closed.
- Expand modal evidence beyond the current conservative window state.
- A third-party UIA provider can hang; COM calls cannot be safely cancelled in
  process after entry. Single-flight prevents worker accumulation but one hung
  worker can block further probes until it returns or the process exits.
- Run the committed workflow on a GitHub Windows runner and obtain reviewed
  macOS/Linux regression signals before upstream release work.
- No live selector compatibility, target identity, empty-draft proof, stage
  restoration, or submission result has been measured.

## Next permissible step

The offline multiple-window remediation, replay-ledger scaffold,
explicit-synthetic-base native ledger store, pure executable-trust decision
seam, disconnected ledger location constructor, disconnected native trust API
adapter, and native boundary inventory are implemented and must pass the full
safe regression matrix. The next safe offline work is an independent unsafe
audit of both disconnected native boundaries, plus a provenance design for a
repository-owned signed fixture and canonical install-root rule. Neither task
requires or authorizes a real KakaoTalk path/signature probe.
The failed L10 result does not authorize another live observation.

A future retry of DAG node L10, documented in
[`manuals/read-only-doctor-dry-run.md`](manuals/read-only-doctor-dry-run.md),
is a new live read-only KakaoTalk/UIA session and is **not authorized by this
handoff**. It requires environment/selector remediation followed by fresh user
approval naming L10, and must preserve focus, composer, clipboard, and all
user data.

L20 through L40 remain blocked both by sequence and by missing production
selectors. L20 modifies the composer, L30 reserves submission for the user,
and L40 requires a separate immediate approval for exactly one automatic
self-chat commit. `R00` cannot complete until those gates do; do not mark it
complete based on I20.
