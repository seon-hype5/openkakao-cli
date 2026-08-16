# Root target-binding scaffold handoff

Date: 2026-08-17 KST

Status: complete offline scaffold; production target observation remains
unavailable and fail-closed

Predecessor tip:
`1e11569c69ba2d7fdf5b99f44abc5d33806ae75c`. The atomic commit containing
this document is its successor and must be reported outside the commit.

## Outcome

The safety policy no longer accepts an allowlist match and independent target
booleans as sufficient target identity evidence. Every policy inspection now
creates a fresh opaque target-binding request. A probe can attach evidence only
after presenting an exact observed UTF-16 label, and policy verifies that the
evidence belongs to the same request and the exact returned redacted snapshot.

This change does not add a KakaoTalk label reader, selector, live probe, or
write capability. The production Windows backend returns no target-binding
evidence, keeps all self-target evidence false, advertises
`send_open_chat=false`, and cannot reach draft Value, `SetValue`, or `Invoke`.

## Contract and privacy design

- A new random 32-byte key is generated for every policy inspection.
- Domain-separated HMAC-SHA-256 tags the configured label's exact UTF-16 code
  units. No Unicode, case, locale, or whitespace normalization occurs.
- The configured Rust string is streamed through `encode_utf16` twice, once
  for the unit count and once for HMAC input. No secondary label allocation is
  created.
- `InspectRequest` is no longer copyable or cloneable when it carries the
  opaque request material. It exposes only whether binding is required and an
  exact observed-UTF-16 verification method.
- The evidence HMAC commits to all redacted authorization snapshot fields:
  platform/process/session/version/window/composer/time/profile/target/input
  state. Moving evidence to another state fails.
- `TargetBindingEvidence` has private bytes, no accessor, redacted Debug, and
  `serde(skip)` storage in `ChatTargetSnapshot`. JSON schema v1 is unchanged.
- Request and approval secrets share one reference-counted allocation whose
  key and expected tag are zeroized when the last owner drops. Evidence bytes
  are also zeroized on drop.
- Different request keys reject replayed evidence. Missing, wrong-case,
  whitespace-changed, normalized/decomposed, and unpaired-surrogate candidates
  fail closed.

## Authorization and transaction gates

`WindowsSafetyPolicy::dry_run` and `authorize` now inspect with a bound request
and validate its permit at the target-snapshot boundary. Fixed allowlisted
errors distinguish binding refusal and RNG refusal without including dynamic
material. A write approval retains the private permit and rechecks its own
snapshot before the guarded transaction may construct expected state.

`FreshState` adds an independent `target_binding_verified` gate. The
transaction requires it with self/exact/unique evidence before any ledger
stage, execution claim, or mutation. Native draft classification and final
self-target preflight also require the fourth gate. The current native
observer always supplies false, so changing the older three booleans alone
cannot expose draft text or activate writes.

## Synthetic verification

All Rust artifacts used the ignored repository-local
`.target/wave2-root` directory. No product command or live backend was run.

- `cargo fmt --all -- --check`: passed.
- focused platform contract tests: passed.
- `cargo test --test windows_policy`: 24 passed.
- focused all-feature Windows transaction tests: 22 passed.
- default library suite: 169 passed.
- `cargo test --test windows_cli`: 2 passed.
- all-feature binary unit suite: 177 passed.
- all-feature lib/tests Clippy with warnings denied: passed.

Final full debug/release, compatibility, exact safe CLI, Markdown-link, and
diff gates are recorded in the integration handoff after they run.

## Files changed

- `src/platform/contract.rs`
- `src/platform/mod.rs`
- `src/platform/fake.rs`
- `src/platform/windows/mod.rs`
- `src/platform/windows/native.rs`
- `src/platform/windows/transaction.rs`
- `src/safety/policy.rs`
- `src/cli/windows/mod.rs`
- `src/output/windows/mod.rs`
- `src/main.rs`
- synthetic Windows policy/CLI fixtures and tests
- Windows-port contract, architecture, security, decision, activation, and
  handoff documentation

## Skipped and prohibited work

- no KakaoTalk window/title/UIA Name/Value/label observation;
- no real draft read, stage, clear, Invoke, or message submission;
- no KakaoTalk file, database, credential, token, cookie, or process-memory
  access;
- no screenshot, UI tree dump, OCR, clipboard, key input, focus, Z-order,
  hook, injection, network login, or telemetry;
- no L10 retry because the user has not issued the exact separate approval
  phrase required by the runbook;
- no push, pull request, release, or external CI execution.

## Residual activation blockers

1. A separately approved privacy measurement must establish a stable
   version-bound target selector and determine whether any label read is
   necessary. Ordinary L10 does not authorize that read.
2. If a label read is necessary, a native observer must keep it in one bounded
   zeroizing UTF-16 allocation, compare only through the opaque request/permit,
   scrub before COM release, and repeat immediately before mutation.
3. The exact positive/negative observation matrix in `ACTIVATION_RFC.md` has
   not run; therefore no production target profile exists.
4. No exact unique submit selector or InvokePattern profile exists.
5. Reviewed signer/install-root provenance and activation of the disconnected
   native trust adapter remain absent.

These are activation blockers, not reasons to weaken target evidence or turn
capability flags on. L20 through L40 remain blocked.
