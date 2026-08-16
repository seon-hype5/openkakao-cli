# Root read-only COM cancellation handoff

Date: 2026-08-17 KST

Status: timed-out read-only COM calls receive one bounded cancellation request;
production mutation remains unreachable and fail-closed

Reviewed predecessor: `d4532399d00438eb7489fdb20f06ed95c768c7b3`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

The read-only Windows probe now enables COM call cancellation on its fresh,
windowless MTA worker before inspection. Only after enable succeeds does the
worker publish its OS thread ID. Worker creation, readiness, and native
inspection share the existing eight-second budget. The caller grants an
inspection permit only after receiving readiness within that budget, and the
worker rechecks the deadline before native entry. A timeout closes the permit,
so a readiness event racing the boundary cannot start inspection afterward.

On expiry after readiness, the caller retains a release sender while it makes
exactly one zero-wait `CoCancelCall` request for that thread ID. The worker
cannot exit and its ID cannot be recycled until the caller releases it. A Rust
unwind after readiness is caught as a fixed worker error and observes the same
pinned lifetime. A normal completion disables cancellation while COM remains
initialized, releases the worker, and joins it before returning. Expiry still
returns `windows_read_only_inspect` with `retry_safe=false` and consumes no
late result.

The caller temporarily initializes COM only when needed and balances a
successful initialization. An already initialized apartment is accepted via
`RPC_E_CHANGED_MODE`. `S_OK`, `RPC_E_CALL_COMPLETE`, and
`RPC_E_CALL_CANCELED` are terminal request results; other results do not alter
the worker-owned single-flight lease. Every successful cancellation enable
receives one disable attempt, and the fresh thread's `CoUninitialize` resets
the state if disable reports failure.

This is client-side containment, not proof of server termination. Standard
marshaling may unblock the client; custom marshaling may expose no cancel
object, and the server may continue processing. The lease therefore remains
with the worker until the native call really returns. This is safe only for the
metadata-only probe. The mutation worker remains synchronous, joined, and
cancellation-disabled.

No Cargo feature or dependency changed. The existing
`Win32_System_Com`/`Win32_System_Threading` bindings provide the four native
entry points.

## Changed surface

- `src/platform/windows/mod.rs`: total-budget event protocol, pinned release
  handshake, unwind containment, and single cancellation dispatch;
- `src/platform/windows/native.rs`: cancellation enable/disable RAII, worker
  thread publication, caller COM balance, and terminal HRESULT classifier;
- `src/output/windows/mod.rs` and `tests/windows_cli/mod.rs`: closed redacted
  operation-code coverage; and
- Windows architecture, security, interface, activation, CI, decision, and
  handoff documentation.

## Synthetic verification

Pure tests cover saturating total-budget arithmetic, pre-readiness permit
closure, terminal cancellation HRESULTs, and a coordinated synthetic worker
proving cancellation runs before thread release and runs once. The tests do
not sleep, call a native COM API, enumerate windows, invoke UIA, launch an
application, or inspect KakaoTalk.
The complete safe matrix and final counts are recorded in
[`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md).

One initial grouped contract run was denied before process creation by the
host's application-control error 4551. It reached no CLI command or assertion.
The isolated safe case, the full two-test contract target, and all fourteen
closed-allowlist CLI cases subsequently passed without changing source or
policy. The final matrix records the clean results.

No doctor, KakaoTalk/UIA probe, local-state or credential command,
`CoEnableCallCancellation`, `CoCancelCall`, known-folder resolution, stage,
`SetValue`, `Invoke`, or send ran. No UI focus, Z-order, clipboard, keyboard,
window-message, hook, injection, or process-memory action occurred.

## Remaining blockers

1. A custom-marshaled or otherwise unsupported provider may remain hung. Its
   worker keeps the single-flight lease until return or process exit.
2. Provider-side work may continue after the client unblocks. The native
   cancellation path is compiled and linted but has not been exercised against
   a live UIA provider; compatibility and performance remain unmeasured.
3. No approved, measured, version-bound self-chat selector or ephemeral label
   observer exists.
4. No exact unique submit selector or production `InvokePattern` exists.
5. Independent native unsafe/root review and a clean pinned Windows CI run
   remain external requirements.
6. Reviewed Kakao signer/root provenance and production trust wiring remain
   absent; `UnavailableExecutableTrust` stays wired.
7. L10 retry and L20-L40 remain unauthorized and blocked.

This handoff grants no live observation, UI mutation, send, or
capability-activation authority.
