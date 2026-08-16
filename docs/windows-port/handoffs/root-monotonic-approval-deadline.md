# Root monotonic approval-deadline handoff

Date: 2026-08-17 KST

Status: the recorded wall-clock rollback lifetime risk is closed offline;
production mutation remains unreachable and fail-closed

Reviewed predecessor: `36cc84723f9aa6ba4c8e806b5aef57b405a9e494`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

The safety policy now captures a process-local `Instant` immediately before
its approved wall-clock read. After the existing snapshot validation, it adds
only the remaining lifetime to that anchor and seals the resulting private
deadline inside `ApprovedSend`. The deadline has no public accessor, is not
serializable, and is absent from custom Debug output.

An approval is fresh only while both its wall-clock interval and monotonic
deadline remain fresh. Equality with either boundary is stale. Policy execute
checks the monotonic deadline before sender dispatch. The Windows path checks
it before scoped-worker/native entry, before consuming the one-shot ledger
correlation, before every native observation, during final revalidation, and
immediately before the actual `SetValue` or `Invoke` call. Wall-clock checks
remain in place, so rollback cannot extend lifetime and a forward jump can only
refuse earlier.

## Synthetic verification

Tests use explicit synthetic future `Instant` values and a pure two-clock truth
table. They cover just-before/equal/after monotonic boundaries, prove zero
sender dispatch after monotonic expiry even while the snapshot wall time is
unchanged, and prove either clock independently refuses. No test sleeps or
changes the system clock.

The complete safe matrix and final counts are recorded in
[`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md). All artifacts stay under the
ignored repository-local `.target/wave2-root` directory.

No doctor, KakaoTalk/UIA probe, local-state or credential command, known-folder
resolution, stage, `SetValue`, `Invoke`, or send ran. No UI focus, Z-order,
clipboard, keyboard, window-message, hook, injection, or process-memory action
occurred.

## Remaining blockers

1. No approved, measured, version-bound self-chat selector or ephemeral label
   observer exists.
2. No exact unique submit selector or production `InvokePattern` exists.
3. Independent native unsafe/root review and a clean pinned Windows CI run
   remain external requirements.
4. Reviewed Kakao signer/root provenance and production trust wiring remain
   absent; `UnavailableExecutableTrust` stays wired.
5. L10 retry and L20-L40 remain unauthorized and blocked.

The deadline is intentionally process-local because the approval itself is a
nonserializing in-process capability; no approval can be restored after a
restart. This handoff grants no live observation, UI mutation, send, or
capability-activation authority.
