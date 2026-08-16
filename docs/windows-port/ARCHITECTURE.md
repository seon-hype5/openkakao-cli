# Windows MVP architecture

## Scope and current state

The Windows release-candidate path is a fail-closed, UI-only integration for
an already-open KakaoTalk self-chat. It does not log in, access KakaoTalk files
or databases, inspect process memory, select or open rooms, synthesize keys,
use the clipboard, or force focus or Z-order.

Wave 2 adds a guarded transaction implementation, but not a usable production
send profile. The default build excludes native UI write call sites. Even an
all-feature build advertises `send_open_chat=false` because the current
profile cannot privately prove self-chat identity and has no measured unique
send-button selector. Production stage and commit therefore refuse before
stdin or UI inspection.

```text
Windows CLI / redacted output
        |
        +--> mode + Windows-specific config gate
        |
        +--> exact allowlist preflight --> bounded stdin
        |
        v
Windows safety policy --> dry-run report
        |      `--> request-scoped exact target-binding proof
        |
        `--> consumed ApprovedOperation
                   |
                   v
          sealed MessageSender
                   |
                   v
       guarded Windows transaction
                   |
                   v
        final native revalidation
          /                  \
  stage/readback/restore   one Invoke attempt
```

`src/platform` contains platform-neutral snapshots, outcomes, errors, and
traits. HWND, COM, Windows API types, raw labels, draft text, and message text
do not cross that public snapshot boundary.

## Read-only discovery

The Windows backend may:

- enumerate exact-class top-level windows and inspect no more than eight in a
  single read-only probe;
- verify PID, executable path, file version, process creation time, session,
  integrity compatibility, and visible/enabled state;
- when several exact-class windows exist, narrow them only if exactly one has
  one exact composer and every other inspected window has no exact composer;
- classify zero, one, duplicate, internally ambiguous, or over-limit
  candidates without guessing;
- perform a server-side exact UI Automation search for composer metadata on a
  dedicated windowless MTA thread; and
- return run-local fingerprints and structured refusal evidence.

Read-only workers are process-wide single-flight. If a third-party UIA
provider does not return before the caller's eight-second deadline, the worker
keeps the lease until the native call actually finishes. Later probes refuse
without spawning another worker, and timeout is never automatically retried.
The process does not pretend it can cancel an in-flight COM provider call.

The known profile is KakaoTalk `26.7.0.5255`, top-level class
`EVA_Window_Dblclk`, and composer class `RICHEDIT50W`, AutomationId `1006`,
with edit-control metadata. Unknown or ambiguous profiles fail closed.

The normal inspection path does not read window titles, UIA Name or Value
properties, room/profile labels, or draft text. It consequently leaves
`exact_match`, `unique_match`, `self_chat_verified`, and `draft_empty` false.
`doctor --ui` can return this redacted diagnostic state; production
`local-send` cannot turn it into an approval.

For policy inspection, a per-request random HMAC key and the configured label
tag are hidden inside `InspectRequest`. A probe receives no raw configured
label. It can return opaque evidence only after an exact UTF-16 candidate
match; that evidence commits to the entire redacted snapshot and is omitted
from every serialized report. Replays under another request key and evidence
moved to another state refuse. This is an offline contract only: the Windows
probe has no observed-label reader and returns no proof.

Read-only narrowing does not apply to the native transaction path. Fresh
write observation and final mutation preflight still require raw top-level
enumeration itself to contain exactly one window. This asymmetry lets doctor
distinguish a normal non-composer application window from a composer-bearing
window without weakening any future mutation gate.

## Authorization boundary

Dry-run accepts only `PlatformProbe`, so mutation is unavailable in that call
graph. Write orchestration additionally requires all of the following:

1. the default-off Cargo feature `windows-ui-write` at build time;
2. `safety.allow_windows_ui_write=true` at runtime;
3. a backend advertising `send_open_chat=true`;
4. stdin-only input within 4,000 UTF-8 bytes and 1,000 Unicode scalars;
5. an exact, unique configured self-chat label;
6. an explicit `--stage-only --yes` or `--commit --yes` request; and
7. a fresh, fully validated policy snapshot whose exact observed target is
   bound to the requested allowlist entry by request-scoped evidence.

The production backend intentionally fails item 3. The separate Windows
configuration flag prevents a macOS `allow_ax_send` opt-in from silently
authorizing Windows writes in a future profile.

`ApprovedOperation::execute` consumes the approval while retaining the policy
mutex for the synchronous call. `MessageSender` is sealed to reviewed crate
implementations. Each implementation validates the approved mode, and the
policy validates the returned outcome: stage accepts only
`StagedAndRestored`; commit accepts only commit-attempt outcomes. Any mismatch
becomes `SubmissionUncertain` and is never retry-safe.

`ApprovedSend` also contains a crate-private atomic execution claim. The
Windows backend claims it only after all pre-mutation validation and
immediately before the first write attempt. Once claimed, every success or
failure path consumes the approval.

## Guarded transaction

The feature-gated transaction runs synchronously on a scoped MTA worker and
holds a zero-wait named Windows mutex across fresh observation, final native
validation, mutation, readback, and restoration. Contention, abandoned
ownership, timeout, poisoning, or stale evidence refuses without retry.

Fresh validation binds the approval to the platform, target, process ID,
executable-instance fingerprint, process creation time, session, HWND,
window/composer fingerprints, UI profile, modal/focus/draft state, and a
half-open expiry interval. A separate fresh target-binding flag is mandatory;
the prior self/exact/unique booleans cannot substitute for it. The native
boundary immediately requeries the PID, HWND, executable path, process
creation time, session, integrity, and exact UIA element before the execution
claim.

The native mutation port borrows the same `ApprovedSend` for the entire
synchronous transaction. Any future ephemeral target label is compared only
through that approval, whose verifier is permanently tied to its private
policy snapshot; a native caller cannot supply a different snapshot. The
observer immediately reduces the result to booleans and retains no label.
The current profile supplies no label and therefore keeps the fresh and final
target gates closed.

Stage-only is designed as:

1. observe and exactly match the approved state;
2. complete native preflight and classify the current draft;
3. claim the approval and call `SetValue` once;
4. require exact readback of the owned synthetic value;
5. clear only while the value remains exactly root-owned; and
6. require exact empty readback.

If user activity changes the value, the transaction never clears the mixed or
unknown draft. Commit performs the same preparation, requires an independently
verified exact Invoke selector, and makes at most one `Invoke` call. Every
failure or panic after that call begins is `SubmissionUncertain` with
`retry_safe=false`; there is no automatic retry edge.

The current native profile sets live self-target and target-binding evidence
false and its commit selector to unconfigured. It therefore never reaches
draft Value access, `SetValue`, or `Invoke` in production.

## Threading and native resource ownership

UI Automation interfaces remain on the MTA thread that created them, and COM
initialization is balanced on that thread. Enumeration callbacks are bounded;
process handles use limited query access and are closed on all paths. Message
and CurrentValue UTF-16/BSTR allocations have unique ownership and are scrubbed
before release. The transaction uses no detached mutation worker, so the
policy lease and OS mutex cannot be dropped before a reviewed sender returns.

## Verification boundary

Automated tests use synthetic snapshots, a fake backend, or an in-memory
transaction port. All-feature CI compiles the native boundary and runs only
the explicitly named synthetic Windows subtree. It does not execute the
product or contact a desktop application.

Live gates L10 through L40 remain separate manual activities. I20 completion
does not establish live selector compatibility, target identity, draft
safety, or submission correctness.
