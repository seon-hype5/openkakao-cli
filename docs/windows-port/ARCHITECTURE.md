# Windows MVP architecture

## Scope and current state

The Windows release-candidate path is a fail-closed, UI-only integration for
an already-open KakaoTalk self-chat. It does not log in, access KakaoTalk files
or databases, inspect process memory, select or open rooms, synthesize keys,
use the clipboard, or force focus or Z-order.

The default build excludes native UI write call sites and remains read-only.
The default-off `windows-ui-write` build exposes a guarded send capability for
the exact known executable/UI profile. KakaoTalk `26.7.0.5255` exposes no
separate send element or InvokePattern, so that profile submits with one
bounded synchronous Enter window message sent directly to the freshly
revalidated composer HWND. Runtime opt-in and every policy/transaction gate
remain mandatory.

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
  stage/readback/restore   one submit attempt
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
- classify the selected window as modal-blocked when it is disabled or a
  visible same-process owned top-level popup belongs to the same root-owner
  group, using only HWND relationship metadata;
- when several exact-class windows exist, narrow them only if exactly one has
  one exact composer and every other inspected window has no exact composer;
- classify zero, one, duplicate, internally ambiguous, or over-limit
  candidates without guessing;
- perform a server-side exact UI Automation search for composer metadata on a
  dedicated windowless MTA thread; and
- for a target-bound request only, compare the selected root's UIA Name in
  scrub-on-drop UTF-16 memory and, after an exact match only, reduce the exact
  composer's Value to an empty/nonempty bit; and
- return run-local fingerprints and structured refusal evidence.

Read-only workers are process-wide single-flight. If a third-party UIA
provider does not return within the single eight-second startup-and-inspection
budget, the caller makes one zero-wait `CoCancelCall` request only after the
worker has enabled COM call cancellation and published its pinned OS thread
ID. Readiness grants an inspection permit only while the total budget remains,
and the worker rechecks it before native entry. The caller keeps that thread
alive through the request so ID reuse cannot target an unrelated call, then
returns the same non-retryable timeout without consuming a late result.

Standard-marshaled synchronous calls may unblock the client worker, but the
server may continue and custom marshaling may expose no cancel object. The
worker therefore keeps the single-flight lease until its native call actually
returns; later probes refuse without spawning another worker. Cancellation is
enabled only for this bounded read-only worker. The synchronous mutation
worker remains joined and does not use this cancellation path.

The known profile is KakaoTalk `26.7.0.5255`, top-level class
`EVA_Window_Dblclk`, and composer class `RICHEDIT50W`, AutomationId `1006`,
with Document-control metadata. The selector is profile revision v2; it has no
Edit fallback. This matches Microsoft's standard-control mapping of RichEdit
to the UI Automation Document control type. Unknown or ambiguous profiles fail
closed.

The normal `doctor --ui` path does not read window titles, UIA Name or Value
properties, room/profile labels, or draft text. It consequently leaves
`exact_match`, `unique_match`, `self_chat_verified`, and `draft_empty` false.
The renderer reports this as `draft_unobserved`, not `draft_present`.
A target-bound `local-send` inspection is narrower: it accepts no target on the
command line, requires exactly one configured allowlist entry, and reads only
the selected root's `CurrentName` BSTR for an exact UTF-16 comparison. The
process/root/modal/composer path is revalidated on both sides of that read. A
successful match alone permits one exact-composer `CurrentValue` read, reduced
to `draft_empty`. The root Name is read and bound again afterward; a mismatch
discards the bit and refuses. All BSTRs are scrubbed without decoding or output.

Only after exact executable-name verification, modal discovery separately
enumerates top-level windows but retains only a boolean. A candidate blocks
when it is visible, belongs to the selected PID, has an owner, and has the same
`GA_ROOTOWNER` as the selected window. Hidden, foreign-process, unowned, and
different-root-owner windows do not block.
Every visible owned popup in that group is deliberately treated as blocking,
even if it could be modeless. Missing owner-chain metadata fails closed. When
modal evidence is present, composer traversal is skipped and the public
snapshot suppresses any composer identity or input-availability evidence.

For policy inspection, a per-request random HMAC key and the configured label
tag are hidden inside `InspectRequest`. A probe receives no raw configured
label. It can return opaque evidence only after an exact UTF-16 candidate
match; that evidence commits to the entire redacted snapshot and is omitted
from every serialized report. Replays under another request key and evidence
moved to another state refuse. When the draft bit changes after its guarded
read, a second scrubbed Name observation must match before evidence is
recomputed against the complete final snapshot.

This selector remains a candidate, not production proof. Twenty separately
opened positive observations and the ordinary/group/open/main/popup/duplicate
negative matrix are still required, so `send_open_chat` remains false.

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

The default build fails item 3. The feature build passes it only as a static
capability declaration; every later runtime gate can still refuse. The
separate Windows configuration flag prevents a macOS `allow_ax_send` opt-in
from silently authorizing Windows writes.

`ApprovedOperation::execute` consumes the approval while retaining the policy
mutex for the synchronous call. `MessageSender` is sealed to reviewed crate
implementations. Each implementation validates the approved mode, and the
policy validates the returned outcome: stage accepts only
`StagedAndRestored`; commit accepts only commit-attempt outcomes. Any mismatch
becomes `SubmissionUncertain` and is never retry-safe.

Authorization pairs the validated Unix-millisecond snapshot time with a
process-local monotonic `Instant`. The remaining wall-clock lifetime is sealed
as a private deadline in `ApprovedSend`; it is omitted from Debug and cannot be
serialized. `execute` checks it before sender dispatch. A system-clock rollback
therefore cannot extend the approval, while a forward jump can only make the
independent wall-clock checks refuse earlier. Both intervals are half-open.

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
half-open wall-clock expiry interval plus the approval-owned monotonic
deadline. The deadline is checked before worker/native entry, before consuming
the transaction correlation, before every native observation, at final
revalidation, and immediately before each `SetValue` or `Invoke`. A separate
fresh target-binding flag is mandatory; the prior self/exact/unique booleans
cannot substitute for it. The native boundary immediately requeries the PID,
HWND, executable path, process creation time, session, integrity, and exact UIA
element before the execution claim.

The same owner-group modal scan runs during fresh observation, final native
preflight, and again immediately before each actual `SetValue` or `Invoke`.
The last scan is followed by the approval time check and native call, leaving
no intentionally intervening UI operation. A selected window that becomes
disabled is also blocking. Generic owner-chain evidence cannot identify an
unowned custom overlay or an in-window overlay; activation still requires
negative live measurements and any version-specific rule needed for those
states.

The native mutation port borrows the same `ApprovedSend` for the entire
synchronous transaction. The ephemeral target label is compared only
through that approval, whose verifier is permanently tied to its private
policy snapshot; a native caller cannot supply a different snapshot. The
observer immediately reduces the result to booleans and retains no label.
Selection uses a closed internal state, and only its exact-unique variant may
carry a label or invoke the verifier; exactness and uniqueness are not supplied
as independent caller booleans. The current candidate constructs exact-unique
only after raw enumeration itself contains one root and its Name matches the
approval-owned permit. Its qualification gate remains closed until the required
positive and negative observations pass.

Stage-only is designed as:

1. observe and exactly match the approved state;
2. complete native preflight and classify the current draft;
3. claim the approval and call `SetValue` once;
4. require exact readback of the owned synthetic value;
5. clear only while the value remains exactly root-owned; and
6. require exact empty readback.

If user activity changes the value, the transaction never clears the mixed or
unknown draft. Commit performs the same preparation, requires the exact
profile-bound submit strategy, and makes at most one submit call. The current
profile uses `SendMessageTimeoutW` for one composer-targeted
`WM_KEYDOWN/VK_RETURN`; it does not synthesize global input or change focus.
Every failure or panic after that call begins is `SubmissionUncertain` with
`retry_safe=false`; there is no automatic retry edge.

## Threading and native resource ownership

UI Automation interfaces remain on the MTA thread that created them, and COM
initialization is balanced on that thread. Enumeration callbacks are bounded;
the modal callback retains no HWND collection or text and reduces candidate
metadata to booleans. Process handles use limited query access and are closed
on all paths. Message
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
