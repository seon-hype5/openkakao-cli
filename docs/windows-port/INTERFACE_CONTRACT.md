# Windows MVP interface contract v1

Status: the public schema remains v1; Wave 2 adds deny-by-default internal
execution guards without changing serialized report fields.

## Capabilities and snapshots

The platform facade exports:

- `UiCapabilities`;
- `AppSnapshot`, `ChatTargetSnapshot`, `InputSnapshot`, `UiSnapshot`, the fixed
  `ReadOnlyWindowAmbiguity` diagnostic enum, and its opaque bounded
  `ReadOnlyCandidateBlockers` detail, plus opaque bounded
  `ReadOnlyComposerSelectorEvidence`;
- `InspectRequest`, opaque `TargetBindingEvidence`, `TargetKind`, and
  `PlatformProbe`;
- `MessageSender`, `SendIntent`, `SecretMessage`, and `ApprovedSend`;
- `SendMode`, `SendOutcome`, `UiError`, and `UiErrorKind`; and
- `ActionReport`, `BackendKind`, `ExitCode`, and exact-match helpers.

Snapshots contain only process/window/composer fingerprints and bounded state.
Raw room/profile names, draft text, message text, HWNDs, creation FILETIMEs, and
UIA runtime IDs are excluded. Target-binding evidence has no byte accessor,
formats only as redacted, and is skipped by serde, so schema v1 is unchanged.
The read-only ambiguity enum is likewise skipped by snapshot serde. Reports
translate it to exactly one allowlisted content-free evidence code; no raw
candidate count or native identifier is added to the report schema.

## Inspection semantics

`PlatformProbe::inspect` is read-only: no focus, Z-order, clipboard, input
value mutation, room selection, network change, or submission.
`inspect_dry_run` accepts only that trait.

Plain `doctor --ui` does not read window titles, UIA Name/Value, room/profile
names, or draft text. A target-bound inspection may read only the uniquely
selected root's Name for an exact in-memory UTF-16 comparison and, after a
successful binding, the exact composer's Value reduced to an empty/nonempty
bit. It may return a diagnostic snapshot for cleanly observed absent,
ambiguous, unknown-profile, or mismatched-target states; native/COM failures
remain `UiError`.

When multiple visible exact-class candidates cannot be narrowed, the internal
snapshot distinguishes only five content-free classes: candidate limit,
duplicate exact composers, an internally ambiguous composer, an uninspected
candidate, or no exact composer. The classification order is deterministic.
Any class is policy-rejected as `AmbiguousTarget` and is included in the opaque
target-binding HMAC, so it cannot be moved to an otherwise acceptable snapshot.
For the uninspected-candidate class only, existing observation booleans are
unioned across candidates into fixed blocker classes. Reports expose no count,
candidate association, or raw bitset; they append only allowlisted codes for
executable trust, UI profile, visibility, enabled/modal, session, and integrity
failure classes. No additional native or UIA observation is performed.
If one known-profile window has no full composer match, the read-only backend
may additionally test only the three exact two-property subsets of the reviewed
class/AutomationId/control-type selector. It retains existence booleans only
and reports fixed near-match classes without values, counts, or element
associations. This state is serde-skipped, target-bound, and policy-rejected.
The supported v2 selector is exactly `RICHEDIT50W`, AutomationId `1006`, and
Document control type. v1's Edit triple is not a fallback.

Worker startup and native inspection share one eight-second budget. After the
worker has enabled cancellation and published its pinned thread ID, expiry
causes exactly one zero-wait COM cancellation request. The public result is
still `Timeout` with `retry_safe=false`; no completion arriving after the
deadline is consumed. A provider without a usable cancel object retains the
process-wide single-flight lease until its call actually returns, so another
backend instance cannot accumulate a second worker. Expiry before readiness
cannot target a thread and instead makes the worker stop before inspection
when it reaches the closed inspection-permit channel.

After exact executable-name verification, `AppSnapshot.modal_present` is true
for a disabled selected window or a visible, owned, same-process top-level
popup in the selected window's root-owner group. The scan uses only
HWND/PID/visibility/owner metadata and retains no candidate identifier.
Hidden, foreign-process, unowned, and
different-root-owner candidates do not set the flag; an uncertain relevant
owner-chain query returns an error. Any positive modal result suppresses
composer identity and input-availability evidence in the snapshot.

Policy inspection differs from ordinary doctor inspection only by an opaque,
request-scoped binding challenge. A probe can mint evidence only by supplying
an exact observed UTF-16 label to the request. HMAC-SHA-256 binds the match to
the complete redacted process/window/composer/time/input snapshot; the policy
retains the key and rejects missing, replayed, mismatched, or moved evidence.
When constructing the opaque binding, the configured label is streamed through
UTF-16 encoding without a secondary UTF-16 buffer and must fit the same
512-unit bound as an observed Name. The Windows candidate reads the selected
root Name into a scrubbed BSTR before and after the guarded draft read. Both
observations must bind to the same request; otherwise the draft bit is discarded
and inspection refuses.
Reports emit `draft_empty` or `draft_present` only when that guarded read is
proven to have occurred. Plain doctor, mismatch, focus, or any other skipped
read emits `draft_unobserved`; the fail-closed internal false bit is not
misreported as evidence of a real draft.

The exact profile treats a zero native text length, one source-static
placeholder UTF-16 digest, or the exact post-submit two-carriage-return value as
empty. SetValue ownership accepts only the exact message or that message plus
one provider carriage return. Other control-only shapes remain nonempty.
Neither provider text form is serialized or formatted.

## Mutation capability semantics

`MessageSender` is public for invocation but sealed against external
implementations. The only reviewed implementations are the synthetic fake and
Windows backend. Its methods still borrow `ApprovedSend` internally, but no
public API lends that value: callers receive `ApprovedOperation`, whose
`execute` method consumes the operation and retains its policy mutex for the
entire synchronous sender call.

`ApprovedSend` privately carries both the approved Unix-millisecond timestamp
and a process-local monotonic deadline derived from the snapshot's remaining
lifetime. Neither adds a serialized field or public accessor. Equality with
either expiry is stale. Policy refuses a reached monotonic deadline before
sender dispatch, and the Windows implementation repeats both clock checks at
native observation, final preflight, and the actual mutation boundary. System
clock rollback therefore cannot lengthen an approval.

The Windows sender independently validates mode and fresh evidence and uses a
crate-private atomic one-shot execution claim immediately before its first
write attempt. Policy then validates the returned outcome against the
dispatched mode. An incompatible successful result is normalized to
`SubmissionUncertain`.

Fresh observation and final native preflight repeat the owner-group modal
scan. The native port repeats it once more at each actual `SetValue` or submit
boundary, followed by the two-clock freshness check and native call.
A positive final preflight returns `ModalPresent` with the fixed allowlisted
operation `windows_mutation_modal`; uncertainty never becomes modal absence.
After the one-shot claim and entry into a Value/Invoke method, the transaction's
existing conservative uncertainty boundary still applies even if this last
gate refuses before the OS call. The generic owner-chain rule conservatively
blocks visible modeless owned popups as well, but cannot prove the absence of
unowned or in-window custom overlays.

An approved operation retains the opaque target-binding permit. The native
mutation port borrows that exact approval through the synchronous operation;
its label verifier is fixed to the approval's private policy-bound snapshot and
accepts no caller-selected snapshot. The state machine requires independently
fresh `target_binding_verified` evidence in addition to separate exact and
unique claims before draft access or any mutation, and repeats the same
approval-owned check in final native preflight. A target-bound inspection may
now carry the selected root's ephemeral UTF-16 UIA Name only from an exact
profile/root/composer path. Exact match creates opaque evidence; mismatch is
unique-inexact. The Name BSTR is never decoded or retained and is scrubbed
before COM release. Plain doctor inspection carries no binding request and
continues to read no Name or Value. Inexact and ambiguous states cannot mint
evidence or supply contradictory booleans.

Only a valid exact binding can authorize a guarded exact-composer Value read.
The Value BSTR becomes one empty/nonempty bit and is scrubbed; target evidence
is then rebound to the complete final snapshot. This selector is not yet
positive/negative measurement-qualified, so these interfaces still supply no
production capability.

The native transaction is compiled only by the default-off
`windows-ui-write` feature. This feature is not authorization. Runtime also
requires `safety.allow_windows_ui_write=true`, an exact allowlist, explicit
confirmation, and a backend send capability. The current production backend
always reports that capability false, in both default and all-feature builds.

## Outcomes, errors, and retry rules

Outcomes are:

- `dry_run`;
- `staged_and_restored`;
- `commit_issued`;
- `echo_confirmed`;
- `submitted_unverified`;
- `not_submitted`; and
- `indeterminate`.

`commit_issued`, `echo_confirmed`, `submitted_unverified`, and `indeterminate`
all have `attempted=true` and `retry_safe=false`. A commit report carrying any
of those uncertain/attempted states exits 21. `SubmissionUncertain` errors also
exit 21 and override any incorrectly supplied retry flag.

Once the first `SetValue` method is entered, every error or panic through
readback, validation, clear, restore, or commit preparation is non-retryable
uncertainty. Once submit is entered, every returned error or panic is
submission uncertainty. Profile v3 focuses the exact target/composer, repeats
the foreground/focus/draft proof, and queues one Enter keydown/key-up pair to
that exact composer HWND. There is no global input or automatic retry.

A commit approval derived from a nonempty snapshot is marked for stage-only
recovery and is valid only when the sealed backend advertises that capability.
The backend must find the exact sequence-2 stage-only ledger record, prove the
exact live message and all fresh gates, durably promote to terminal sequence 3,
and submit once without SetValue or clear. Normal approvals cannot enter this
branch, and focus/foreground activity still refuses.

## Windows CLI contract

The Windows surface is:

```text
openkakao-cli doctor --ui [--json]
openkakao-cli local-send --stdin --opened-only \
  [--dry-run | --stage-only --yes | --commit --yes] [--json]
```

Dry-run is the default. Staging and commit are guarded requests, not a promise
of availability. They fail before stdin or UI inspection unless both the
Windows-specific runtime gate and backend capability are present. The default
build remains read-only; the default-off feature build exposes only the guarded
profile-v3 path.

Stdin is the only Windows message path and is capped at 4,000 valid UTF-8 bytes
and 1,000 Unicode scalar values. Windows accepts neither a target nor message
positional; it resolves only a sole configured allowlist entry. Mode, config,
backend capability, policy configuration, and allowlist checks occur before
message acquisition where applicable. Any rejected positional is never echoed
in parse output.

The safety policy performs one inspection. Dry-run reports the exact retained
redacted snapshot; write authorization passes the same approved evidence into
a fresh transaction revalidation instead of trusting it as current state.

## JSON contract

`ActionReport` schema version 1 contains action, platform, backend, UI profile,
target kind, attempted, outcome, evidence, and retry safety. Report fields and
operation diagnostics are normalized through closed code allowlists. Unknown
strings become fixed redacted values. Request keys, label tags, and target
binding evidence are not serialized.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success or intended dry-run |
| 2 | CLI usage/input error |
| 10 | app or capability unavailable |
| 11 | target refused |
| 12 | composer/draft/user-state refusal |
| 13 | permission/session/profile refusal |
| 20 | backend failure proven before commit/mutation uncertainty |
| 21 | mutation/submission indeterminate; never retry automatically |

## Compatibility

The macOS implementation remains in place and continues to use
`safety.allow_ax_send`. Windows uses the separate
`safety.allow_windows_ui_write` flag, so an existing macOS opt-in cannot grant
Windows UI-write authority. Linux and unsupported stubs remain buildable.
Windows-only dependencies and the write feature are target-scoped/additive.
