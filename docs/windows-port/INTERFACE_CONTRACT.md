# Windows MVP interface contract v1

Status: the public schema remains v1; Wave 2 adds deny-by-default internal
execution guards without changing serialized report fields.

## Capabilities and snapshots

The platform facade exports:

- `UiCapabilities`;
- `AppSnapshot`, `ChatTargetSnapshot`, `InputSnapshot`, and `UiSnapshot`;
- `InspectRequest`, opaque `TargetBindingEvidence`, `TargetKind`, and
  `PlatformProbe`;
- `MessageSender`, `SendIntent`, `SecretMessage`, and `ApprovedSend`;
- `SendMode`, `SendOutcome`, `UiError`, and `UiErrorKind`; and
- `ActionReport`, `BackendKind`, `ExitCode`, and exact-match helpers.

Snapshots contain only process/window/composer fingerprints and bounded state.
Raw room/profile names, draft text, message text, HWNDs, creation FILETIMEs, and
UIA runtime IDs are excluded. Target-binding evidence has no byte accessor,
formats only as redacted, and is skipped by serde, so schema v1 is unchanged.

## Inspection semantics

`PlatformProbe::inspect` is read-only: no focus, Z-order, clipboard, input
value, room selection, network change, or submission. `inspect_dry_run`
accepts only that trait.

The Windows implementation does not read window titles, UIA Name/Value,
room/profile names, or draft text during normal inspection. It may return a
diagnostic snapshot for cleanly observed absent, ambiguous, or unknown-profile
states; native/COM failures remain `UiError`. Target identity and draft-empty
claims stay false in the current production profile.

Policy inspection differs from ordinary doctor inspection only by an opaque,
request-scoped binding challenge. A probe can mint evidence only by supplying
an exact observed UTF-16 label to the request. HMAC-SHA-256 binds the match to
the complete redacted process/window/composer/time/input snapshot; the policy
retains the key and rejects missing, replayed, mismatched, or moved evidence.
The configured label is streamed through UTF-16 encoding without a secondary
buffer. The current Windows probe does not read a label and therefore returns
no binding evidence.

## Mutation capability semantics

`MessageSender` is public for invocation but sealed against external
implementations. The only reviewed implementations are the synthetic fake and
Windows backend. Its methods still borrow `ApprovedSend` internally, but no
public API lends that value: callers receive `ApprovedOperation`, whose
`execute` method consumes the operation and retains its policy mutex for the
entire synchronous sender call.

The Windows sender independently validates mode and fresh evidence and uses a
crate-private atomic one-shot execution claim immediately before its first
write attempt. Policy then validates the returned outcome against the
dispatched mode. An incompatible successful result is normalized to
`SubmissionUncertain`.

An approved operation retains the opaque target-binding permit. The native
mutation port borrows that exact approval through the synchronous operation;
its label verifier is fixed to the approval's private policy-bound snapshot and
accepts no caller-selected snapshot. The state machine requires independently
fresh `target_binding_verified` evidence in addition to separate exact and
unique claims before draft access or any mutation, and repeats the same
approval-owned check in final native preflight. Current production observation
constructs only a closed absent-selection state and always leaves that evidence
false. Only a future exact-unique state may carry a label to the verifier;
inexact and ambiguous states cannot call it or supply contradictory booleans.

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
uncertainty. Once `Invoke` is entered, every returned error or panic is
submission uncertainty. There is no automatic retry.

## Windows CLI contract

The Windows surface is:

```text
openkakao-cli doctor --ui [--json]
openkakao-cli local-send SELF_CHAT_NAME --stdin --opened-only \
  [--dry-run | --stage-only --yes | --commit --yes] [--json]
```

Dry-run is the default. Staging and commit are guarded requests, not a promise
of availability. They fail before stdin or UI inspection unless both the
Windows-specific runtime gate and backend capability are present. The current
backend capability is absent, so production writes remain unavailable.

Stdin is the only Windows message path and is capped at 4,000 valid UTF-8 bytes
and 1,000 Unicode scalar values. Mode, config, backend capability, policy
configuration, and requested-label allowlist checks occur before message
acquisition where applicable. A rejected positional message is never echoed
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
