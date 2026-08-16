# Windows MVP security model

## Assets and primary hazards

The protected assets are the user's account, conversation privacy, target
correctness, current draft, and freedom from duplicate submission. The main
hazards are writing to the wrong chat, destroying an existing draft, racing a
user or restarted process, leaking message/target material, and retrying an
uncertain submission.

## Deny-by-default authorization layers

A Windows UI write is unavailable unless every independent layer permits it:

- the binary was built with the default-off `windows-ui-write` feature;
- `safety.allow_windows_ui_write` is explicitly true;
- the backend advertises the required send capability;
- the requested target occurs exactly once in the configured allowlist;
- the request is self-chat, stdin-only, opened-only, explicitly confirmed,
  and within the fixed input limits;
- policy evidence proves a supported profile, exact unique self target, empty
  draft, no focus/modal, compatible process/session/integrity, and a fresh TTL;
- a process-local approval mutex and hashed one-use nonce are available;
- a zero-wait named Windows mutex provides cross-process exclusion;
- fresh transaction state exactly matches the approved state; and
- final native PID/HWND/path/process-creation/session/UIA evidence still
  matches immediately before the atomic execution claim.

The current production backend deliberately advertises no send capability.
It has no privacy-safe target identity proof and no measured commit selector,
so no amount of CLI flags or configuration can currently reach `SetValue` or
`Invoke`.

## Target, state, and replay rules

- Only a deterministically verified self-chat may progress beyond inspection.
- Matching is byte-exact and unique; partial, normalized, case-folded, absent,
  unreadable, or duplicate candidates are refusals.
- PID alone is insufficient. A run-local digest includes executable identity
  and process creation time, and native preflight requeries both.
- Existing, unknown, or changed drafts; stale snapshots; user focus; modals;
  session/integrity mismatch; and ambiguous windows/composers are refusals.
- Snapshot validity uses a half-open interval: equality with expiry is stale.
- One approval is consumed by one synchronous reviewed sender call. A
  crate-private atomic claim prevents a second native write attempt.
- Policy nonce tracking is process-local and hashed. Durable replay storage is
  intentionally not introduced while production commit remains unavailable.

## Message and output privacy

Windows message input is accepted only from stdin. Acquisition stops after
4,001 raw bytes so overflow is detected before constructing the final String.
Accepted input is capped at 4,000 valid UTF-8 bytes and 1,000 Unicode scalar
values and rejects empty/all-whitespace text, NUL/control characters, CR/LF,
U+2028, and U+2029.

Temporary input buffers are zeroized on read, overflow, and UTF-8 failures;
`SecretMessage`, intent, approved nonce material, and native UTF-16/BSTR
buffers are scrubbed on release. Debug, Display, JSON, human output, errors,
fixtures, screenshots, and committed artifacts must never contain message
text, real room/profile names, draft text, HWND, or UIA runtime IDs.

The production read-only probe does not read window titles, UIA Name/Value,
room/profile labels, or draft contents. Reports contain only fixed allowlisted
action/profile/evidence/operation codes and run-local fingerprints. Unknown
operation strings are replaced with `redacted_operation` in both streams.
A rejected legacy positional message is handled by generic parse output so
clap cannot echo it.

No KakaoTalk data directory, database, token, cookie, credential, process
memory, injection, hook, unofficial login, or telemetry is used by this port.

## Mutation and uncertainty rules

The guarded implementation uses UIA ValuePattern and InvokePattern only. It
does not use the clipboard, global keys, forced focus/Z-order, guessed window
messages, or retries.

Stage clears only an exactly read-back value that remains byte-for-byte owned
by the transaction. If the user or provider changes it, the code leaves it
untouched. Commit requires an exact unique Invoke selector and issues at most
one Invoke. Every error or panic after Invoke begins is normalized to
`SubmissionUncertain`; commit-attempt outcomes and errors are always
`retry_safe=false` and exit 21. A sender result incompatible with the approved
mode is treated the same way.

The Windows named mutex is held across observation, final validation, write,
readback, restore, or Invoke. Abandoned ownership is a refusal, not permission
to continue. Native UI work stays synchronous so neither the approval lease
nor mutex outlives the transaction invisibly.

## Remaining security blockers

- No privacy-safe measured selector proves that the current room is the
  requested self-chat.
- No live-measured exact unique send-button selector/InvokePattern is
  configured.
- Signing and canonical installation-root verification are absent.
- Modal evidence remains narrower than a full application-wide model.
- A blocked third-party UIA provider cannot be safely cancelled in-process.
  Read-only discovery is process-wide single-flight, so one timed-out worker
  blocks later probes instead of allowing retained workers to accumulate.
- Cross-process exclusion exists, but durable cross-process replay history is
  not yet designed.

These are blockers to enabling production write capability, not reasons to
weaken the gates.

## Test and live-validation policy

Automated gates may compile all features and exercise fake/synthetic ports,
but must not launch a live UI probe or product write command. CI has no
credentials, app setup, secret injection, UI dump, screenshot, trace, or
artifact upload.

L10 read-only inspection and L20-L40 mutation validations require their own
fresh approvals. I20, a green build, or the existence of guarded native call
sites authorizes none of them.
