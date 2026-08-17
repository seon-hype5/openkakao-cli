# Windows live-validation manuals

> **Status: documentation only. No L10 or later gate is authorized now.**

These manuals describe future, separately approved validation. Reading them,
merging them, or obtaining a green CI result does not authorize a live probe,
UI mutation, submission, data access, screenshot, or artifact capture.
Production-activation prerequisites are proposed separately in
[`ACTIVATION_RFC.md`](../ACTIVATION_RFC.md); that document is also not
authorization.

## Mandatory sequence

| Gate | Manual | Effect ceiling | Current status |
|---|---|---|---|
| L10 | [Read-only doctor and dry-run](read-only-doctor-dry-run.md) | Bounded read-only UI inspection; zero mutation | Not authorized |
| L20 | [Stage-only](stage-only.md) | Place one synthetic canary in an empty composer, then safely restore | Not authorized; product support absent |
| L30 | [User-manual-submit](user-manual-submit.md) | User submits one staged synthetic canary | Not authorized; product support absent |
| L40 | [One-shot automatic smoke](one-shot-automatic-smoke.md) | Automation issues exactly one approved commit | Not authorized; product support absent |

The sequence is strict. Failure, refusal, indeterminate evidence, missing
product support, or incomplete acceptance at one gate blocks every later gate.
Approval for one gate never carries forward to another gate or another
session.

## Authority and roles

- The user must give fresh, explicit approval naming the exact gate, scope,
  session, and one synthetic action before any live step.
- One root operator is the only automation controller during a live UI test.
  Child agents are stopped before the session begins.
- The user opens and visually verifies the self-chat. Automation never searches
  for or chooses a room.
- L30 reserves the submit action for the user. L40 requires a separate,
  immediate approval for one automated commit.
- No gate authorizes account-data, database, credential, token, process-memory,
  injection, hook, unofficial-login, or telemetry access.

## Universal privacy rules

Use only a session-generated synthetic canary. Never place real labels,
message bodies, user/chat identifiers, runtime identifiers, draft contents, or
screenshots in a manual, command transcript, issue, log, fixture, or committed
file. Output is reviewed under the
[artifact privacy policy](artifact-privacy.md).

Do not record raw UI trees or screen content. Keep execution-scoped secrets and
canaries in memory only and discard them at session end. A failure that might
have exposed private material is an immediate abort and privacy incident, not
a reason to gather more diagnostics.

## Common stop and recovery rules

Use [abort, rollback, and troubleshooting](abort-rollback-troubleshooting.md)
for every gate. In particular:

- never force-close the application;
- never continue automatically after process/window replacement;
- clear a staged value only when it is still exactly the session's own canary;
- never delete or recall an unintended submission automatically; and
- never retry an indeterminate commit.
