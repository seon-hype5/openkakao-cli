# Abort, rollback, and troubleshooting

> **Applies to L10–L40. It does not authorize any gate or live action now.**

## First response

On ambiguity, unexpected UI change, private output, process replacement,
timeout, or user activity:

1. Stop issuing automation calls.
2. Do not force-close the application or change focus to investigate.
3. Preserve the user's visible state; do not search, navigate, or reopen a
   room.
4. Classify whether commit definitely did not begin. If that cannot be proved,
   mark the outcome `indeterminate` and `retry_safe=false`.
5. Tell the user what category failed using fixed error/evidence codes only.

## Safe rollback boundary

"Rollback" applies only to an unsubmitted staged value:

| State | Allowed response |
|---|---|
| No stage call occurred | Stop; nothing to restore |
| Composer is exactly root's current synthetic canary | Restore the proven prior empty value once, then verify empty |
| Composer differs or user activity is possible | Leave it unchanged and alert the user |
| Commit call began | Never clear, retry, delete, recall, or compensate automatically |
| Stage-only is durable `Indeterminate` sequence 2 and the exact owned draft remains | A newly confirmed commit may use the reviewed recovery path once; it must promote to terminal sequence 3 before submit |
| Any other indeterminate state | Stop and ask the user to inspect out of band; never retry |

Never restore an assumed prior draft. Existing or unknown input is user-owned.

## Stable exit-code triage

| Exit | Meaning | Response |
|---:|---|---|
| 2 | Usage or input refusal | Correct offline syntax/input only; do not weaken validation |
| 10 | App/capability unavailable | Stop the gate; verify support before a later approved session |
| 11 | Target refused | Stop; never broaden or normalize matching |
| 12 | Composer, draft, modal, activity, or stale-state refusal | Preserve UI state and stop |
| 13 | Session, integrity, permission, or profile refusal | Stop and resolve the environment outside the live gate |
| 20 | Backend failure before commit | Stop; no automatic rediscovery/continuation |
| 21 | Mutation/submission indeterminate | Never retry a submit. Only the exact stage-only sequence-2 recovery contract may resume before any prior submit call |

## Troubleshooting limits

Allowed offline troubleshooting:

- reproduce with synthetic fakes;
- inspect fixed error codes and mutation counters;
- rerun fmt, Clippy, safe tests, and build in an isolated repository target;
- compare reviewed selector metadata against documented constants; and
- review source without opening application state.

Not allowed:

- screenshots, screen recordings, raw UI trees, private console transcripts,
  memory dumps, crash dumps, hooks, injection, guessed messages, or remote
  memory;
- legacy doctor/local-data diagnostics on Windows;
- credential, token, cookie, session, account-data, or database inspection;
- weakening exact/unique matching, TTL, draft, modal, user-activity, approval,
  mutex, or retry rules; or
- creating an artifact first and attempting to redact it later.

If fixed codes are insufficient, stop and open a contract/privacy RFC using
only synthetic reproduction. Do not collect more live material.

## Privacy incident

If unexpected private material appears, do not paste, upload, commit, or quote
it. Stop the gate, prevent further artifact creation, tell the user that a
privacy incident occurred without repeating the content, and follow the
[artifact privacy policy](artifact-privacy.md). Any later cleanup or deletion
requires an exact target review and user direction.
