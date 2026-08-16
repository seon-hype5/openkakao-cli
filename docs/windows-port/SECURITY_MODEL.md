# Windows MVP security model

## Assets and primary hazard

The protected assets are the user's account, conversation privacy, current
draft, target correctness, and freedom from duplicate submission. The primary
hazard is mutating or submitting to an unintended chat because a title,
window, process, or UI Automation element became ambiguous or stale.

## Deny-by-default rules

- Only a deterministically verified self-chat may progress beyond inspection.
- Matching is exact and unique; partial, glob, regex, normalization, case
  folding, zero candidates, and duplicates are refusals.
- Unsupported KakaoTalk versions are read-only.
- Existing drafts, stale snapshots, user activity, modals, session mismatch,
  integrity mismatch, and multiple composers are refusals.
- Message input rejects empty text, NUL/control characters, CR/LF, and the
  configured conservative length limit.
- Stage/commit require explicit approval; dry-run is the default.
- An uncertain commit is never automatically retried.

## Privacy

Message text and real room/profile names are forbidden in Debug, Display,
errors, JSON, logs, fixtures, screenshots, and committed artifacts. Read-only
diagnostics use length, state booleans, and execution-scoped fingerprints.

No KakaoTalk data directory, database, token, cookie, credential, process
memory, injection, hook, unofficial login, or telemetry is used by this port.

## UI mutation boundary

Wave 1 permits no UI mutation. Future mutation code is isolated behind
`MessageSender` and accepts only `ApprovedSend`. It may not use the clipboard,
global keys, forced focus, guessed control messages, or automatic retry.

Cross-process synchronous queries must use `SendMessageTimeoutW`. Unsafe calls
must document handle ownership, pointer validity, buffer length, COM apartment
lifetime, and the mapping from native failure to structured refusal/error.

## Test policy

Automated tests use fake backends and synthetic labels/messages only. A dry-run
test verifies stage and commit call counts remain zero. Live KakaoTalk UI tests,
stage-only, manual submit, or automatic submit are outside this session and
require fresh explicit approval under the separate safety runbook.
