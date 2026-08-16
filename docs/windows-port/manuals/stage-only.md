# L20 stage-only validation

> **Gate L20 — NOT AUTHORIZED NOW. Current product support is absent.**

L20 may be considered only after L10 passes in a separately approved session
and a privacy-preserving design deterministically proves exact unique
self-chat identity and empty draft state. A transaction implementation now
exists behind the default-off `windows-ui-write` build feature, but the
production profile proves neither prerequisite and therefore advertises no
send capability. Do not run it merely to observe the refusal.

## Required fresh approval

Future approval must name L20, one session, one synthetic canary, and the fact
that the composer will be temporarily modified but nothing submitted. L10
approval does not satisfy this requirement. Root is the only automation
controller and all child agents remain stopped.

## Preconditions

- The exact build and mutation implementation have passed adversarial review
  and Windows synthetic CI.
- L10 evidence is current for the same session.
- The user has manually opened and visually verified the self-chat.
- Target and composer are exact and unique; process/session/profile evidence
  matches; no modal or user activity is present.
- The composer is proven empty. An unknown or nonempty draft is a refusal.
- The future implementation uses a reviewed value-staging API. Enter, button
  invocation, key input, clipboard, forced focus, and guessed control messages
  remain unavailable to L20.

## Future controlled procedure

1. Generate a single in-memory canary using the fixed synthetic prefix, UTC
   time, and a fresh nonce. It contains no link, mention, private data, or line
   break.
2. Revalidate every precondition immediately before staging.
3. Stage once without any submission action.
4. Read back through the reviewed bounded path and require byte-for-byte exact
   equality with the in-memory canary.
5. If the value is still exactly that canary, restore the prior empty value.
6. Verify exact empty readback and zero submit/commit calls.
7. Discard the canary and nonce; retain no raw transcript.

No executable staging command is documented because the production capability
is not configured or approved. Merely compiling `windows-ui-write` grants no
runtime authority.

## Pass criteria

- One stage call, zero commit/submit calls.
- Exact readback before restoration and exact empty state afterward.
- No focus, Z-order, clipboard, process, session, modal, or target change.
- No persistent artifact other than an optional reviewed redacted journal.

## Mandatory abort

If readback differs, user activity appears, state becomes stale, or any value
is not exactly root's own canary, stop and leave the value unchanged for the
user. Never clear mixed or unknown input. L20 failure blocks L30 and L40.
