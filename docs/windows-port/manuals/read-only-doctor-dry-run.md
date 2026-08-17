# L10 read-only doctor and dry-run

> **Gate L10 — NOT AUTHORIZED NOW. Fresh explicit user approval is required.**

## Purpose and ceiling

L10 may observe bounded process, top-level-window, and composer metadata from
an already-open self-chat. It may not activate or focus a window, alter
Z-order, set a value, invoke a control, synthesize input, touch the clipboard,
open/search a room, or persist a UI dump.

The production probe intentionally cannot prove self-chat identity or an empty
draft without crossing the privacy boundary. Therefore a redacted UI doctor
report can succeed while production local-send dry-run is expected to refuse.
That refusal is a correct result, not permission to weaken evidence.

## Entry gate

Before a future L10 session, all of the following must be true:

1. The user explicitly approves L10 for one session and no later gate.
2. Root records only the approval scope and time; no private label or content.
3. Child agents are stopped and root is the only automation controller.
4. The user manually opens and visually verifies the intended self-chat.
5. No output redirection, screenshot tool, UI recorder, or raw trace is active.
6. The build under test passed the Windows safe CI workflow for its exact
   commit.

If any condition is unknown, do not begin.

## Procedure template

The command shapes below are documentation, not authorization and not a
copy/paste instruction for this session:

```text
openkakao-cli doctor --ui --json
<synthetic canary via stdin> | openkakao-cli local-send <SELF_CHAT_LABEL_IN_MEMORY> --stdin --opened-only --dry-run --json
```

At a separately approved session, root performs these steps:

1. Establish an in-memory before-state containing only booleans or redacted
   fingerprints for foreground stability, Z-order stability, clipboard
   sequence stability, and composer-value length stability.
   Raw exact-class window multiplicity is not by itself a selector failure.
   Exclude only invisible windows, then apply the reviewed read-only rule to at
   most eight remaining exact-class candidates: exactly one window with exactly
   one known-profile composer, and no duplicate or internally ambiguous
   composer. Keep counts and native identifiers in memory and never print or
   persist them. If narrowing fails, emit only one reviewed fixed reason code:
   candidate limit, duplicate composer, internally ambiguous composer,
   candidate not inspected, or no composer. This visibility narrowing and its
   diagnostic reasons are not used by the mutation path.
   For `read_only_candidate_not_inspected`, the report may additionally state
   any applicable fixed aggregate blocker classes for executable trust, UI
   profile, visibility, enabled/modal state, session, and integrity. It must
   never emit a count, candidate association, raw bitset, or native value.
   If one known-profile window reports `composer_absent`, the report may also
   emit fixed near-match-without-expected-class-name, AutomationId, or
   control-type codes, or a no-two-property-near-match code. These come only
   from existence checks for the three exact two-property subsets of the
   reviewed selector. They never
   expose the observed value, element, count, association, Name, or Value.
2. Run only `doctor --ui`; never run legacy `doctor` on Windows.
3. Review the console report without persisting it. Confirm fixed schema,
   allowlisted evidence, and absence of private material.
4. Generate one session-specific synthetic canary in memory and feed it only
   through stdin to the dry-run shape.
5. Treat target or input-state refusal as expected for the metadata-only
   backend. Do not retry with weaker matching or alternate selectors.
6. Compare the after-state to the before-state. Every mutation indicator must
   be unchanged.
7. Discard the canary and execution-scoped fingerprint secret from memory.

## Pass criteria

- UI doctor output contains only schema-version-1 fixed fields and redacted
  evidence.
- Dry-run produces either an intended plan from a separately approved safe
  fake or a stable production refusal; it never stages or commits.
- Inspect count is bounded by the reviewed path and mutation counts are zero.
- The before-state, doctor report, and after-state agree on one narrowed
  composer-bearing diagnostic window; this remains only composer evidence,
  not proof of self-chat identity.
- Foreground, focus, Z-order, clipboard sequence, and composer value length are
  unchanged.
- No persistent artifact is created by default.

## Abort criteria

Abort L10 and block L20 if any output contains unexpected strings, a window is
activated, focus/Z-order changes, clipboard state changes, a composer value
changes, the app/process is replaced, the selector is ambiguous, or the
result is not understood. Follow
[abort and troubleshooting](abort-rollback-troubleshooting.md); do not gather
screenshots or private dumps.
