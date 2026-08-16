# L30 user-manual-submit validation

> **Gate L30 — NOT AUTHORIZED NOW. Current product support is absent.**

L30 separates staging risk from submission risk: reviewed automation may stage
one synthetic canary, but only the user may operate the confirmed submission
control. Automation observes only the reviewed redacted echo signal. L30 does
not permit automatic commit.

## Entry requirements

- L10 and L20 passed in earlier explicitly approved sessions, including exact
  safe restoration at L20.
- The user gives new approval naming L30 and exactly one synthetic submission.
- Root is the sole automation controller and all child agents are stopped.
- The same identity, empty-draft, selector, revalidation, mutex, privacy, and
  artifact controls required by L20 are satisfied.
- A bounded read-only echo path has passed its separate acceptance threshold.
  OCR or unreadable evidence cannot be promoted to exact confirmation.

The current product cannot satisfy these requirements; stop before live work.

## Future controlled procedure

1. The user manually opens and visually verifies the self-chat.
2. Root creates one session-specific synthetic canary in memory.
3. Root revalidates all state and stages once using the reviewed L20 path.
4. Root proves exact staged readback, then yields control.
5. The user personally operates Enter or a separately verified submission UI.
   Root does not invoke, focus, or synthesize the submit action.
6. Root observes for one bounded interval through the approved read-only echo
   path and classifies the result once.
7. Root discards all raw canary and nonce material from memory.

## Outcome rules

- `echo_confirmed`: exact synthetic echo observed once.
- `submitted_unverified`: submission likely occurred but exact echo is absent.
- `indeterminate`: the observation path timed out or state became uncertain.
- `aborted`: submission did not begin and the safe abort path completed.

After the user submits, `retry_safe=false` regardless of outcome. There is no
automatic retry, second canary, deletion, recall, or compensation action.

## Pass and stop conditions

Pass requires exactly one user submission, one exact echo, zero duplicate
echoes, no wrong target, and no forbidden artifact. Any uncertainty is reported
immediately and blocks L40. Do not turn a failed L30 into another submission in
the same approval.
