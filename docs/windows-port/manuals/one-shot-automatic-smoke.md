# L40 one-shot automatic smoke

> **Gate L40 — NOT AUTHORIZED NOW. It requires fresh immediate approval for one commit.**

L40 is the highest-risk MVP gate. It permits at most one automatic commit in
one approved session. The current Windows backend does not implement stage or
commit, so this manual cannot presently be executed.

The release goal of repeated exact echoes is cumulative across separately
approved sessions. It never means sending a batch in one session.

## Hard prerequisites

- L10, L20, and L30 have passed without privacy, target, draft, duplicate, or
  indeterminate failure.
- The full adversarial refusal matrix is green with zero mutation calls on
  every refusal path.
- A reviewed implementation supports a verified submit-button invocation.
  Key-input fallback requires its own approved RFC and is otherwise forbidden.
- Cross-process mutual exclusion, one-shot nonce consumption, snapshot TTL,
  user-activity detection, and exact staged readback are all active.
- The user gives a separate immediate approval naming L40 and exactly one
  automatic synthetic commit. Prior approvals do not carry forward.
- Root is the sole automation controller and all child agents are stopped.

## Final revalidation

Immediately after approval and immediately before commit, root must prove:

- unchanged process, session, executable fingerprint, and top-level window;
- unchanged exact unique self-chat and composer fingerprints;
- exact staged canary and no other draft content;
- no modal, focus transition, or user activity;
- unexpired snapshot and held cross-process mutex; and
- unused one-shot nonce.

Any mismatch aborts before commit. Do not rediscover and continue
automatically.

## One-shot procedure

1. Stage one in-memory synthetic canary through the already accepted L20 path.
2. Perform the final revalidation once.
3. Invoke the one reviewed submit control exactly once.
4. Mark `retry_safe=false` as soon as the commit call begins.
5. Observe one bounded echo interval and classify the outcome once.
6. Report the outcome to the user and stop the session.

There is no loop, retry, fallback submit mechanism, automatic deletion, or
second smoke action.

## Acceptance

Pass requires one `commit_issued`, one exact `echo_confirmed`, zero duplicates,
zero wrong-target evidence, and zero forbidden artifacts. Timeout, UI hang,
state replacement, or uncertain echo is `indeterminate`; it is never retried.
Any L40 anomaly blocks release-candidate status pending human review.
