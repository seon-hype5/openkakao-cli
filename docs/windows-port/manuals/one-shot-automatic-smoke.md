# L40 one-shot automatic smoke

> **Gate L40 — NOT AUTHORIZED NOW. It requires fresh immediate approval for one commit.**

L40 is the highest-risk MVP gate. It permits at most one automatic commit in
one approved session. The default-off write build now has an exact target,
composer-Enter submit strategy, and durable replay store, but every remaining
qualification prerequisite and fresh session approval below is still required.

The release goal of repeated exact echoes is cumulative across separately
approved sessions. It never means sending a batch in one session.

## Hard prerequisites

- L10, L20, and L30 have passed without privacy, target, draft, duplicate, or
  indeterminate failure.
- The full adversarial refusal matrix is green with zero mutation calls on
  every refusal path.
- The reviewed v3 profile supports exactly one composer-targeted queued Enter
  keydown/key-up pair after exact top-level-target activation and a repeated
  root-normalized foreground/composer/draft proof. Global key input, fallback controls,
  and retry remain forbidden.
- Cross-process mutual exclusion, one-shot nonce consumption, snapshot TTL,
  user-activity detection, exact staged readback, and the accepted durable
  ledger protocol from [the activation RFC](../ACTIVATION_RFC.md) are all
  active.
- The user gives a separate immediate approval naming L40 and exactly one
  automatic synthetic commit. Prior approvals do not carry forward.
- Root is the sole automation controller and all child agents are stopped.

## Final revalidation

Immediately after approval and immediately before commit, root must prove:

- unchanged process, session, executable fingerprint, and top-level window;
- unchanged exact unique self-chat and composer fingerprints;
- exact staged canary and no other draft content;
- no modal or user activity before the deliberate v3 target activation;
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

If a prior stage-only call alone left a durable sequence-2 indeterminate record,
the recovery branch may skip steps 1's SetValue and restore work only after it
proves the exact staged canary. It must promote to terminal sequence 3 before
step 3 and still dispatch at most once.

There is no loop, retry, fallback submit mechanism, automatic deletion, or
second smoke action.

## Acceptance

Pass requires one `commit_issued`, one exact `echo_confirmed`, zero duplicates,
zero wrong-target evidence, and zero forbidden artifacts. Timeout, UI hang,
state replacement, or uncertain echo is `indeterminate`; it is never retried.
Any L40 anomaly blocks release-candidate status pending human review.
