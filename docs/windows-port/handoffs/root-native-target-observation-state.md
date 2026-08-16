# Root native target-observation state handoff

Date: 2026-08-17 KST

Status: contradictory native target-evidence inputs eliminated; production
target observation remains unavailable and fail-closed

Reviewed predecessor: `7dfbf0d3b55a9d6b16d690092beac48ebc9993ad`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

The native target helper no longer accepts an optional label plus independent
`exact` and `unique` booleans. It accepts one closed internal state:

- `Absent`;
- `UniqueInexact`;
- `AmbiguousInexact`;
- `AmbiguousExact`; or
- `ExactUnique` carrying one borrowed UTF-16 label.

Every `TargetEvidence` flag is derived from that state. Only `ExactUnique` can
invoke the approval-owned binding callback. All other states carry no label,
produce no self-chat/binding proof, and fail the existing four-way target gate.
An exact-unique mismatched label also fails. Neither the state, evidence, nor
mutation port retains label content.

The current observer constructs only `Absent`; it still performs no title,
UIA Name/Value, room/profile-label, or draft read and cannot reach mutation.

## Synthetic verification

All artifacts use the ignored repository-local `.target/wave2-root` directory.
The focused test exercises all five states and an exact-unique mismatch. Panic
canaries prove that absent, inexact, and ambiguous states do not invoke the
binding verifier. The complete safe matrix and counts are recorded in
[`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md).

No doctor, local-state, credential, live UI, KakaoTalk file/data, selector
measurement, stage, Invoke, or message-send command ran. The closed safe CLI
parser allowlist is the only binary execution permitted by the matrix.

## Remaining blockers

1. No approved, measured, version-bound self-chat selector or ephemeral label
   observer exists.
2. No exact unique submit selector or production `InvokePattern` exists.
3. Independent native unsafe/root review and a clean pinned Windows CI run
   remain external requirements.
4. Reviewed Kakao signer/root provenance and production trust wiring remain
   absent; `UnavailableExecutableTrust` stays wired.
5. L10 retry and L20-L40 remain unauthorized and blocked.

This handoff grants no live observation, UI mutation, send, or capability
activation authority.
