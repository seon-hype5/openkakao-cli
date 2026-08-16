# Root native target-permit plumbing handoff

Date: 2026-08-17 KST

Status: approval-owned native target verification wired and synthetically
qualified; production target observation remains unavailable and fail-closed

Reviewed predecessor: `3b06ecc785acde8fb0b01073ee535c142b8eb0b5`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

- `ApprovedSend` now checks an ephemeral observed UTF-16 label only against
  the private policy-bound snapshot stored in that approval. A native caller
  can no longer supply a different snapshot to the verifier.
- `NativeMutationPort` borrows the same `ApprovedSend` for the complete
  synchronous stage or commit operation.
- Fresh target observation and final preflight before draft Value access,
  `SetValue`, clear, or `Invoke` route through that approval-owned verifier.
- `TargetEvidence` retains only booleans. The observed label is borrowed only
  for one callback and is not stored in the port, evidence, report, or error.
- Exactness and uniqueness remain separate required claims; an exact label
  binding alone is insufficient.
- The current production profile passes no label and false exact/unique
  claims. It still reads no title, UIA Name, room/profile label, or draft and
  cannot reach mutation.

## Synthetic verification

All Rust artifacts used the ignored repository-local `.target/wave2-root`
directory. Only the closed help/version/usage parser allowlist launched the
binary; no doctor, local-state, credential, UI, or live-backend command ran.

- format and `git diff --check`: passed;
- default library suite: 178 passed;
- all-feature Windows library subtree: 104 passed in debug and release;
- binary unit suite: 177 passed;
- Windows backend/policy/CLI contracts: 2/24/2 passed;
- five retained compatibility suites: 23/13/12/13/20 passed;
- closed exact safe CLI allowlist: 14 passed;
- warnings-denied all-target/all-feature Clippy: passed; and
- default/all-feature debug and release builds: passed.

The new pure target-evidence test covers an absent label without invoking its
callback, an exact match, a mismatched label, an inexact selection, and a
non-unique selection. Existing transaction tests independently require all
target gates before claim or mutation.

## Files changed

- `src/platform/contract.rs`
- `src/platform/windows/native.rs`
- `src/safety/policy.rs`
- Windows-port architecture, interface, activation-boundary, security, CI,
  decision, and handoff documentation

## Remaining blockers

1. No approved, measured, version-bound native self-chat selector or ephemeral
   label observer exists.
2. No exact unique submit selector or production `InvokePattern` exists.
3. Independent native unsafe/root review and a clean pinned Windows CI run are
   still external requirements.
4. Reviewed Kakao signer/root provenance and production trust-adapter wiring
   remain absent; `UnavailableExecutableTrust` is still wired.
5. L10 retry and L20-L40 remain unauthorized and blocked.

This handoff supplies no authority to read a real label, inspect an installed
KakaoTalk artifact, retry a live gate, mutate UI, send a message, or enable
`send_open_chat`.
