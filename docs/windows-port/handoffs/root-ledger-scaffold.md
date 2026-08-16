# Root handoff: offline durable-ledger scaffold

## Outcome

This change implements the privacy-safe, platform-independent portion of the
Windows replay/crash ledger and makes the missing production store an explicit
fail-closed transaction boundary. It does not activate Windows writes.

The fixed 48-byte inner record contains only:

- magic and schema version;
- one of `stage_may_have_started`, `commit_may_have_started`, or
  `indeterminate`;
- a nonzero opaque 128-bit record correlation;
- a monotonic transition sequence; and
- a truncated SHA-256 schema-integrity checksum.

It contains no message, target label, PID, HWND, path, UIA metadata,
fingerprint, KakaoTalk data, or credential. Record and correlation `Debug`
output is redacted. The copyable record correlation is internal to the ledger;
policy generates its bytes in a separate non-Clone, non-serializing, zeroizing
token that the backend can consume exactly once.

## Transition and mutation ordering

The guarded synthetic transaction now enforces:

```text
durable ledger clear preflight
  -> fresh validation
  -> durable stage marker
  -> final native SetValue preflight
  -> one-shot execution claim
  -> first SetValue

exact staged readback
  -> durable commit marker
  -> final native Invoke preflight
  -> exactly one Invoke
  -> durable indeterminate marker (even on apparent success)
```

A stage marker is automatically removed only after exact owned-value clearing
and a fresh exact-empty readback. Claim rejection may also remove it because no
UI mutation has begun. Every other error/panic after `SetValue` entry attempts
to advance to `indeterminate` and returns non-retryable
`SubmissionUncertain`. A commit marker is never automatically removed.

The scoped mutation worker's uncaught panic is also normalized to
non-retryable uncertainty, because a durable marker or UI mutation may already
exist.

## Production activation state

`NativeMutationPort` embeds `UnavailableLedger`. It stops at
`windows_ledger_unavailable` before initial UI observation, final native write
preflight, execution claim, or any `SetValue`/`Invoke`. Existing independent
barriers also remain unchanged:

- `windows-ui-write` is default-off;
- product write configuration is default-false;
- `WindowsBackend` advertises `send_open_chat=false`;
- native self/exact/unique target evidence remains false;
- the submit selector remains `Unconfigured`.

The Windows DPAPI/current-user protection, ACL/reparse checks, LocalAppData
resolution, atomic write-through install, directory flush, and human recovery
command are deliberately not present. No code should replace
`UnavailableLedger` until that store is reviewed together with its existing
policy correlation handoff.

## Synthetic coverage

The focused all-feature Windows unit suite covers:

- strict fixed-length codec round trips and redacted formatting;
- nonzero policy correlation generation, redacted Debug, one-use consumption,
  and second-consumption refusal;
- truncated, oversized, corrupt, unknown-version, unknown-phase, reserved-bit,
  zero-sequence, and zero-correlation records;
- durable write failures before and after replacement/removal, plus exact
  reload verification mismatch;
- process restart with every nonempty state and both identical/different
  correlations;
- existing/unavailable ledger refusal before any UI observation;
- simultaneous identical/different correlations with exactly one winner;
- stage resolution as the only automatic removal edge;
- commit/indeterminate monotonic transitions and crash-like write failures;
- ledger unavailable before claim/UI mutation;
- claim rejection cleanup;
- exact stage ordering and terminal commit ordering;
- failed commit marker, failed terminal marker, failed removal, final preflight
  failure, and panics immediately before/after Invoke; and
- one SetValue, at most one clear, exactly zero/one Invoke as appropriate, with
  no retry edge.

No test constructs `WindowsBackend` against the desktop or calls live UIA.

## Verification

All Rust commands used the isolated `.target/wave2-root` directory.

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`:
  passed.
- default/all-feature library checks: passed.
- default library tests: 129 passed.
- all-feature Windows unit subtree: 48 passed in debug and release.
- binary unit tests: 177 passed.
- Windows backend/policy/CLI integration targets: 2 + 23 + 2 passed.
- all-feature Windows backend contract target: 2 passed.
- exact safe CLI compatibility allowlist: 14 passed.
- compatibility targets (`auth_flow`, `loco_client`, `loco_crypto`,
  `loco_packet`, `message_db`): 23 + 13 + 12 + 13 + 20 passed.
- default/all-feature debug and release builds: passed.
- Windows-port Markdown: 26 files, 16 local links, 0 broken.
- workflow static audit: 3 full 40-hex action pins, no artifact upload,
  contents-write permission, or credential persistence.
- `git diff --check`: passed before final commit.

## Still blocked

Before production storage can be connected, the remaining ledger work is:

1. `FOLDERID_LocalAppData` resolution without environment variables;
2. current-user DPAPI with UI forbidden and strict post-decrypt decoding;
3. owner/ACL/local-volume/reparse validation;
4. same-directory exclusive temporary files, flush, write-through atomic
   install, reopen, decrypt, and exact verification;
5. injected filesystem/DPAPI tests for wrong owner/ACL, reparse/network paths,
   partial writes, rename/flush failures, and process-crash recovery; and
6. a separately authorized human-only recovery design.

The successor
[`root-executable-trust-scaffold.md`](root-executable-trust-scaffold.md)
implements only the pure signer/install-root decision seam; its native observer
and reviewed profile remain blocked. Target/submit selectors and all live gates
also remain blocked as described in `docs/windows-port/ACTIVATION_RFC.md`.

## Safety ledger

- Live KakaoTalk/UIA inspection or mutation: not run.
- `CurrentValue`, `SetValue`, or `Invoke` against a live provider: 0 calls.
- Messages sent: 0.
- KakaoTalk data/database/credential/token access: 0.
- Keyboard, clipboard, focus/Z-order, screenshot, OCR, hook, injection, or
  process-memory operations: 0.
- Network writes, pushes, PRs, and releases: 0.
