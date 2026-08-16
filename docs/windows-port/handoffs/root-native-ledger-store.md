# Root handoff: synthetic-base Windows ledger store

Successor note: [`root-production-ledger-wiring.md`](root-production-ledger-wiring.md)
records the later trust-ordered lazy composition. This handoff otherwise
describes the earlier disconnected phase.

Successor note: [`root-native-ledger-location.md`](root-native-ledger-location.md)
adds the separately reviewed, disconnected LocalAppData/fixed-volume location
constructor. Production wiring remains unavailable.

## Outcome

This change implements the Windows-native half of the durable replay store for
an explicit synthetic temporary base only. It remains disconnected from
`NativeMutationPort` and has no production `LocalAppData` constructor, so it
does not activate or make Windows UI writes reachable.

The implementation uses:

- the current process token's validated `TokenUser` SID;
- an explicit absolute security descriptor created before the directory/file;
- a protected, present DACL containing exactly one current-user full-control
  allow ACE;
- handle-based owner/DACL and reparse/type verification;
- current-user DPAPI with `CRYPTPROTECT_UI_FORBIDDEN`, no machine scope,
  description, prompt, or optional entropy;
- bounded exclusive synchronous reads/writes and `FlushFileBuffers`;
- same-directory random temporary files and `MoveFileExW` with replace and
  write-through but no copy fallback; and
- write-through rename to a random tombstone before exact restored-stage
  deletion.

Every native error is reduced to the closed `LedgerStoreError` vocabulary. No
path, SID, record byte, system error, or allocator content enters an error,
`Debug`, test name, stdout, or stderr.

## Ownership and bounds

- Token and ACL buffers are `usize`-aligned and range-checked before casts.
- `GetSecurityInfo`'s descriptor is validated and freed once with `LocalFree`;
  its owner, DACL, and ACE pointers are treated as borrows.
- DPAPI allocations are bounded, zeroed over the full reported span, and freed
  once with `LocalFree` on success, refusal, and unwind.
- Process token and file handles use exactly-once `CloseHandle`; enumeration
  handles use `FindClose`, never `CloseHandle`.
- The inner plaintext is exactly 48 bytes. Ciphertext is nonempty and capped at
  64 KiB. A trailing byte, length change, corrupt DPAPI blob, or invalid inner
  schema refuses.
- Temporary names use independent random 128-bit bytes and never reuse the
  policy correlation.

## Crash/failure behavior

The native test store exposes a test-only one-shot fault seam at:

1. before temporary creation;
2. after temporary creation;
3. after the exact write;
4. after flush;
5. after temporary reopen/verification;
6. after installed-file rename;
7. after installed-file verification;
8. after tombstone rename; and
9. after tombstone deletion.

A failure before any artifact leaves a clear restart state and no mutation can
follow the returned error. Every later replacement failure leaves either an
unexpected artifact or an installed nonempty ledger, both of which block a
restart. A removal failure after tombstone rename blocks on the tombstone. A
failure after tombstone deletion may restart clear only because the transaction
controller had already proven exact stage restoration before calling removal.

## Production state

Production still embeds `UnavailableLedger`. The new module has no production
constructor and cannot resolve or create a user-state directory. Independent
barriers remain:

- default-off `windows-ui-write`;
- default-false product write configuration;
- `send_open_chat=false`;
- `UnavailableExecutableTrust` before ledger/UI observation;
- native self/exact/unique target evidence false; and
- submit selector `Unconfigured`.

The added `windows` feature namespaces implement the accepted inventory in
`NATIVE_ACTIVATION_BOUNDARIES.md`; they are bindings, not authorization.

## Synthetic coverage

Seven focused native-store tests cover:

- DPAPI protect/unprotect plus strict codec round trip;
- exact restored-stage removal and verified absence;
- restart refusal for a present valid record;
- current-user inherited-file ACL refusal versus the explicit protected ACL;
- corrupt ciphertext with a still-valid explicit ACL;
- unexpected directory artifacts;
- fixed DPAPI/UI and inner-length constants plus overflow/reparse classifiers;
- all seven replacement fault points and both removal fault points; and
- restart classification after every injected point.

Only `tempfile`-owned synthetic directories and content-free 48-byte records
are used. The product binary, production backend, desktop, KakaoTalk process,
installation, UI, data files, and credentials are never opened.

## Remaining store blockers

Before replacing `UnavailableLedger`, a separate review must still complete:

1. `SHGetKnownFolderPath(FOLDERID_LocalAppData)` ownership and a fixed
   application directory constructor;
2. opened-parent-chain reparse checks and exact `DRIVE_FIXED`/local-volume
   evidence, including mounted-folder negatives;
3. a testable wrong-user DPAPI adapter and independent unsafe audit;
4. cross-process tests while the production named mutex is held;
5. cleanup/tombstone behavior under real process termination, power-loss
   assumptions, and filesystem variants; and
6. a separately authorized human recovery command/format.

None of these may be filled by inspecting or trusting the current KakaoTalk
installation.

## Verification

All commands use `.target/wave2-root`. At this checkpoint:

- `cargo check --locked --lib --all-features`: passed;
- `cargo test --locked --lib --all-features
  platform::windows::ledger_native`: 7 passed; and
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed;
- default library tests: 138 passed;
- all-feature Windows unit subtree: 64 passed in debug and release;
- binary unit tests: 177 passed;
- Windows backend/policy/CLI contract targets: 2 + 23 + 2 passed;
- all-feature Windows backend contract: 2 passed;
- compatibility targets: 23 + 13 + 12 + 13 + 20 passed;
- exact safe CLI allowlist: 14 passed;
- default/all-feature debug and release builds: passed;
- Windows-port Markdown: 29 files, 21 local links, 0 broken; and
- workflow audit: 3 full-SHA action pins, no artifact upload, contents write,
  or credential persistence.

The final commit SHA is recorded in the external/current checkpoint after this
file is committed.

## Safety ledger

- Live KakaoTalk/UIA inspection or mutation: 0.
- `CurrentValue`, `SetValue`, or `Invoke` against a live provider: 0.
- Messages sent: 0.
- KakaoTalk files, databases, credentials, tokens, or installation metadata
  accessed: 0.
- Keyboard, clipboard, focus, screenshot, OCR, hook, injection, or process
  memory operations: 0.
- Network writes, pushes, PRs, and releases: 0.
