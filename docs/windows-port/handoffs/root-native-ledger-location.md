# Root handoff: disconnected LocalAppData ledger location

## Outcome

This change implements the previously missing current-user LocalAppData,
fixed-local-volume, and parent-chain validation boundary for the Windows
durable ledger. The constructor is compiled only with `windows-ui-write` and
is deliberately unreachable from `NativeMutationPort`; production continues
to use `UnavailableLedger`.

No test or command called the production locator. All filesystem writes stayed
inside newly created synthetic temporary directories.

## Location protocol

The disconnected constructor performs this exact sequence:

1. call `SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, null)`
   through a narrow raw binding that preserves a non-null output even on a
   failing HRESULT;
2. wrap every non-null Shell allocation immediately and release it exactly
   once with `CoTaskMemFree`;
3. open the returned source directory with `FILE_FLAG_OPEN_REPARSE_POINT`,
   require a disk directory, and reject a final-component reparse point;
4. obtain a bounded normalized `VOLUME_NAME_GUID` path from that handle;
5. require an exact volume-GUID path, an exactly matching volume root, and
   `GetDriveTypeW == DRIVE_FIXED`;
6. open every component of both the original Shell path and canonical path
   without following a reparse point;
7. requery the original handle's canonical path exactly, then retain that
   handle in the validated location and through the ledger store lifetime;
8. append only the fixed ASCII directory `openkakao-cli`; and
9. create it with the existing explicit current-user security descriptor, or
   accept an existing entry only after exact handle/type/owner/protected-DACL
   verification and known-entry enumeration.

The retained parent handle is checked before and after child-directory
verification and before later store operations. A rename or replacement that
changes its canonical identity returns content-free `IoUncertain`.

## Ownership and privacy

- A Shell path uses `CoTaskMemFree`, including a non-null failure output.
- Directory handles use one RAII `CloseHandle` wrapper.
- UTF-16 paths are bounded below 32,760 units and reject NUL, relative, dot,
  parent, non-volume-GUID, malformed GUID, and unexpected root shapes.
- `ValidatedLedgerLocation` Debug output is always
  `<redacted-validated>`; paths and OS error text never enter the ledger error
  vocabulary.
- `catch_unwind` converts adapter control-flow failure to `IoUncertain`, but a
  future change must still avoid dynamic panic payloads because panic hooks
  run before unwind is caught.

## Synthetic coverage

Eight locator tests cover exact ordering, every adapter error/panic point,
nonlocal volume, source/canonical reparse evidence, path replacement,
volume-GUID parsing, fixed component/bounds, redacted Debug, and retained
native-handle revalidation against a synthetic temporary directory.

Eight native-store tests include create/reopen of the fixed directory under a
synthetic parent and refusal after an unexpected entry, in addition to the
existing DPAPI/ACL/restart/fault-injection cases.

## Production state and remaining blockers

`WindowsLedgerStore::open_disconnected_production` is intentionally unused.
`src/platform/windows/native.rs` has no reference to it, the locator, or
`WindowsLedgerStore`; it still constructs `UnavailableLedger`. This change
does not advertise `send_open_chat`, resolve real LocalAppData during tests,
or authorize a live gate.

Before production wiring, the locator and store still require an independent
unsafe review, an explicitly designed human recovery workflow for surviving
terminal records/artifacts, and a separate activation decision. Executable
trust, reviewed signer/root digests, self-target evidence, and the submit
selector also remain unavailable.

## Verification

All commands use `.target/wave2-root`.

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- focused ledger-location tests: 8 passed.
- focused native-ledger tests: 8 passed.
- default library suite: 155 passed.
- debug and release all-feature Windows unit subtree: 82 passed each.
- binary unit suite: 177 passed.
- Windows backend/policy/CLI contracts: 2/23/2 passed.
- compatibility suites: 23/13/12/13/20 passed.
- closed exact CLI allowlist: 14 passed.
- all-feature debug and release builds: passed.

The final regression counts and commit SHA are recorded in the next
checkpoint after commit.

## Safety ledger

- production `SHGetKnownFolderPath` calls: 0;
- real LocalAppData writes: 0;
- live KakaoTalk/UIA inspection or mutation: 0;
- messages sent: 0;
- KakaoTalk executable/data/database/credential/token access: 0; and
- network writes, pushes, PRs, and releases: 0.
