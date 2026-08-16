# Root handoff: trust-ordered lazy production ledger wiring

Date: 2026-08-16 KST

## Status

Complete as offline activation scaffolding. The final atomic commit is recorded
in the external checkpoint because a commit cannot embed its own
content-derived identifier.

This change does not enable Windows writes. `windows-ui-write` remains default
off, runtime write configuration remains default false,
`send_open_chat=false`, native self-target evidence remains false, the submit
selector remains unconfigured, and production executable trust still refuses.

## Delivered boundary

`NativeMutationPort` now owns `LazyProductionLedger` instead of the synthetic
unavailable placeholder. The lazy wrapper:

- stores only a factory and content-free transaction correlation at
  construction time;
- opens the reviewed `WindowsLedgerStore` on the first ledger method only;
- consumes the factory before entry so an error or unwind cannot be retried;
- reuses exactly one controller after a successful open; and
- maps every open error or panic to fixed `SubmissionUncertain` /
  `windows_ledger_state_uncertain` with `retry_safe=false`.

The transaction calls `verify_executable_trust` before `ensure_clear` for both
stage and commit. The native port still uses `UnavailableExecutableTrust`, so
the lazy production factory cannot currently execute. Merely constructing or
dropping the port makes no Shell, file, DPAPI, ACL, or UI call.

## Synthetic verification

Tests use an in-memory factory/store to prove:

- construction opens nothing;
- the first ledger operation opens exactly once and later operations reuse the
  controller;
- factory error and panic are permanent non-retryable uncertainty with one
  attempted open; and
- the concrete production lazy wrapper remains unopened when merely
  constructed.

The existing transaction test proves unavailable executable trust refuses
before any ledger method or UI observation. No test invokes the production
factory.

The final non-live regression matrix passed:

- default library: 161 tests;
- all-feature Windows library, debug and release: 91 tests each;
- binary library: 177 tests;
- Windows backend/policy/CLI contracts: 27 default-feature tests and 2
  all-feature backend tests;
- compatibility targets: 81 tests;
- exact safe CLI allowlist: 14 tests;
- all-target/all-feature Clippy with warnings denied;
- default/all-feature debug and release builds; and
- 33 Windows-port Markdown files with 29 local links and zero broken links.

## Remaining blockers

- The native executable-trust adapter remains disconnected and deliberately
  lacks an installation-root digest.
- No reviewed signer/root provenance or repository-owned signed fixture exists.
- No privacy-safe measured self-target identity or exact submit selector exists.
- The production location/store has never been opened against the user's real
  LocalAppData; doing so requires a separately scoped review and authorization
  after trust provenance is complete.
- Live gates L10 through L40 remain blocked by their documented sequence and
  fresh-approval requirements.

## Safety ledger

- Production `SHGetKnownFolderPath` calls: 0.
- Real LocalAppData directory/file operations: 0.
- Native WinTrust calls: 0.
- KakaoTalk executable/data-file access: 0.
- Live KakaoTalk/UIA inspection or mutation: 0.
- Actual messages sent: 0.
- Credential/token/process-memory access: 0.
- Pushes, PRs, releases, or external writes: 0.
