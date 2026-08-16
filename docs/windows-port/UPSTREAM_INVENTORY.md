# Upstream inventory

## Pinned source

- URL: `https://github.com/JungHoonGhae/openkakao-cli.git`
- remote name: `origin` (no fork was created)
- default branch: `main`
- pinned commit: `be6edd442c803de8e4f06bfc4446d166ac474952`
- pinned subject: `docs(research): DB key path is stored-not-derived; dynamic hook blocked by keychain (#43, #40)`
- nearest release: `v1.7.1` at `c65f450`
- license: MIT, with the copyright/license notice required in substantial copies

No push or pull request was performed.

## Rust package

- package and binary: `openkakao-cli` 1.7.1
- library crate: `openkakao_cli`
- edition: 2021
- declared MSRV/toolchain: Rust 1.95.0 pin
- CI before this port: Ubuntu test/lint and macOS release build; no Windows job

## Command and dispatch inventory

`src/main.rs` owns clap definitions and dispatch. Existing relevant commands:

- `local-send CHAT_NAME MESSAGE [--dry-run] [-y]`
- `ax-read CHAT_NAME [-n COUNT]`
- `ax-watch ...`
- `doctor [--loco]`

The existing `local-send` dry-run prints the room and message, so it does not
meet the Windows privacy contract. Non-dry-run uses `allow_ax_send` plus an
exact string allowlist in `SafetyConfig`, then calls
`commands::local_send::cmd_local_send`.

## Accessibility boundary

`src/ax_send.rs` is approximately 855 lines. Its public facade is:

- `send_via_ax(chat_display_name, message)`
- `read_via_ax(chat_display_name, count)`
- `scrape_chat_list()`
- `ChatListRow`

The macOS implementation is under `cfg(target_os = "macos")`; a same-shape
unsupported stub is exported on every other platform. Callers are
`commands/local_send.rs`, `commands/ax_read.rs`, and `commands/ax_watch.rs`.

The visible chat-list matcher was already exact and duplicate-aware, but the
already-open-window fast path used substring title matching. The contract
commit routes both through the common exact-and-unique matcher without moving
the macOS implementation.

## Configuration compatibility

`OpenKakaoConfig` uses serde defaults, so adding a defaulted Windows section is
backward compatible. Existing `SafetyConfig` defaults both LOCO and AX writes
off and uses `allowed_send_chats: Vec<String>`. Windows MVP narrows the target
further to a single verified self-chat and never treats that legacy list alone
as sufficient approval.

## Local database impact

`src/local_db.rs` contains macOS paths and commands but was compiled on every
target. A global `rusqlite` `bundled-sqlcipher` feature made Windows builds
require an external OpenSSL layout before any source was compiled. The port
keeps SQLCipher only for macOS and uses bundled plain SQLite for non-macOS
openkakao's own cache. This does not add or enable Windows KakaoTalk DB access.

Legacy `doctor` calls `LocalDbReader::check_access`; it must not be used for the
Windows UI-only session. The new UI diagnostic path must remain independent.

## Tests and CI

Existing unit/integration tests live in `src/**` and `tests/**`. Linux CI runs
test, fmt, and clippy. macOS CI builds a release and runs `--version`. Wave 1
adds only local Windows/fake coverage; a Windows CI workflow is deferred to
Wave 2.
