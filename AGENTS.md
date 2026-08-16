# AI Agent Integration Guide

openkakao-cli is designed for AI agent integration. All commands support `--json` for structured output.

## Safety Model

LOCO write operations (send, delete, edit, react) are **disabled by default** to prevent account bans.

### Safe commands (always available, no server contact)

```bash
# Read chats from local KakaoTalk database (SQLCipher, no network)
openkakao-cli local-chats --json
openkakao-cli local-read <chat_id> -n 30 --json
openkakao-cli local-search "keyword" --json
openkakao-cli local-schema

# Preview actions without executing
openkakao-cli send 123 "message" --dry-run --json
openkakao-cli delete 123 456 --dry-run --json
```

### Safe commands (REST API, lower risk)

```bash
openkakao-cli chats --json
openkakao-cli read <chat_id> --rest --json
openkakao-cli friends --json
openkakao-cli me --json
openkakao-cli doctor --json
```

### Risky commands (require opt-in)

These require `allow_loco_write = true` in `~/.config/openkakao/config.toml`:

```bash
openkakao-cli send <chat_id> "message" -y --json
openkakao-cli send --me "test" -y --json    # Send to memo chat
openkakao-cli delete <chat_id> <log_id> -y --json
openkakao-cli edit <chat_id> <log_id> "new" -y --json
openkakao-cli react <chat_id> <log_id> --json
```

## Unattended Mode

For fully non-interactive operation:

```bash
openkakao-cli --unattended --allow-non-interactive-send send <chat_id> "msg" -y --json
```

Or configure in `~/.config/openkakao/config.toml`:

```toml
[mode]
unattended = true

[send]
allow_non_interactive = true

[safety]
allow_loco_write = true
min_unattended_send_interval_secs = 10
```

## Recommended Agent Workflow

1. **Read** with `local-chats` / `local-read` (zero risk)
2. **Preview** with `--dry-run` before any write
3. **Execute** only after user confirmation
4. **Prefer** `--me` flag for testing sends

## JSON Output

All commands with `--json` return structured JSON to stdout. Diagnostic messages go to stderr.

```bash
# List chats
openkakao-cli local-chats --json
# Returns: [{"chat_id": 123, "chat_type": 0, "chat_name": "...", ...}]

# Read messages
openkakao-cli local-read 123 --json
# Returns: [{"log_id": 456, "chat_id": 123, "sender_name": "...", "message": "...", ...}]

# Dry-run
openkakao-cli send 123 "hello" --dry-run --json
# Returns: {"dry_run": true, "action": "send", "chat_id": 123, "message": "..."}
```

## Diagnostics

```bash
openkakao-cli doctor --json        # Check installation, credentials, local DB access
openkakao-cli auth-status --json   # Check auth recovery state
```

## Windows MVP Session Rules

The rules below apply to the Windows port work rooted at
`C:\Users\ihvna\source\openkakao-dev`. The user's current session constraints
override the general examples above.

- Do not access KakaoTalk data directories, databases, credentials, tokens,
  cookies, sessions, process memory, or private conversation content.
- Do not send a message or mutate KakaoTalk UI. In particular: no focus or
  Z-order changes, `ValuePattern.SetValue`, button invocation, key input, or
  clipboard changes.
- Do not run `doctor` in its legacy form because it checks the local database.
  Windows UI diagnosis must use the new read-only probe seam only.
- Do not push, create a pull request, release, force-update a branch, use
  `git reset --hard`, or use `git clean`.
- Build only under this repository or its assigned worktrees, never under
  System32 or OneDrive. Keep artifacts in each worktree's ignored `.target`.
- Before editing, verify the exact git top-level, assigned branch, clean
  status, and ancestry from the frozen contract commit.
- Children do not install packages and do not spawn subagents.

### Ownership after `contract/windows-mvp-v1`

- root: manifests and lockfile, `src/main.rs`, `src/lib.rs`, common platform
  contracts and module indexes, common JSON/exit-code contract, and contract
  documentation.
- Child A: `src/platform/windows/**`, `tests/windows_backend/**`, and
  `docs/windows-port/handoffs/child-a.md`.
- Child B: `src/safety/**`, `src/config/windows*`,
  `tests/windows_policy/**`, and its handoff.
- Child C: `src/cli/windows/**`, `src/output/windows/**`,
  `tests/windows_cli/**`, and its handoff.

Children must request a root RFC instead of editing a manifest, common type,
trait, module index, or another owner's path. Every handoff includes an atomic
commit SHA, changed files, tests, skipped tests, assumptions, residual risks,
and any contract/dependency RFC.

### Windows implementation invariants

- Core types expose no HWND, COM, or UI Automation types.
- Unsafe Windows calls live in the smallest possible wrapper and document
  pointer validity, ownership, lifetime, and failure handling.
- Cross-process synchronous window messages use `SendMessageTimeoutW`.
- Target matching is case-sensitive, exact, and unique; zero or multiple
  candidates fail closed.
- Dry-run accepts only the read-only probe trait and performs zero mutations.
- A send backend accepts only `ApprovedSend`; uncertain submission is
  `Indeterminate` and is never automatically retried.
- Message text and real room/profile names never appear in Debug, Display,
  errors, JSON, logs, snapshots, fixtures, screenshots, or committed files.
- Tests use synthetic canaries and fake backends only during Phase 0/Wave 1.
