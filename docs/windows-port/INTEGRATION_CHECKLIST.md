# Wave 1 integration checklist

Frozen contract: `d974c0597528e079919d4c45ee0893fa61d4335d`

## Per-child intake

For every child SHA:

1. Confirm the expected branch and clean worktree.
2. Run `git merge-base --is-ancestor` from the frozen contract.
3. Inspect `git diff --name-only CONTRACT..CHILD` for exact ownership.
4. Run `git diff --check CONTRACT..CHILD`.
5. Review every unsafe block and any COM/native resource wrapper.
6. Confirm no manifest/common-contract edits, private strings, screenshots,
   KakaoTalk data paths, UI mutation, send, retry, push, or PR.
7. Confirm the handoff lists focused tests, skipped tests, assumptions, risks,
   and RFCs.

## Windows API review points

- `EnumWindows` callback state has a valid lifetime and does not retain stale
  pointers or handles.
- `GetWindowThreadProcessId` failure (zero) is checked.
- process handles request only the minimum query rights, are non-inheritable,
  and are closed on every path; no process-memory rights are requested.
- executable path buffer lengths are in UTF-16 code units and checked.
- file-version buffers remain alive while `VerQueryValueW` pointers are used.
- UI Automation runs on a dedicated windowless MTA thread; successful
  `CoInitializeEx` calls, including `S_FALSE`, are balanced by
  `CoUninitialize` on the same thread.
- UIA interface pointers/elements do not outlive or escape the creating
  apartment.
- desktop searches use direct children, and app-subtree searches are bounded.
- selector decisions combine process, top-level class, composer class,
  AutomationId, control type, and pattern metadata.
- no `SetValue`, Invoke, focus/Z-order, key, clipboard, screen capture, raw UI
  tree dump, title/body logging, or cross-process memory access exists.

## Integration order

1. Child B safety policy.
2. Resolve only root-owned config/module wiring requested by a reviewed RFC.
3. Child A Windows discovery backend.
4. Child C CLI/output/fake surface.
5. Root wires `doctor --ui` and Windows `local-send` into `src/main.rs` while
   preserving the macOS compatibility path.

Each child is cherry-picked, not merged, and followed by focused tests. No
branch rewrite or force operation is allowed.

## Final automated gates

Use a root-only target directory and no live KakaoTalk command:

```text
cargo fmt --check
cargo test --lib
cargo test --bin openkakao-cli
cargo test --test windows_backend
cargo test --test windows_policy
cargo test --test windows_cli
cargo test --test cli_test -- --skip doctor_json_outputs_valid_json
cargo clippy --all-targets --all-features -- -D warnings
cargo build
```

The legacy `doctor --json` integration test remains excluded until its Windows
case is switched to the new `doctor --ui --json` path, because legacy doctor
loads credential/local-DB diagnostics forbidden in this session.

## Exit evidence

- integration worktree clean;
- all accepted child commits recorded;
- Windows build and safe automated tests recorded;
- mutation count 0;
- actual message count 0;
- KakaoTalk data/credential access count 0;
- push/PR count 0;
- `NEXT_HANDOFF.md` names Wave 2 as the next start point.
