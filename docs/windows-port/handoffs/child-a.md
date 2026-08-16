# Child A handoff: Windows read-only backend, Wave 1

## Status

Complete on branch `agent/win-backend-w1`. The atomic child commit is the
branch tip containing this handoff; its exact SHA is reported to root
immediately after commit creation (a commit cannot contain its own hash).

The backend is strictly read-only. It enumerates exact top-level
`EVA_Window_Dblclk` windows, fails closed on zero or multiple candidates,
verifies an absolute process image ending exactly in `KakaoTalk.exe`, reads the
executable file version, checks caller/target session and integrity
compatibility, and records visible/enabled state without focus or Z-order
changes. The only known selector profile is version `26.7.0.5255`.

For the known profile, UI Automation runs on a dedicated windowless MTA thread
and uses server-side exact conditions for composer class `RICHEDIT50W`,
AutomationId `1006`, and Edit control type. It reads only enabled/focused and
ValuePattern availability/read-only metadata. It never reads Name, Value,
message text, draft text, room/profile names, or a raw UI tree. Public native
identities are salted, execution-scoped fingerprints.

Cleanly observed absent, ambiguous, and unknown-profile conditions return a
diagnostic `UiSnapshot` with deny-by-default fields. Native/COM failures return
`UiError`. Safety/CLI layers are responsible for translating snapshot refusal
states to their fixed exit semantics. Because no room/profile label is read,
`exact_match`, `unique_match`, and `self_chat_verified` always remain false;
verified process/window metadata is not treated as target identity evidence.

## Changed files

- `src/platform/windows/mod.rs`
- `src/platform/windows/native.rs`
- `docs/windows-port/handoffs/child-a.md`

No common contract, matcher, manifest, lockfile, CLI, policy, or output file was
edited by Child A.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo test --lib platform::windows`: passed, 8 tests; 0 failed.
- `cargo clippy --lib -- -D warnings`: passed.
- Static forbidden-operation scan over `src/platform/windows`: no calls to
  message send, Value/Name reads, SetValue, focus, Invoke, key input,
  clipboard, or screen-capture APIs.

Tests are synthetic unit tests only. They cover exact/case-sensitive selector
matching and duplicate ambiguity, absent/ambiguous window states, ambiguous
composer state, exact version/profile gating, native-to-contract mapping, and
run-local/domain-separated fingerprints.

## Skipped tests

- No live KakaoTalk process/window/UIA probe was invoked.
- No stage, commit, message-send, focus, clipboard, key-input, Invoke, or other
  mutating test was run.
- No screenshot, UI dump, process-memory inspection, KakaoTalk data-file read,
  package installation, network write, push, merge, or PR operation occurred.

## Assumptions

- The CLI's own Windows session is the intended interactive session, so
  `ProcessIdToSessionId` equality is the session-match criterion.
- Exact absolute image path basename plus exact file version identifies the
  supported executable profile; code-signing verification and an install-path
  allowlist are outside the frozen Wave 1 contract.
- A disabled selected top-level window is conservatively surfaced through
  `modal_present`; Wave 2 must independently revalidate modal state before any
  future mutation.
- Because Wave 1 forbids reading real room/profile names and draft contents,
  `exact_match`, `unique_match`, `self_chat_verified`, and `draft_empty` always
  remain false. This intentionally prevents write approval even when the
  process/window and composer metadata are unique and writable.

## Residual risks

- The known selector was not exercised against live KakaoTalk UI under this
  session's synthetic-only test policy; provider metadata changes will fail
  closed as absent, ambiguous, unknown, or a sanitized native error.
- The eight-second caller timeout cannot cancel an already-blocked COM provider
  call. The detached read-only worker retains its apartment until that call
  returns; repeated provider hangs could temporarily retain worker threads.
- Executable signing and canonical install-root validation are not present.
  Exact process name/version, session, integrity, class, visibility, enabled
  state, and final PID/class revalidation are the implemented Wave 1 evidence.
- Modal detection is limited to the selected top-level window's disabled state;
  no unrelated UI tree or private window title is inspected.

## RFCs and dependencies

Approved RFC `windows-uia-property-conditions` added the existing
`windows` 0.62.2 feature `Win32_System_Ole` in root-owned commit `9ee5594`.
It enables the generated `IUIAutomation::CreatePropertyCondition`/`VARIANT`
surface used for targeted server-side selection. This is additive,
Windows-target-only, has no public contract change, and retains the existing
`windows` crate MIT OR Apache-2.0 licensing. Child A made no dependency or
contract changes and has no further RFC.
