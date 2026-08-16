# Windows MVP architecture

## Scope

The MVP is a fail-closed, UI-only path for inspecting process, window, and
composer metadata for an already-open Windows KakaoTalk instance. Wave 1
contains no UI mutation. It does not log in, read KakaoTalk files or databases,
inspect memory, select rooms, read room/profile names or draft text, or send a
message.

```text
CLI / redacted output
        |
        v
read-only orchestration -----> dry-run report
        |
        v
safety policy -----> refusal or ApprovedSend
        |
        v
platform traits
   /          \
macOS facade  Windows UIA/Win32
```

`src/platform` contains platform-neutral data and traits. HWND, COM, Windows
API types, raw room titles, and message text do not cross this boundary.

## Read-only Wave 1

The Windows backend may:

- enumerate `KakaoTalk.exe` and top-level windows;
- verify PID, executable path, version, session, and access compatibility;
- classify zero/one/multiple KakaoTalk windows;
- inspect UI Automation metadata for the known composer profile;
- return redacted fingerprints and structured refusal states.

The known profile is KakaoTalk 26.7.0.5255 with top-level class
`EVA_Window_Dblclk` and composer class `RICHEDIT50W`, AutomationId `1006`.
Version/profile uncertainty leaves write capability false.

The production backend deliberately leaves `exact_match`, `unique_match`,
`self_chat_verified`, and `draft_empty` false. Process/window/composer metadata
cannot prove target identity or an empty draft, and Wave 1 does not read the
private text that could provide that evidence. Consequently, `doctor --ui` can
produce a redacted diagnostic snapshot, while production `local-send` dry-run
fails closed at policy validation. Synthetic fake-backend tests exercise the
successful orchestration shape without weakening this boundary.

The backend may not activate a window, change focus/Z-order, set a value,
invoke a button, synthesize keys, touch the clipboard, or save UI dumps.

## Safety boundary

`PlatformProbe` is read-only. `MessageSender` exposes mutation methods but each
accepts only `ApprovedSend`. The approval value has private fields and requires
an unforgeable token owned by the safety module. CLI and platform code cannot
construct it directly.

Dry-run accepts only `PlatformProbe`, making mutation unavailable by type. A
fake backend records inspect/stage/commit counts and locks this property in a
unit test.

On Windows, root dispatch validates the command mode before reading stdin or
constructing a backend. A valid dry-run is inspected once by the policy, and
the report reuses that exact validated redacted snapshot rather than probing a
second time. Reserved stage/commit modes are rejected before stdin and UI
inspection.

## Identity and matching

All labels use one common, case-sensitive exact-and-unique matcher. Unreadable,
partial, normalized, or duplicate labels never resolve to a target. Public
snapshots use execution-scoped fingerprints rather than raw names or runtime
identifiers.

## Future write transaction

Wave 2 may implement `planned -> validated -> staged -> commit_issued` after a
new explicit request. It must revalidate process, session, window, target,
composer, draft, modal state, TTL, and mutex. A commit-call timeout is
`Indeterminate` with `retry_safe=false`. Wave 1 does not implement or exercise
that transaction.
