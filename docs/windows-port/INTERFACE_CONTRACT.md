# Windows MVP interface contract v1

Status: frozen by the local commit named `contract/windows-mvp-v1`.

## Capabilities and snapshots

The public contract is exported from `openkakao_cli::platform`:

- `UiCapabilities`
- `AppSnapshot`, `ChatTargetSnapshot`, `InputSnapshot`, `UiSnapshot`
- `InspectRequest`, `TargetKind`
- `PlatformProbe`, `MessageSender`
- `SendIntent`, `SecretMessage`, `ApprovedSend`
- `SendMode`, `SendOutcome`, `UiError`, `UiErrorKind`
- `ActionReport`, `BackendKind`, `ExitCode`
- `ExactMatch` and `exact_unique_match`

Snapshots contain only process/window/composer fingerprints and non-sensitive
state. Raw room names, profile names, draft text, and message text are excluded.

## Backend semantics

`PlatformProbe::inspect` is read-only: no focus, Z-order, clipboard, input
value, room selection, or network change. `inspect_dry_run` accepts only this
trait.

The Windows implementation additionally does not read window titles, UIA Name
or Value properties, room/profile names, or draft text. It may return a
diagnostic snapshot for cleanly observed absent, ambiguous, or unknown-profile
states; native/COM failures remain `UiError`. Target identity and draft-empty
claims stay false unless a future, separately approved design can verify them
without crossing the privacy boundary.

`MessageSender::stage` and `MessageSender::commit` require `&ApprovedSend`.
Windows Wave 1 returns unsupported for both. The type is not serializable or
cloneable, formats message text as redacted, and can be created only through
the safety token boundary.

## Outcomes and retries

Outcomes are `dry_run`, `staged_and_restored`, `commit_issued`,
`echo_confirmed`, `submitted_unverified`, `not_submitted`, and
`indeterminate`. `commit_issued`, `submitted_unverified`, and `indeterminate`
always report `retry_safe=false`.

## CLI meaning fixed for Wave 1

The integration target is:

```text
openkakao-cli doctor --ui [--json]
openkakao-cli local-send SELF_CHAT_NAME --stdin --opened-only [--dry-run] [--json]
```

Dry-run is the default. `--stage-only` and `--commit` are reserved, mutually
exclusive write modes and require `--yes`; neither is implemented or executed
in Wave 1. They are refused before stdin or UI inspection. Stdin is the only
Windows message path and is capped at 4,000 UTF-8 bytes and 1,000 Unicode
scalar values. A rejected positional message is never echoed in parse output.
Existing macOS syntax remains a compatibility facade until a later, separately
reviewed migration.

The safety policy performs the production dry-run inspection exactly once.
`DryRunPlan` retains the validated redacted snapshot privately, excludes it
from serialization, redacts it in Debug, and exposes it by reference for report
construction. This prevents a second-probe race between authorization and
output.

## JSON contract

`ActionReport` schema version 1 contains action, platform, backend, UI profile,
target kind, attempted, outcome, evidence, and retry safety. It never contains
a message, raw room name, profile name, HWND, or UIA runtime ID.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success or intended dry-run |
| 2 | CLI usage/input error |
| 10 | app or capability unavailable |
| 11 | target refused |
| 12 | composer/draft/user-state refusal |
| 13 | permission/session/profile refusal |
| 20 | backend failure before commit |
| 21 | submission indeterminate; never retry automatically |

## Compatibility

The macOS implementation remains in place. Its visible-list and
already-open-window paths now share the common exact-and-unique matcher. Linux
and unsupported stubs remain buildable. Manifest changes are target-scoped.
