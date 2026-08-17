# I20 release-candidate integration checklist

Wave 1 integration ancestor: `fed2bb1558b4e07878f17f4c8140aab5ead682b2`

## Wave 2 intake

For every child source commit:

1. verify its expected branch, clean worktree, and Wave 1 ancestry;
2. inspect the complete name/status diff for exact ownership;
3. run `git diff --check` and review every unsafe/native change;
4. confirm no private strings, screenshots, UI dumps, KakaoTalk paths, data,
   credentials, live UI calls, sends, retries, pushes, or PRs;
5. reconcile root-owned contracts/config only through recorded RFC decisions;
6. cherry-pick atomic commits without rewriting child history; and
7. retain child handoffs with tests, skips, assumptions, and residual risks.

Integrated Wave 2 sources:

- P40 Windows transaction: Child A `47452d8327d4ce52929de17523a6fc4f971d4293`;
- P50 adversarial safety: Child B `f9ca1964942276fa3fb0a4305a5408afb5599e2d`;
- P60 Windows CI/manuals: Child C `f09fc19bb05e11b0d4659a726e662e414c1e1408`.

Root additionally closed consuming-capability, sender-sealing,
mode/outcome-normalization, post-SetValue uncertainty, process-instance,
same-process foreground, mutex-result, UTF-16 zeroization, parse-redaction,
allowlist-ordering, and CI allowlist findings.

## Native and unsafe review

- COM initialization and uninitialization occur on the same MTA thread.
- No UIA interface leaves the scoped mutation worker/apartment.
- Enumeration callbacks, lengths, pointers, SIDs, file-version data, and
  process/token handles have documented validity and ownership.
- Process handles request only limited query rights; no memory rights exist.
- PID/HWND/path/process-creation/session/integrity and exact UIA identity are
  revalidated immediately before mutation.
- The named mutex is zero-wait and held through validation and the complete
  write/readback/restore or Invoke transaction.
- Contention, abandoned ownership, wait failure, and every post-SetValue error
  or panic are non-retryable uncertainty.
- Secret stdin, nonce, UTF-16, outgoing BSTR, and CurrentValue BSTR buffers are
  bounded/redacted/zeroized according to their ownership.
- No global keys, clipboard, screenshots, hooks, injection, process-memory
  access, or retry edge exists. The v3 profile's sole focus/Z-order change is
  activation of the exact revalidated target/composer immediately before one
  composer-queued Enter keydown/key-up pair.

## Automated I20 gates

Use an isolated ignored target directory and never execute a product command:

```text
cargo fmt --all -- --check
cargo test --locked --lib
cargo test --locked --lib --all-features platform::windows
cargo test --locked --bin openkakao-cli
cargo test --locked --test windows_backend --test windows_policy --test windows_cli
cargo test --locked --all-features --test windows_backend
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked
cargo build --locked --all-features
```

Run only the fourteen exact help/version/usage cases listed in
`.github/workflows/windows.yml` from `cli_test`. Do not replace this closed
allowlist with a skip list or full integration-target execution. The legacy
doctor/auth/cache cases may enter local-state or credential paths.

The synthetic compatibility suites `auth_flow_test`, `loco_client_test`,
`loco_crypto_test`, `loco_packet_test`, and `message_db_test` may also run;
they must not be replaced by live CLI/product invocations.

## Release-candidate interpretation

A green I20 proves buildability, lint, deterministic synthetic transaction
behavior, redaction, exact configuration/capability refusal order, and the
absence of automatic retry. It does not prove live KakaoTalk selector
compatibility, target identity, draft safety, or submission correctness.

Default-build production mutation must remain unreachable:

- `windows-ui-write` defaults off;
- `allow_windows_ui_write` defaults false;
- the Windows backend advertises `send_open_chat=false`; and
- native UI write call sites are not compiled.

The feature build may advertise guarded send only when the exact target and
composer profile plus its single-attempt submission strategy are compiled in.
Runtime configuration still defaults to refusal.

## Exit evidence

- integration worktree clean;
- all accepted source/integration commits recorded;
- default and all-feature builds recorded;
- all safe automated gates recorded;
- unsafe audit and residual blockers recorded;
- KakaoTalk UI mutation and actual message counts are zero;
- KakaoTalk data/credential access counts are zero;
- push and PR counts are zero; and
- `NEXT_HANDOFF.md` names L10 as a manual, not-yet-authorized next gate.
