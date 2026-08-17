# Root handoff: Windows native-trust assumption qualification

Date: 2026-08-17 KST

Branch: `integration/windows-mvp`

The qualification implementation is
`e2f257d2e3b2d6017f698a47fa9c2694e1d545a0`. The successor commit containing
this hosted result and cross-platform compile-parity fixes must be reported
externally because it cannot embed its own hash.

## Outcome

The disconnected Windows executable-trust adapter now exposes one shared
production helper for its guarded second process-image path query. The helper
requires exact canonical-path and file-identity agreement with the retained
verification handle. A Windows Rust test uses that same helper for replacement
completed before the first query, between the first query and guarded open, and
after the second query.

The production `CERT_STRONG_SIGN_PARA` construction is also shared with an OS
semantic test. With no signing certificate, the exact `szOID_CERT_STRONG_SIGN_OS_1`
policy must reject MD5 and SHA-1 and accept SHA-256. Pointer/lifetime tests and
the cache-only WinTrust fixture remain separate and unchanged in purpose.

## OS qualification result

The committed
[`qualify-windows-trust-assumptions.ps1`](../../../scripts/qualify-windows-trust-assumptions.ps1)
was parser-validated. The host's restricted script execution policy prevented
direct file invocation, so the same API and three-timing qualification body was
run inline through the already trusted PowerShell host without changing that
policy. It reported:

```text
windows_version=10.0.26200.0 filesystem=NTFS strong_hash=pass timings=before,between,after:pass
```

The run used three fresh byte-exact temporary copies of the OS-supplied
System32 `ping.exe`, whose local catalog signature status was `Valid`. Each was
windowless and limited to `127.0.0.1`. All three owned
processes were stopped and waited, the generated temporary root was removed,
and no helper was supplied an external network destination. No product
executable, installed application, user data, trust store, or UI was accessed.

## Rust and policy status

`cargo test --locked --lib --no-run` and warnings-denied all-target/all-feature
Clippy pass with the new tests. Local Smart App Control refused the newly
linked unsigned Rust test executable before entry with OS error 4551. The
policy was not disabled, bypassed, or relaxed; the copied ignored helper did not
enter. The
[hosted Windows workflow](https://github.com/seon-hype5/openkakao-cli/actions/runs/31985013629)
then passed the committed OS script, Rust library suite, lint, synthetic tests,
and debug/release build matrix at `e2f257d`.

This is not production activation evidence. Production remains wired to
`UnavailableExecutableTrust`, and no KakaoTalk process, file, path, UI,
credential, or message was accessed or changed.

## Remaining activation gates

- Repeat the committed script and Rust test on every declared supported
  Windows/NTFS build; the pinned GitHub-hosted image is one passing data point.
- Qualify a trusted timestamped SHA-2 WinTrust success through the real provider
  chain and record its legal high-word flags.
- Prove weak-signed MD5/SHA-1 WinTrust rejection end to end in an isolated VM.
- Accept one architecture-specific target bundle containing exact installed
  target bytes/length, version/machine, target leaf SPKI, install-root relation,
  signature algorithm, and timestamp semantics.
- Keep production construction disconnected until a separate wiring review;
  selector measurement and every live gate retain their own approval boundary.

The branch was pushed to the `seon-hype5/openkakao-cli` fork. Its paired
[cross-platform run](https://github.com/seon-hype5/openkakao-cli/actions/runs/31985013674)
passed the Linux synthetic job and exposed one Linux all-feature dead-code
scope error plus one macOS `CFArray` indexing error. The successor fixes those
compile-only defects; both hosted workflows must be green before upstream
release work.
