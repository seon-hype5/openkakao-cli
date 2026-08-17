# Root handoff: Windows native-trust assumption qualification

Date: 2026-08-17 KST

Branch: `integration/windows-mvp`

The reviewed predecessor is
`f7d94c68e875aafcc3722c7199dda2fdf69e1682`. The successor commit containing
this handoff must be reported externally because it cannot embed its own hash.

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
enter. The committed Windows workflow therefore runs the OS script and the
Rust library suite on the hosted image, where the result is still required.

This is not production activation evidence. Production remains wired to
`UnavailableExecutableTrust`, and no KakaoTalk process, file, path, UI,
credential, or message was accessed or changed.

## Remaining activation gates

- Run the committed script and Rust test on the pinned hosted Windows image and
  every declared supported Windows/NTFS build.
- Qualify a trusted timestamped SHA-2 WinTrust success through the real provider
  chain and record its legal high-word flags.
- Prove weak-signed MD5/SHA-1 WinTrust rejection end to end in an isolated VM.
- Accept one architecture-specific target bundle containing exact installed
  target bytes/length, version/machine, target leaf SPKI, install-root relation,
  signature algorithm, and timestamp semantics.
- Keep production construction disconnected until a separate wiring review;
  selector measurement and every live gate retain their own approval boundary.

Hosted execution also depends on pushing the branch. Repository write
authentication was still unavailable when this handoff was prepared.
