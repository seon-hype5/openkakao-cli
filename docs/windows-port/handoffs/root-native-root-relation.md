# Root native installation-relation handoff

Date: 2026-08-17 KST

Status: generic runtime root derivation complete and disconnected; production
provenance, independent review, and wiring remain absent

Reviewed predecessor: `74dff3ef5c6d957f275f3c21d7af375b0c2f04c5`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

- `InstallRootDigest` now retains its source-static `InstallRootKind` inside the
  reviewed profile while exposing neither expected components nor digest bytes.
- The fakeable observer receives only that kind, proving the selected root
  authority comes from the profile rather than the observed executable.
- The Windows adapter maps the three kinds exactly to Program Files x86,
  Program Files x64, or current-user LocalAppData known-folder IDs.
- Every non-null Shell path allocation is owned before HRESULT handling and
  released exactly once.
- Source and canonical root paths are opened no-follow; the canonical root and
  ancestor handles exclude write/delete sharing through VERIFY, CLOSE, root
  revalidation, and final executable reopen.
- Root and executable must be normalized paths on the same fixed volume-GUID
  namespace, with a strict component-boundary descendant relation.
- Only bounded portable relative ASCII components enter temporary zeroizing
  buffers and the existing version-1 codec. Native output is an evidence-only
  digest that cannot construct a reviewed profile value.

## Changed files

- `src/platform/windows/executable_trust.rs`: reviewed-kind retention and the
  shared static/observed byte codec.
- `src/platform/windows/executable_trust_native.rs`: known-folder ownership,
  retained guards, relation derivation, revalidation, and adversarial tests.
- Current Windows activation, security, provenance, decision, CI handoff, and
  integration documents record the completed generic boundary.

## Verification and safety

Focused exact-kind, valid relation, sibling/volume/ADS/device/non-ASCII/depth
refusal, fake orchestration, and repository-fixture tests pass. The complete
safe matrix is recorded in [`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md).

The full process/HWND-bound adapter was not constructed. No real known folder,
installed executable, KakaoTalk path/process/window/data, credential, or UI
state was read. No product or fixture executable was launched, no UI mutation
or message send occurred, and no production reference/capability changed.

## Remaining blockers

1. A second reviewer must independently audit the new Shell allocation,
   directory-handle lifetime, prefix relation, and zeroizing codec boundary
   together with the existing WinTrust unsafe path.
2. A clean pinned Windows CI image must reproduce the full safe matrix.
3. No Kakao release signer, installer hash, root kind/components, or version
   bundle has been accepted with independent provenance.
4. The process-bound adapter has no production constructor call and
   `UnavailableExecutableTrust` remains wired.
5. Target/submit selectors and all live gates remain separately blocked.

This handoff supplies no authority to inspect an installed/downloaded Kakao
artifact, retry L10, mutate UI, or enable `send_open_chat`.
