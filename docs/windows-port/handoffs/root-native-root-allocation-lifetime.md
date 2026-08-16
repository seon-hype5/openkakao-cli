# Root native Shell-allocation lifetime handoff

Date: 2026-08-17 KST

Status: synthetic success/failure/NULL ownership proof complete; production
provenance, independent review, and wiring remain absent

Reviewed predecessor: `efa4f13d6d94a71aeadcaadb7d6962b0bb17601d`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

- The raw `SHGetKnownFolderPath` call still preserves a non-null output pointer
  even when HRESULT reports failure.
- One private result decoder moves every non-null pointer into an RAII owner
  before inspecting HRESULT.
- Raw decoder, constructor, and release calls retain explicit `unsafe`
  allocation/string preconditions at their callers.
- The owner carries the matching private release function and invokes it once
  on success, failure, or later path-validation refusal. NULL is never released.
- Production continues to use only `CoTaskMemFree`.
- A counting synthetic release wrapper proves the success, `E_FAIL`, relative
  path refusal, successful NULL, and failed NULL branches with buffers created
  by `CoTaskMemAlloc`.

## Verification and safety

The full safe regression matrix and exact counts are recorded in
[`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md). The process/HWND-bound adapter was
not constructed and `SHGetKnownFolderPath` was not called. No installed
executable, KakaoTalk path/process/window/data, credential, or UI state was
read. No product or fixture executable was launched, no UI mutation or message
send occurred, and no production reference or capability changed.

## Remaining blockers

1. A second reviewer must independently audit the Shell result owner together
   with the known-folder guards, relative relation, and WinTrust lifetime.
2. A clean pinned Windows CI image must reproduce the full safe matrix.
3. No Kakao release signer/root/version provenance bundle has been accepted.
4. The process-bound adapter has no production constructor call and
   `UnavailableExecutableTrust` remains wired.
5. Target/submit selectors and all live gates remain separately blocked.

This handoff supplies no authority to inspect an installed or downloaded Kakao
artifact, retry L10, mutate UI, or enable `send_open_chat`.
