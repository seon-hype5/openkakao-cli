# Root process owner-group modal-evidence handoff

Date: 2026-08-17 KST

Status: conventional same-process owned-popup evidence is closed offline;
production mutation remains unreachable and fail-closed

Reviewed predecessor: `e94801fa9f181e95fc44505ba374b80be3e5ace2`.
The atomic successor containing this handoff must be reported externally
because a commit cannot contain its own identifier.

## Delivered boundary

Native inspection no longer derives modal absence from only the selected
window's enabled style. The richer scan runs only after exact executable-name
verification. A disabled selected window remains blocking. Otherwise a
synchronous top-level scan treats a candidate as blocking only when it is
visible, belongs to the selected PID, has a non-null owner, and shares the
selected window's root-owner group. Hidden, foreign-process, unowned, and
different-root-owner candidates do not block. Every matching owned popup is
conservatively blocking even if it could be modeless, and relevant
owner/root-owner uncertainty fails closed.

The scan uses only HWND/PID, visibility, `GW_OWNER`, and `GA_ROOTOWNER`
metadata. The callback retains no candidate collection or text. It does not
read a candidate title/class, UIA Name/Value, room/profile label, draft,
KakaoTalk file, credential, or process memory. The already selected class/PID
and enabled state are revalidated after enumeration.

Positive modal evidence prevents composer traversal. Public mapping also
suppresses composer identity and all input-availability evidence even if an
internally inconsistent synthetic value carries both modal and composer
metadata. Fresh mutation observation returns the same modal state before
opening a mutation composer.

Final native preflight repeats the scan under the transaction mutex. The
actual `SetValue` and `Invoke` methods repeat it again, then perform the final
wall/monotonic time check and native call. A positive final-preflight result
uses the fixed allowlisted `windows_mutation_modal` operation before the
execution claim. After claim and Value/Invoke method entry, the transaction's
existing conservative uncertainty normalization still applies even when the
last modal gate stops before the OS call. Production cannot reach those calls
because capability, executable trust, target identity, and submit selector
gates remain closed.

## Synthetic verification

A pure classifier covers self, foreign PID, hidden, unowned, different
root-owner, matching root-owner, missing root-owner, and invalid selected
metadata. A mapping test proves modal evidence hides composer/input claims.
Neither test invokes `EnumWindows`, `GetWindow`, `GetAncestor`, UIA, or another
desktop API. The complete safe matrix and final counts are recorded in
[`../NEXT_HANDOFF.md`](../NEXT_HANDOFF.md).

No doctor, KakaoTalk/UIA probe, local-state or credential command, known-folder
resolution, stage, `SetValue`, `Invoke`, or send ran. No UI focus, Z-order,
clipboard, keyboard, window-message, hook, injection, or process-memory action
occurred.

## Remaining blockers

1. Generic Win32 owner chains cannot identify an unowned custom dialog or an
   overlay rendered inside the selected window. Future activation needs
   negative live measurements and a reviewed version-specific rule if either
   shape exists.
2. No approved, measured, version-bound self-chat selector or ephemeral label
   observer exists.
3. No exact unique submit selector or production `InvokePattern` exists.
4. Independent native unsafe/root review and a clean pinned Windows CI run
   remain external requirements.
5. Reviewed Kakao signer/root provenance and production trust wiring remain
   absent; `UnavailableExecutableTrust` stays wired.
6. L10 retry and L20-L40 remain unauthorized and blocked.

This handoff grants no live observation, UI mutation, send, or
capability-activation authority.
