# Windows MVP security model

## Assets and primary hazards

The protected assets are the user's account, conversation privacy, target
correctness, current draft, and freedom from duplicate submission. The main
hazards are writing to the wrong chat, destroying an existing draft, racing a
user or restarted process, leaking message/target material, and retrying an
uncertain submission.

## Deny-by-default authorization layers

A Windows UI write is unavailable unless every independent layer permits it:

- the binary was built with the default-off `windows-ui-write` feature;
- `safety.allow_windows_ui_write` is explicitly true;
- the backend advertises the required send capability;
- the requested target occurs exactly once in the configured allowlist;
- request-scoped opaque evidence binds that exact requested label to the
  independently observed target and complete redacted snapshot;
- the request is self-chat, stdin-only, opened-only, explicitly confirmed,
  and within the fixed input limits;
- policy evidence proves a supported profile, exact unique self target, empty
  draft, no focus/modal, compatible process/session/integrity, and a fresh TTL;
- a process-local approval mutex and hashed one-use nonce are available;
- a zero-wait named Windows mutex provides cross-process exclusion;
- fresh transaction state exactly matches the approved state; and
- final native PID/HWND/path/process-creation/session/UIA evidence still
  matches immediately before the atomic execution claim.

The current production backend deliberately advertises no send capability.
It has no privacy-safe target identity proof and no measured commit selector,
so no amount of CLI flags or configuration can currently reach `SetValue` or
`Invoke`.

## Target, state, and replay rules

- Only a deterministically verified self-chat may progress beyond inspection.
- Matching is byte-exact and unique; partial, normalized, case-folded, absent,
  unreadable, or duplicate candidates are refusals.
- Missing, replayed, state-moved, wrong-case, whitespace-changed,
  Unicode-normalized, or unpaired-surrogate target evidence is a refusal.
- Fresh native state must re-establish target binding; setting only
  self/exact/unique flags cannot authorize draft access or mutation.
- The native mutation port carries the same approval through observation and
  final preflight. An observed UTF-16 label can be checked only against that
  approval's private policy-bound snapshot; callers cannot substitute a
  different snapshot, and no observed label is retained.
- Target selection is a closed native state. Only exact-unique selection may
  carry a label to the permit verifier; absent, inexact, and ambiguous states
  cannot invoke it or construct contradictory evidence flags.
- PID alone is insufficient. A run-local digest includes executable identity
  and process creation time, and native preflight requeries both.
- Existing, unknown, or changed drafts; stale snapshots; user focus; modals;
  session/integrity mismatch; and ambiguous windows/composers are refusals.
- Modal evidence includes both a disabled selected window and every visible
  same-process owned top-level popup in its root-owner group. Owner-query
  uncertainty refuses; visible modeless owned popups may conservatively block.
- Snapshot validity uses two half-open intervals: equality with either the
  wall-clock expiry or approval-owned monotonic deadline is stale. A clock
  rollback cannot extend the original remaining lifetime; a forward jump can
  only refuse earlier.
- The monotonic deadline is private, process-local, nonserializing, omitted
  from Debug, and checked before sender dispatch, native observation, final
  preflight, and each actual Value/Invoke call.
- One approval is consumed by one synchronous reviewed sender call. A
  crate-private atomic claim prevents a second native write attempt.
- Policy nonce tracking is process-local and hashed. A content-free replay
  codec/state machine is implemented synthetically, but durable Windows
  storage is intentionally replaced by a fail-closed placeholder while
  production commit remains unavailable.

## Message and output privacy

Windows message input is accepted only from stdin. Acquisition stops after
4,001 raw bytes so overflow is detected before constructing the final String.
Accepted input is capped at 4,000 valid UTF-8 bytes and 1,000 Unicode scalar
values and rejects empty/all-whitespace text, NUL/control characters, CR/LF,
U+2028, and U+2029.

Temporary input buffers are zeroized on read, overflow, and UTF-8 failures;
`SecretMessage`, intent, approved nonce material, and native UTF-16/BSTR
buffers are scrubbed on release. Debug, Display, JSON, human output, errors,
fixtures, screenshots, and committed artifacts must never contain message
text, real room/profile names, draft text, HWND, or UIA runtime IDs.

The production read-only probe does not read window titles, UIA Name/Value,
room/profile labels, or draft contents. Reports contain only fixed allowlisted
action/profile/evidence/operation codes and run-local fingerprints. Unknown
operation strings are replaced with `redacted_operation` in both streams.
A rejected legacy positional message is handled by generic parse output so
clap cannot echo it.

The modal scan begins only after exact executable-name verification and reads
only HWND/PID, visibility, owner, and root-owner relationships. Its callback
retains no candidate list, title, class, or UIA property and publishes only the
final boolean. Positive modal evidence also suppresses composer identity and
input-availability evidence.

The offline target-binding contract uses a new random HMAC-SHA-256 key for
each policy inspection. It streams the configured label through UTF-16 without
allocating a second label buffer. Returned proof bytes have no public accessor,
format only as redacted, are never serialized, commit to the full snapshot,
and cannot validate under another request key. The native observer currently
passes no label to the approval-owned verifier, so no production label read was
added and production cannot currently create such proof.

No KakaoTalk data directory, database, token, cookie, credential, process
memory, injection, hook, unofficial login, or telemetry is used by this port.

## Mutation and uncertainty rules

The guarded implementation uses UIA ValuePattern and InvokePattern only. It
does not use the clipboard, global keys, forced focus/Z-order, guessed window
messages, or retries.

Stage clears only an exactly read-back value that remains byte-for-byte owned
by the transaction. If the user or provider changes it, the code leaves it
untouched. Commit requires an exact unique Invoke selector and issues at most
one Invoke. Every error or panic after Invoke begins is normalized to
`SubmissionUncertain`; commit-attempt outcomes and errors are always
`retry_safe=false` and exit 21. A sender result incompatible with the approved
mode is treated the same way.

The Windows named mutex is held across observation, final validation, write,
readback, restore, or Invoke. Abandoned ownership is a refusal, not permission
to continue. Native UI work stays synchronous so neither the approval lease
nor mutex outlives the transaction invisibly.

Owner-group modal evidence is refreshed during observation, final preflight,
and immediately before each actual Value/Invoke call. A positive result is a
fixed `ModalPresent` refusal before the execution claim. Once a Value/Invoke
method has been entered after the claim, the existing conservative
`SubmissionUncertain` normalization applies even when this final gate refuses
before the OS call. A failed relevant relationship query is never proof of
absence.

## Remaining security blockers

The proposed contracts and activation order are in
[`ACTIVATION_RFC.md`](ACTIVATION_RFC.md). Merging that proposal grants no live
or write authority.

- The privacy-safe request/proof and fresh-state gates exist synthetically,
  but no approved, measured native selector or ephemeral UTF-16 observer can
  yet prove that the current room is the requested self-chat.
- No live-measured exact unique send-button selector/InvokePattern is
  configured.
- A pure executable-trust verifier, fakeable VERIFY/extract/CLOSE
  orchestration, and a disconnected native process/path/file/WinTrust/SPKI
  adapter exist. Distinct source-static target-byte, signer, and root-relation
  profile types prevent runtime observations from becoming expected pins.
  Runtime verification now requires an exact complete-file SHA-256, NTFS on a
  fixed local volume, a guarded second process-image path query, exact file
  identities, exact version/root/signer, and WinTrust's SHA-2-only strong-sign
  policy. Provider extraction exact-checks owned state/pointer links, SIP
  subject choice, effective provider flags, catalog recall, top-level/nested
  errors, primary index, and helper pointer identity. Root derivation receives
  only the source-static known-folder kind and emits a bounded relation digest;
  observed paths cannot construct a profile. The repository fixture exercises
  structure, complete-file hashing, strong-policy pointer lifetime, SPKI, and
  cache-only VERIFY/CLOSE without execution. The native adapter and fixture
  remain disconnected from KakaoTalk.

  Independent unsafe review accepted these additions for a production-
  disconnected merge, but activation remains blocked. On Windows
  `10.0.26200.0`/NTFS, a signed-PowerShell qualification rejected MD5/SHA-1,
  accepted SHA-256, and passed replacement before, between, and after the two
  process-image path queries. The committed OS script and a Rust test now gate
  those assumptions. Local Smart App Control refused the newly linked unsigned
  Rust test binary before entry; it was compile/lint checked without bypassing
  policy, and hosted execution remains required.

  Windows still documents `QueryFullProcessImageNameW` as returning a path,
  not a backing-file identity, so the NTFS timing matrix must pass on every
  declared supported Windows image. A trusted timestamped fixture must also
  qualify real provider traversal, weak-signature rejection, and legal provider
  high-word flags. The current exact provider flag comparison may
  conservatively reject RFC3161 timestamp state. No architecture-specific
  Kakao target hash/SPKI/root bundle or production wiring exists. Production
  refuses at `windows_executable_trust_unavailable` before ledger or UI
  observation.
- Generic owner-chain evidence does not detect an unowned custom dialog or an
  overlay drawn inside the selected window. Activation needs negative live
  measurements and a reviewed version-specific rule if either shape exists.
- A blocked third-party UIA provider receives one zero-wait COM cancellation
  request after the read-only worker's single eight-second budget expires.
  Standard marshaling may unblock the client, but custom marshaling may expose
  no cancel object and a server may continue after cancellation. Read-only
  discovery therefore remains process-wide single-flight: the lease clears
  only when the worker really returns, and one unsupported hung call blocks
  later probes instead of allowing retained workers to accumulate. The worker
  thread ID stays pinned through the request so it cannot identify a recycled
  unrelated thread.
- Cross-process exclusion, the pure replay transition protocol, and a
  policy-owned one-use redacted correlation token exist. A current-user
  DPAPI/protected-ACL/write-through store is synthetically tested only under an
  explicit temporary base. The LocalAppData/volume-GUID/parent-chain locator
  is wired to the native port through a side-effect-free lazy factory, but
  transaction ordering verifies executable trust first. Current production
  trust refuses, so neither tests nor reachable production paths resolve the
  known folder or open the store. A future ledger-open error or unwind is a
  permanent non-retryable uncertainty for that transaction object.

These are blockers to enabling production write capability, not reasons to
weaken the gates.

## Test and live-validation policy

Automated gates may compile all features and exercise fake/synthetic ports.
They may parse the committed synthetic Authenticode fixture in memory and call
WinTrust on that fixture only with the frozen cache-only/noninteractive policy;
they must not execute that fixture. The native-assumption gate may launch only
its owned temporary OS-supplied loopback helper and an exact ignored copy
of the Rust unit-test harness. Both are bounded, windowless, detached from
product or user data, stopped by their parent, and retained nowhere; only the
signed helper sends loopback traffic. Gates must not change a certificate
store, launch a live UI probe, open an installed application, or run a product
write command. CI has no credentials, app setup, secret injection, UI dump,
screenshot, trace, or artifact upload.

L10 read-only inspection and L20-L40 mutation validations require their own
fresh approvals. I20, a green build, or the existence of guarded native call
sites authorizes none of them.
