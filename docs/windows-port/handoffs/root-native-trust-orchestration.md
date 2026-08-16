# Root handoff: fakeable native trust orchestration

## Outcome

This change freezes the call policy and lifetime orchestration for the future
Windows executable-trust observer without making a native trust call or
opening any executable. It connects a crate-private fake adapter to the
existing content-free pure verifier and remains disconnected from
`NativeMutationPort`.

The fixed call policy requires:

- `WINTRUST_ACTION_GENERIC_VERIFY_V2`;
- a noninteractive invalid-window call plus `WTD_UI_NONE`;
- `WTD_CHOICE_FILE`, never a catalog subject;
- `WTD_REVOKE_WHOLECHAIN`;
- `WTD_CACHE_ONLY_URL_RETRIEVAL`;
- `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`;
- `WTD_DISABLE_MD2_MD4`;
- `WTD_UICONTEXT_EXECUTE`; and
- `WSS_GET_SECONDARY_SIG_COUNT`.

The adapter cannot supply alternate flags. Any change requires modifying the
fixed policy constructor and exact-policy test.

## State lifetime

The orchestration order is:

```text
content-free path observation
  -> VERIFY state creation
  -> provider/signer extraction
  -> exactly one CLOSE
  -> canonical-path identity reopen while the original path state is alive
  -> pure evidence verification
```

Every state successfully returned to the orchestrator receives exactly one
CLOSE attempt before extracted evidence is accepted. Extraction error or
unwind still closes. CLOSE error or unwind
overrides apparent trust success and becomes a fixed
`windows_executable_signature_trust` refusal. A path or begin failure does not
invent a state and therefore does not call CLOSE.

Only copied content-free evidence survives CLOSE. The third file identity is
observed only afterward, while an opaque original-path state is still alive,
so a replacement during verification cannot be accepted. Future pointers
returned by WinTrust are required to remain borrowed within the adapter's
extraction call. The native adapter must additionally protect the interval
between a successful `WinVerifyTrust` call and returning its state with a
local RAII guard; a panic in that interval cannot strand native state.
`catch_unwind` normalizes only the returned refusal: the process panic hook may
still run, so production adapter code must not panic with a path, provider
message, certificate field, or other dynamic content.

## Evidence mapping

Only integer WinVerifyTrust status `0` maps to `AuthenticodeStatus::Trusted`.
Catalog choice, any secondary signature, zero/multiple primary signer count,
signer mismatch, canonical-root mismatch, or file-identity replacement still
fails in the existing pure verifier. Primary and secondary counts use
saturating addition, so an adversarial count cannot wrap to one.

All adapter failures use the existing closed output operation vocabulary. The
path, file identities, signer/root digests, state token, provider pointers,
and any system error text are absent from error and Debug surfaces.

## Synthetic coverage

Nine fake-adapter tests cover:

- exact successful order and fixed policy;
- path failure and VERIFY-begin failure with zero CLOSE calls;
- extraction error and panic with exactly one CLOSE;
- CLOSE error and panic overriding success;
- observe/begin panic sanitization;
- post-CLOSE reopen failure/panic and exact ordering;
- nonzero trust status, catalog choice, and secondary-signature refusal;
- signer cardinality/digest and reopened-file identity mismatch; and
- redacted, content-free Debug output.

The tests do not call `WinVerifyTrust`, open a file, enumerate a process or
window, resolve a path, or construct `WindowsBackend`.

## Production state and remaining work

Production still uses `UnavailableExecutableTrust`; the new observer has only
a generic crate-private adapter contract and no Windows API implementation.
Before that placeholder can be replaced, a separate reviewed adapter must:

1. bind an opened process-image file to PID/process creation time;
2. obtain and bound the final volume-GUID path and all component reparse state;
3. prove a fixed local volume and three-way file identity, with the final
   identity reopened only after CLOSE while the original handle remains alive;
4. run the exact policy above, borrow provider state only until CLOSE, and
   DER-encode/hash the leaf SPKI with strict pointer bounds; use an adapter-local
   RAII guard from native state creation until ownership reaches the
   orchestrator;
5. derive the versioned root-relation digest; and
6. receive independently reviewed signer/root profile digests rather than
   learning them from the current machine.

No live executable-signature observation is authorized by this seam.

## Verification

All commands use `.target/wave2-root`.

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- focused native-trust orchestration tests: 9 passed.
- default library suite: 147 passed.
- debug and release all-feature Windows unit subtree: 73 passed each.
- all-feature Windows backend contract tests: 2 passed.
- all-feature debug and release builds: passed.

The final integration matrix and commit SHA are recorded in the updated
checkpoint after commit.

## Safety ledger

- WinVerifyTrust/native executable observations: 0.
- Live KakaoTalk/UIA inspection or mutation: 0.
- `CurrentValue`, `SetValue`, or `Invoke` against a live provider: 0.
- Messages sent: 0.
- KakaoTalk executable/data/database/credential/token access: 0.
- Network writes, pushes, PRs, and releases: 0.
