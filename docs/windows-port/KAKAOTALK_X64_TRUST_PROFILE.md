# KakaoTalk Windows x64 stable executable-trust profile

Date: 2026-08-17 KST

## Acceptance boundary

This is the accepted public, architecture-specific executable-trust bundle for
source profile `kakaotalk-windows-x64-stable-26.7.0.5255-v2`. It authorizes
embedding only the target whole-file digest, target leaf-SPKI digest,
`ProgramFiles64` root relation, exact file version, and the qualified WinTrust
provider policy. It does **not** authorize a live UI observation, composer
mutation, submit-selector choice, `send_open_chat=true`, or a message send.

Selector profile v2 reuses the same executable-trust bytes as v1 and changes
only the exact composer control type from Edit to Document. That revision is
based on a bounded live result showing the reviewed class/AutomationId pair but
no Edit triple, plus Microsoft's published
[RichEdit-to-Document UI Automation mapping](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-controlsupport).
It adds no alternate selector or fallback and does not itself
authorize a live retry or mutation.

The schema is `openkakao.windows.executable-trust-profile.v1`, the channel is
`stable`, the architecture is `x64`, and there is no predecessor executable-
trust bundle. Rollback means restoring `UnavailableExecutableTrust`; it never
means falling back to a version-only, signer-only, or alternate-root match.

## Distribution artifact

Kakao's [official-channel notice](https://pc.kakao.com/talk/notices/ko/2882?agent=win32)
identifies the corporate service page as an official Windows distribution
channel. At review time its mutable x64 latest link was
`https://lk.kakaocdn.net/talkpc/talk/win32/x64/KakaoTalk_Setup.exe`. The
byte-identical `https://app-pc.kakaocdn.net/talk/win32/x64/KakaoTalk_Setup.exe`
alias is pinned by the
[Microsoft winget manifest at commit `780a6313`](https://github.com/microsoft/winget-pkgs/blob/780a6313731a43f3ed63ed6420a6afa5b673a798/manifests/k/Kakao/KakaoTalk/26.7.0.5255/Kakao.KakaoTalk.installer.yaml).
That community manifest is corroboration, not Kakao-signed metadata.

| Field | Accepted value |
|---|---|
| installer bytes | `94,763,296` |
| installer SHA-256 | `57dc1e9aaa56df4354b5bbf4daa60728375b08b834434777c28e60888e821882` |
| corporate-link observation | `2026-08-17 06:47–06:57 KST` |
| corporate-link `Last-Modified` | `2026-08-11T01:12:23Z` |
| hosted mirror retrievals | `2026-08-17T02:29:12Z` and `2026-08-17T02:29:13Z` |
| hosted response metadata | no `Last-Modified` or ETag exposed |

Both mutable aliases are accepted only when byte length and SHA-256 match this
table before parsing or installer execution.

## Target executable

The installer was parsed as NSIS with pinned 7-Zip 26.02. A static extraction
and a fresh default installation produced byte-identical `KakaoTalk.exe`
files. Two independent SPKI derivations—RSA
`ExportSubjectPublicKeyInfo` and reconstruction from the certificate's encoded
algorithm parameters/key value—matched the earlier Windows
`CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)` reproduction.

| Field | Accepted value |
|---|---|
| filename | `KakaoTalk.exe` |
| PE machine / optional header | AMD64 `0x8664` / PE32+ `0x020b` |
| file and product version | `26.7.0.5255` |
| bytes | `34,857,576` |
| digest kind | `whole-file-sha256-v1` |
| whole-file SHA-256 | `882b326ad348ed9d51b92fcf3aa09ada27ed4a737fba4b8ab4d7168576c96e50` |
| leaf SPKI SHA-256 | `c7a395989045de47835902e0e9123a4d5dfa7f2efef6ec9cb036aedc697886dc` |
| embedded primary / secondary signatures | `1` / `0` |
| classic countersigners / nested signatures | `1` / `0` |
| content-digest algorithm | SHA-384, OID `2.16.840.1.101.3.4.2.2` |
| signed Authenticode digest | `0495b8cf2382be66049fe8dab14bc47cbc6c72718979dd4111e7e28c386dcf347647679d185883f74c98ffc02917adc7` |
| timestamp semantics | one classic Authenticode countersignature; no RFC3161/nested signature |

`SignedCms.CheckSignature(true)` succeeded, and an independent PE
Authenticode hash calculation matched the signed SHA-384 value. The source pin
is still the complete-file SHA-256 because Authenticode deliberately excludes
some PE bytes.

## Exact WinTrust provider result

The guarded target handle was verified with invalid/noninteractive HWND,
`WTD_UI_NONE`, embedded-file choice, `WTD_REVOKE_WHOLECHAIN`, caller flags
`0x00003080` (cache-only URL retrieval, chain excluding root, MD2/MD4
disabled), `WSS_GET_SECONDARY_SIG_COUNT`, and a live
`CERT_STRONG_SIGN_PARA` selecting `szOID_CERT_STRONG_SIGN_OS_1`. VERIFY and
CLOSE used the same unmanaged allocations.

The target returned success for VERIFY and CLOSE, one provider signer, zero
provider/final errors, SIP subject choice, no catalog recall, zero secondary
signatures, verified index zero, and exact provider-to-caller pointer identity.
`CRYPT_PROVIDER_DATA` was 240 bytes and `dwProvFlags` was exactly
`0x80003080` on both:

- Windows 11 `10.0.26200.9168` with the local SDK/PowerShell P/Invoke
  reproduction; and
- GitHub `windows-2022`, Windows Server 2022 `10.0.20348`, runner image
  `20260802.262.1`.

The Microsoft SDK says the provider low word is initialized from the caller
flags and defines `CPD_USE_NT5_CHAIN_FLAG` as `0x80000000`. The qualified
policy therefore requires the exact caller low word plus that one documented
provider bit. CPD revocation high bits, RFC3161, lower-quality-chain, or unknown
bits remain refusals. The SHA-2-only strong-sign policy independently excludes
weak signature algorithms.

## Installation-root relation

The network-isolated default installation on a fresh hosted VM produced
exactly:

- root kind: `ProgramFiles64`;
- relative components: `Kakao`, `KakaoTalk`, `KakaoTalk.exe`; and
- relation-codec SHA-256:
  `737529deafe88fb3b3bccd0fb6625b944aac87d783b1529c399db6e300b68e2e`.

The installer does accept NSIS `/D` and, in a separate fresh VM, installed the
same reviewed target under the requested temporary root with relative
components `KakaoTalk`, `KakaoTalk.exe`. That capability is recorded rather
than hidden. It cannot satisfy this production profile: runtime verification
resolves `FOLDERID_ProgramFilesX64` and requires the exact three-component
relation digest above. Any override, x86, per-user, relocated, or additional
component relation fails closed before UI inspection.

During both installer observations a machine-wide outbound block was active
and an IFEO debugger refusal for `KakaoTalk.exe` was installed. The workflow
asserted that no KakaoTalk process existed before or after installation and
reported `product_binary_executed=false`; it uploaded no artifact. The public
evidence is the successful
[GitHub Actions run `31988112914`](https://github.com/seon-hype5/openkakao-cli/actions/runs/31988112914)
at source commit `c591d565835aafc7cc0ba22d5e83be2b04113e75`.

## Reproduction and review

Reproduction A used PowerShell 5.1.26100.9168, two independent SPKI encoders,
pinned 7-Zip 26.02, direct PE/ASN.1 parsing, complete-file hashing, and the
exact WinTrust P/Invoke state. Reproduction B used the repository-owned
PowerShell 7 workflow in two independent fresh hosted VMs, re-downloaded both
pinned inputs, repeated every target/signature/provider check, and compared
the static extraction with installed bytes. The earlier independent public
installer review and immutable winget snapshot agree with both.

No reproduction read an existing KakaoTalk installation, process memory,
credential, database, token, room label, message body, or user-specific path.
The next permissible source change may construct this exact trust profile
while leaving `send_open_chat=false`; live L10 still requires its own fresh
approval.
