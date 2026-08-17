# Root handoff: public Kakao installer provenance snapshot

Date: 2026-08-17 KST

> Successor: the x64 target/root/provider evidence was later accepted in
> [`../KAKAOTALK_X64_TRUST_PROFILE.md`](../KAKAOTALK_X64_TRUST_PROFILE.md).
> The non-authorization statements below describe this earlier installer-only
> checkpoint.

## Outcome

Two independent reviewers reproduced the current public KakaoTalk 26.7 stable
installer bytes from Kakao's corporate-page links. This preserves a
content-addressed installer snapshot for later disposable-VM work, but it is
**not** a production executable-trust bundle and supplies no runtime pin.

[Kakao's official-channel notice](https://pc.kakao.com/talk/notices/ko/2882?agent=win32)
identifies the Kakao corporate page and Microsoft Store as official Windows
distribution channels. The [corporate service index](https://www.kakaocorp.com/page/service/all)
contained the two `lk.kakaocdn.net` anchors below at review time.

| Channel | Architecture | Official mutable URL | Bytes | SHA-256 | Installer PE version |
|---|---|---|---:|---|---|
| stable | x86 | `https://lk.kakaocdn.net/talkpc/talk/win32/KakaoTalk_Setup.exe` | 83,870,776 | `44e3ee8ce7df28efc0c96486139c71436841c496d5a80d7adcab4eaa931b6358` | `26.7.0.5255` |
| stable | x64 | `https://lk.kakaocdn.net/talkpc/talk/win32/x64/KakaoTalk_Setup.exe` | 94,763,296 | `57dc1e9aaa56df4354b5bbf4daa60728375b08b834434777c28e60888e821882` | `26.7.0.5255` |

The URLs are latest aliases with no immutable version component or
publisher-supplied digest metadata. They can be replaced in place. The
[Microsoft winget manifest pinned at commit `780a6313`](https://github.com/microsoft/winget-pkgs/blob/780a6313731a43f3ed63ed6420a6afa5b673a798/manifests/k/Kakao/KakaoTalk/26.7.0.5255/Kakao.KakaoTalk.installer.yaml)
independently records the same two hashes. Its
[accepted PR](https://github.com/microsoft/winget-pkgs/pull/416623) is useful
corroboration, but the repository is community maintained and is not
Kakao-signed package metadata.

## Independent reproduction

Reviewer one streamed each URL, checked byte length and SHA-256, parsed the PE
version resource and embedded certificate table, and compared the result with
the pinned winget manifest. Reviewer two independently downloaded both URLs to
ignored `.target/wave2-root/provenance/2026-08-17`, checked the exact lengths
and hashes above, fetched the manifest by immutable commit, and confirmed that
the corporate-page HTML exposed exactly those two stable anchors.

The provenance reviewer recorded PowerShell 5.1.26100.9168, CLR
4.0.30319.42000, and curl 8.21.0; the root reproduction used an independent
PowerShell download/hash path. The second copy remains outside Git and was
never executed. Neither review accessed an installed KakaoTalk process, file,
UI, credential, database, token, or user-specific path.

Preliminary static Authenticode inspection found one `WIN_CERTIFICATE`, one
primary signer, and one classic countersigner in each installer. The installer
leaf SPKI SHA-256 was
`c7a395989045de47835902e0e9123a4d5dfa7f2efef6ec9cb036aedc697886dc`.
The x64 Authenticode SHA-384 matched its signed-content digest and its PKCS#7
cryptographic signature verified. These facts bind the installer only. The
installer signer must not be copied into a runtime `KakaoTalk.exe` profile.

## Why production remains unavailable

No architecture is selected. The two installers share the same file version
but describe different likely root kinds; the winget manifest records an x86
`ProgramFilesX86` location and an x64 `ProgramFiles64` location. That metadata
is corroboration, not accepted root evidence.

The following are still absent for either architecture:

- exact extracted/installed target `KakaoTalk.exe` whole-file SHA-256, PE
  machine, and file/product version;
- target executable leaf-SPKI reproduction by two tools and two reviewers;
- target WinTrust results under the repository's exact offline, no-UI,
  SHA-2-only policy, including primary/secondary signature cardinality;
- a reproducible known-folder kind and exact relative components from a
  disposable network-isolated VM; and
- proof that installer root overrides or alternate roots cannot bypass that
  relation.

Until one architecture satisfies all of those items in a separately accepted
bundle, production stays wired to `UnavailableExecutableTrust`, contains no
target hash/signer/root value, and advertises `send_open_chat=false`.
