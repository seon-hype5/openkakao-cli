# Windows port decisions

## ADR-001: Official desktop UI, not login or local data

Use the already-authenticated official desktop application's accessibility
surface. Do not add LOCO login, credential extraction, KakaoTalk DB access, or
process-memory techniques to the Windows MVP.

## ADR-002: Self-chat and opened-only

Wave 1 recognizes only an already-open, exact-and-unique self-chat. It does not
search for or open rooms. Ambiguity fails closed.

## ADR-003: Read-only probe and sealed mutation capability

Inspection and mutation are separate traits. Mutation accepts only a sealed
`ApprovedSend`; dry-run depends only on the inspection trait.

## ADR-004: Target-scoped SQLite features

Keep `bundled-sqlcipher` on macOS, where legacy KakaoTalk DB code exists. Use
plain `bundled` SQLite elsewhere for openkakao's own cache. Do not install an
OpenSSL workaround that would accidentally imply Windows KakaoTalk DB support.

## ADR-005: windows-rs 0.62.2 with explicit features

Use Microsoft's `windows` crate only on Windows with the minimum namespaces
needed for process/session/file-version/window/UIA discovery. Dependency or
feature expansion requires a root RFC with an official API reference.

## ADR-006: Preserve the macOS implementation

Do not move or rewrite the existing AX module in the contract commit. Replace
its unsafe substring fast-path decision with the common exact-and-unique
matcher and retain the public facade.

## ADR-007: Integration by cherry-pick

Children produce clean atomic commits on branches rooted at the frozen
contract. Root verifies ownership and cherry-picks policy, backend, then CLI.
No force operations, push, or PR creation are permitted in this session.
