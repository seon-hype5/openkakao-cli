# Wave handoffs

Each child writes only its assigned handoff file and records:

- status and assigned branch;
- atomic commit SHA;
- changed files;
- tests and results;
- skipped tests;
- assumptions and residual risks;
- contract or dependency RFCs.

Handoffs must not include message text, room/profile names, user identifiers,
raw HWND/UIA identifiers, screenshots, or KakaoTalk data paths.

Root integration/offline-scaffold handoffs follow the same privacy rules; see
[`root-ledger-scaffold.md`](root-ledger-scaffold.md) for the current durable
replay state-machine boundary and remaining production-store blockers.
