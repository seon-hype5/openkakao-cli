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
The successor [`root-executable-trust-scaffold.md`](root-executable-trust-scaffold.md)
records the content-free trust decision seam and its then-missing native
observer.
[`root-native-ledger-store.md`](root-native-ledger-store.md) records the later
explicit-synthetic-base DPAPI/ACL store and why production remains unavailable.
[`root-native-trust-orchestration.md`](root-native-trust-orchestration.md)
records the fakeable offline WinTrust policy/state-lifetime seam and its
missing native adapter/profile.
[`root-native-ledger-location.md`](root-native-ledger-location.md) records the
earlier disconnected LocalAppData/fixed-volume/parent-chain constructor phase.
[`root-native-trust-adapter.md`](root-native-trust-adapter.md) records the
disconnected process/file/WinTrust/SPKI adapter and its deliberately missing
root provenance and production reference.
[`root-production-ledger-wiring.md`](root-production-ledger-wiring.md) records
the later trust-ordered lazy production-ledger composition and why no real
LocalAppData call becomes reachable.
