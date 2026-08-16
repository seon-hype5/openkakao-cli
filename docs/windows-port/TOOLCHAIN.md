# Windows toolchain manifest

Observed 2026-08-16 17:02-17:12 KST on the implementation host.

| Item | Observed value |
|---|---|
| OS | Windows 11 Home x64, 10.0.26200 build 26200 |
| Git | 2.55.0.windows.3 (`Git.Git` 2.55.0.3) |
| rustup | 1.29.0 |
| repository toolchain | Rust 1.95.0, pinned by `rust-toolchain.toml` |
| installed stable | rustc/cargo 1.97.1 |
| host target | `x86_64-pc-windows-msvc` |
| rustfmt | available for stable and the pinned toolchain |
| clippy | available for stable and the pinned toolchain |
| Visual Studio | Build Tools 2022 17.14.37 |
| MSVC | 19.44.35228 x64, toolset 14.44.35207 |
| linker | 14.44.35228.0 x64 |
| Windows SDK | 10.0.26100.0 |
| winget | 1.29.290 |
| KakaoTalk | executable file version 26.7.0.5255 |

KakaoTalk information was obtained only from the running process and executable
file metadata. No KakaoTalk data directory or database was accessed.

Package IDs were checked immediately before installation:

- `Git.Git`
- `Rustlang.Rustup`
- `Microsoft.VisualStudio.2022.BuildTools`

The Visual Studio installation included
`Microsoft.VisualStudio.Workload.VCTools` and its recommended Windows SDK.
Builds use per-worktree `CARGO_TARGET_DIR` values below ignored `.target/`
directories. At most two Rust builds may run concurrently on this host.
