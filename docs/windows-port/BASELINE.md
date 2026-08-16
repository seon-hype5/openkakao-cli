# Unmodified Windows baseline

Baseline commit: `be6edd442c803de8e4f06bfc4446d166ac474952`

Host/toolchain: see `TOOLCHAIN.md`

Target directory: `.target/baseline`

The commands below ran before source or manifest changes. The generated target
directory was subsequently ignored; no baseline failure was repaired in place.

| Command | Exit | Result |
|---|---:|---|
| `cargo fmt --check` | 0 | passed |
| `cargo test` | 101 | failed while building `libsqlite3-sys` |
| `cargo clippy --all-targets --all-features -- -D warnings` | 101 | same dependency build failure |
| `cargo build` | 101 | same dependency build failure |

The common root cause was the `rusqlite` feature `bundled-sqlcipher` being
enabled globally. On Windows, `libsqlite3-sys 0.31.0` stopped in its build
script because `OPENSSL_DIR` was absent. No project Rust source compiled far
enough to expose a second baseline error.

This is an upstream target-configuration issue, not evidence that OpenSSL
should be installed for the Windows UI MVP. The contract change instead keeps
SQLCipher on macOS and selects bundled plain SQLite on non-macOS targets.

Current upstream CI provides Linux test/lint and macOS release-build evidence,
but it does not run Windows. macOS regression remains a CI requirement because
this Windows host cannot execute the AX implementation.
