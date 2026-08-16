# Artifact privacy policy

> **Applies to automated CI and every L10+ manual. It authorizes no live capture.**

## Default: retain nothing

Live-validation output stays in an ephemeral console and in memory by default.
Do not redirect it to a file. CI uploads no artifacts. A manual gate may retain
a sanitized artifact only when its approval explicitly names the artifact,
purpose, reviewer, storage location, and deletion time.

No screenshot or screen recording is permitted by these manuals, including a
crop that appears synthetic. Raw UI trees, accessibility dumps, event payloads,
crash dumps, memory dumps, command histories, and private console transcripts
are also forbidden.

## Forbidden fields

An artifact, log, cache addition, fixture, issue, or commit must never contain:

- message or draft content;
- real room or profile labels;
- user/chat/account identifiers;
- raw application process or window handles, runtime element identifiers,
  application executable paths, or unredacted live-environment identity;
- credentials, tokens, cookies, session material, keys, nonce material, or
  execution fingerprint secrets; or
- screenshots or any pixels from a live desktop/application.

Synthetic canaries are allowed only in synthetic tests and in memory during a
separately approved gate. They are not a reason to retain a live transcript.

## Allowlisted sanitized records

If explicitly approved, a record may contain only the minimum required subset
of:

- schema version and fixed action/backend/platform/target/outcome codes;
- fixed allowlisted evidence and error codes;
- booleans, bounded counts, relative timings, and retry safety;
- execution-scoped HMAC fingerprints whose secret is discarded at session
  end;
- synthetic fixture identifier and scalar/byte lengths, without content; and
- transaction state (`planned`, `staged`, `commit_issued`, `echo_confirmed`,
  `indeterminate`, or `aborted`) with a redacted nonce fingerprint.

Unknown strings are dropped, not copied and redacted after the fact.

## CI policy

The Windows workflow may cache only Cargo dependency caches and its isolated
compiler target directory. It must not use `upload-artifact`, capture command
output to files, inject repository secrets, run live UI commands, or cache an
arbitrary workspace directory. GitHub job logs must contain only compiler
diagnostics and synthetic test output.

A future artifact-upload step requires a separate privacy RFC, schema-level
allowlist, automated canary-leak test, finite retention, and explicit review.

## Manual review and retention

Before an approved sanitized record leaves the ephemeral session, two checks
are mandatory:

1. schema/field allowlist validation rejects every unknown key and string; and
2. a human reviewer confirms that no forbidden field or unexpected free text
   is present.

Use the shortest approved retention period and a repository-external access-
controlled location. Do not create a raw artifact directory in this repository;
no such directory is authorized by the current ignore policy.

## Incident handling

If forbidden material is produced, stop capture immediately. Do not upload,
paste, quote, rename, or commit it. Record only that an incident occurred, then
ask the user for an exact cleanup target and retention decision. Resume no gate
until the artifact path is understood and the privacy cause is fixed with a
synthetic reproduction.
