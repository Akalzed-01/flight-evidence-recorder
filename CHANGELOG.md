# Changelog

## 0.1.0 — 2026-08-08

First public release.

- Explicit capture of one process by absolute path.
- Minimal environment, `shell=False`, closed stdin, and process-group termination.
- Redaction of sensitive arguments, environment values, and streams.
- JSONL capsules with hashes, strict validation, and read limits.
- Read-only Git observation with time and size limits.
- `inspect`, `replay --plan`, `replay --verify`, and a loopback server with a token.
- Tests, CI, security documentation, and a contribution policy.
