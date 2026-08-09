# Known v1 limitations

- The captured process has the user's normal permissions and can change files, use the network, access services, and modify data.
- Capture creates a process group and attempts to terminate descendants at the limits, but operating-system differences may leave a descendant running.
- PTY support and interactive stdin are outside the contract.
- Redaction does not guarantee that no secret exists outside the artifacts that were scanned.
- Read-only Git is not isolation and does not automatically observe every effect outside the repository.
- Git snapshots have output and time limits; when exceeded, the capsule is marked incomplete.
- Imported capsules have manifest, event, blob, and stream limits; oversized files are rejected.
- `verified` means only `self-consistent/untrusted`.
- `replay --plan` does not replay; `replay --verify` does not execute.
- Windows, macOS, Linux, shells, and tools may produce different behavior.
- The loopback server uses a temporary token, must not be exposed to the network, and does not protect against malicious local clients that obtain the URL.

For destructive commands, use a disposable repository, container, virtual machine, or external sandbox.
