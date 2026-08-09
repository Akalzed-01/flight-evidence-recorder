# Flight Evidence Recorder

A local flight recorder for development tasks.

It turns an explicit attempt into an inspectable capsule containing the command, result, `stdout`/`stderr`, Git snapshots, hashes, redactions, and limitations. The goal is to preserve the operational history that is usually scattered across a terminal, a diff, CI, and an agent session.

> Release name: `flight-evidence-recorder`. Confirm name availability on GitHub before creating the remote repository.

## What v1 proves

- `capture` runs one explicitly authorized process by absolute path, with `shell=False`, `stdin=DEVNULL`, a minimal environment, and separate streams.
- `inspect` validates a capsule without starting processes.
- `replay --plan` describes a possible replay but executes nothing.
- `replay --verify` checks internal consistency but does not authenticate the source or promise a future result.
- `serve` displays a capsule locally on loopback, read-only, using a temporary URL token.

There is no `replay --run` in v1.

## Quick demo

```powershell
$env:PYTHONPATH = "src"
python -m flightrecorder --help
python examples/make_demo.py --output .\demo-capsule
python -m flightrecorder inspect .\demo-capsule
python -m flightrecorder replay .\demo-capsule --plan
python -m flightrecorder replay .\demo-capsule --verify
python -m flightrecorder serve .\demo-capsule
```

Capture requires an explicit allowlist. `--` separates recorder options from the target process:

```powershell
$python = (Get-Command python).Source
python -m flightrecorder capture `
  --capsule .\attempt-001 `
  --allow-executable $python `
  -- $python -c "print('hello')"
```

The executable in the allowlist and the executable used as the first argument must be absolute paths resolving to the same file. This prevents a `PATH` change from silently replacing the authorized program.

## Capsule

```text
capsule/
├── manifest.json
├── events.jsonl
└── blobs/sha256/<digest>
```

The format is canonical UTF-8 JSON, with events chained by SHA-256 and blobs hashed after redaction. A hash indicates byte consistency; it does not indicate authorship, authenticity, or absence of tampering at the source.

## Honest states

| State | Meaning |
|---|---|
| `complete` | Recording finished and the capsule was structurally finalized. |
| `incomplete` | A timeout, limit, interruption, or persistence failure occurred. |
| `valid-complete` | Manifest, events, and blobs are internally consistent. |
| `valid-incomplete` | The capsule is readable but does not represent a complete attempt. |
| `invalid` | Corruption, an invalid schema, or a mismatched hash was found. |
| `verified` | Only `self-consistent/untrusted`; no process was executed. |

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
flightrecorder --help
```

```powershell
python -m unittest discover -s tests -v
```

The v1 implementation uses only the Python standard library. The package can also be installed in editable mode with `pip install -e .` when the build infrastructure is available.

## Important limitations

- This is not a sandbox: the captured process keeps the user's normal permissions.
- Git is observed in read-only mode, but this does not prevent the target process from changing files.
- Redaction is best effort; a secret may appear in unknown formats, arguments outside the supported patterns, memory, external logs, or backups.
- Process descendants, networking, timing, randomness, and environment differences prevent universal determinism.
- The local server uses loopback and a temporary URL token, but it is not a boundary against malware or local processes that obtain that token.
- Imported capsules and Git snapshots have size and time limits to reduce resource-exhaustion risk.

Read [docs/limitations.md](docs/limitations.md) and [SECURITY.md](SECURITY.md) before capturing sensitive data.

## License

MIT for the code. Example fixtures must remain synthetic and may have their own licensing requirements.