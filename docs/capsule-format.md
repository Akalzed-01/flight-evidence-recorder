# Capsule format v1

A capsule is a local directory:

```text
capsule/
├── manifest.json
├── events.jsonl
└── blobs/sha256/<digest>
```

## Manifest

The manifest records `schema_version: 1`, identity, platform, policy, process, Git, redactions, limits, and the integrity root. It starts as `incomplete` and is finalized only after events, blobs, and snapshots are complete.

## Events

Each line is a canonical UTF-8 JSON object with `seq`, `t_ns`, `type`, `data`, `prev_hash`, and `hash`.

```text
hash = SHA256(prev_hash || canonical_json(event_without_hash))
```

The hash detects accidental or later changes to the bytes; it is not a signature or proof of origin.

## Blobs

`stdout`, `stderr`, and Git snapshots are written after redaction. The path is derived from the SHA-256 of the persisted bytes. The reader rejects references outside `blobs/sha256`.
