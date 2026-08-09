import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ZERO_HASH = "0" * 64
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EVENTS_BYTES = 32 * 1024 * 1024
MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 256 * 1024 * 1024
MAX_REPORT_STREAM_BYTES = 128 * 1024 * 1024


class CapsuleError(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cannot canonicalize JSON: {exc}") from exc


def _strict_load(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise CapsuleError(f"invalid canonical JSON: {exc}") from exc


def event_hash(previous_hash: str, event_without_hash: dict[str, Any]) -> str:
    payload = previous_hash.encode("ascii") + canonical_json_bytes(event_without_hash)
    return hashlib.sha256(payload).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find_blob_refs(value: Any):
    if isinstance(value, dict):
        if value.get("algorithm") == "sha256" and isinstance(value.get("hash"), str):
            yield value
        for child in value.values():
            yield from _find_blob_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _find_blob_refs(child)


def _blob_path(root: Path, digest: str) -> Path:
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise CapsuleError("invalid blob digest")
    candidate = root / "blobs" / "sha256" / digest[:2] / digest[2:]
    try:
        if not candidate.resolve(strict=False).is_relative_to(root.resolve(strict=False)):
            raise CapsuleError("blob path escapes capsule")
    except OSError as exc:
        raise CapsuleError("cannot resolve blob path") from exc
    return candidate


def _read_file_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        if path.stat().st_size > limit:
            raise CapsuleError(f"{label} exceeds safety limit")
        return path.read_bytes()
    except OSError as exc:
        raise CapsuleError(f"cannot read {label}") from exc


def _validate_manifest_shape(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest.get("process"), dict):
        raise CapsuleError("manifest process must be an object")
    if not isinstance(manifest.get("git"), dict):
        raise CapsuleError("manifest git must be an object")
    process = manifest["process"]
    argv = process.get("argv")
    if argv is not None and (
        not isinstance(argv, list) or any(not isinstance(item, str) for item in argv)
    ):
        raise CapsuleError("manifest process argv must be a string list")
    for key in ("warnings", "limitations"):
        value = manifest.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise CapsuleError(f"manifest {key} must be a string list")


class CapsuleWriter:
    def __init__(self, path: Path, manifest: dict[str, Any]) -> None:
        if path.exists():
            raise FileExistsError(f"capsule already exists: {path}")
        path.mkdir(parents=True)
        (path / "blobs" / "sha256").mkdir(parents=True)
        self.path = path
        self.manifest = manifest
        self.events_path = path / "events.jsonl"
        self._event_count = 0
        self._previous_hash = ZERO_HASH
        self._started = time.monotonic()
        self._blob_count = 0
        self._write_manifest()

    def _write_manifest(self) -> None:
        payload = dict(self.manifest)
        payload.pop("manifest_hash", None)
        payload["manifest_hash"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        temp = self.path / f".manifest-{uuid.uuid4().hex}.tmp"
        temp.write_bytes(canonical_json_bytes(payload) + b"\n")
        os.replace(temp, self.path / "manifest.json")
        self.manifest = payload

    def put_blob(self, data: bytes, media_type: str = "application/octet-stream") -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        target = _blob_path(self.path, digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != data:
                raise CapsuleError("blob digest collision or corrupted existing blob")
        else:
            temp = target.with_name(f".{target.name}-{uuid.uuid4().hex}.tmp")
            temp.write_bytes(data)
            os.replace(temp, target)
        self._blob_count += 1
        return {
            "algorithm": "sha256",
            "hash": digest,
            "size": len(data),
            "media_type": media_type,
        }

    def append(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        event_without_hash = {
            "seq": self._event_count + 1,
            "t_ns": int((time.monotonic() - self._started) * 1_000_000_000),
            "type": event_type,
            "data": data,
            "prev_hash": self._previous_hash,
        }
        complete = dict(event_without_hash)
        complete["hash"] = event_hash(self._previous_hash, event_without_hash)
        with self.events_path.open("ab") as handle:
            handle.write(canonical_json_bytes(complete) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._event_count += 1
        self._previous_hash = complete["hash"]
        return complete

    def finalize(self, status: str, **updates: Any) -> None:
        self.manifest.update(updates)
        self.manifest.update(
            {
                "status": status,
                "finished_at": _now(),
                "integrity": {
                    "event_count": self._event_count,
                    "event_chain_head": self._previous_hash,
                    "blob_count": self._blob_count,
                },
            }
        )
        self._write_manifest()


class CapsuleReader:
    def __init__(self, path: Path) -> None:
        self.path = path
        if not path.is_dir():
            raise CapsuleError("capsule directory does not exist")
        self.manifest = _strict_load(
            _read_file_bounded(path / "manifest.json", MAX_MANIFEST_BYTES, "manifest")
        )
        if not isinstance(self.manifest, dict) or self.manifest.get("schema_version") != 1:
            raise CapsuleError("unsupported capsule schema")
        _validate_manifest_shape(self.manifest)
        expected_manifest_hash = self.manifest.get("manifest_hash")
        without_hash = dict(self.manifest)
        without_hash.pop("manifest_hash", None)
        actual_manifest_hash = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
        if expected_manifest_hash != actual_manifest_hash:
            raise CapsuleError("manifest hash mismatch")

        self.events: list[dict[str, Any]] = []
        events_path = path / "events.jsonl"
        if not events_path.is_file():
            raise CapsuleError("events.jsonl is missing")
        previous_hash = ZERO_HASH
        expected_seq = 1
        events_raw = _read_file_bounded(events_path, MAX_EVENTS_BYTES, "events")
        for line in events_raw.splitlines():
            event = _strict_load(line)
            if not isinstance(event, dict):
                raise CapsuleError("event is not an object")
            if not isinstance(event.get("type"), str) or not isinstance(event.get("data"), dict):
                raise CapsuleError("event type or data has invalid shape")
            if event.get("seq") != expected_seq or event.get("prev_hash") != previous_hash:
                raise CapsuleError("event sequence or chain mismatch")
            supplied_hash = event.get("hash")
            without_hash_event = dict(event)
            without_hash_event.pop("hash", None)
            if supplied_hash != event_hash(previous_hash, without_hash_event):
                raise CapsuleError("event hash mismatch")
            self.events.append(event)
            previous_hash = supplied_hash
            expected_seq += 1

        integrity = self.manifest.get("integrity", {})
        if integrity.get("event_count") != len(self.events):
            raise CapsuleError("manifest event count mismatch")
        if integrity.get("event_chain_head") != previous_hash:
            raise CapsuleError("manifest event chain head mismatch")

        total_blob_bytes = 0
        verified_blobs: set[str] = set()
        for reference in _find_blob_refs({"manifest": self.manifest, "events": self.events}):
            path_for_blob = _blob_path(self.path, reference["hash"])
            if not path_for_blob.is_file():
                raise CapsuleError("referenced blob is missing")
            size = reference.get("size")
            if type(size) is not int or size < 0 or size > MAX_BLOB_BYTES:
                raise CapsuleError("blob exceeds safety limit or has invalid size")
            if path_for_blob.stat().st_size != size:
                raise CapsuleError("blob size mismatch")
            if reference["hash"] in verified_blobs:
                continue
            data = _read_file_bounded(path_for_blob, MAX_BLOB_BYTES, "blob")
            total_blob_bytes += len(data)
            if total_blob_bytes > MAX_TOTAL_BLOB_BYTES:
                raise CapsuleError("capsule blobs exceed safety limit")
            if hashlib.sha256(data).hexdigest() != reference["hash"]:
                raise CapsuleError("blob hash or size mismatch")
            verified_blobs.add(reference["hash"])

        status = self.manifest.get("status")
        if status not in {"complete", "incomplete"}:
            raise CapsuleError("invalid capsule status")
        self.read_state = f"valid-{status}"

    def read_blob(self, reference: dict[str, Any]) -> bytes:
        digest = reference.get("hash")
        size = reference.get("size")
        if not isinstance(digest, str) or type(size) is not int or size < 0 or size > MAX_BLOB_BYTES:
            raise CapsuleError("invalid blob reference")
        path = _blob_path(self.path, digest)
        if not path.is_file() or path.stat().st_size != size:
            raise CapsuleError("blob is missing or has invalid size")
        data = _read_file_bounded(path, MAX_BLOB_BYTES, "blob")
        if hashlib.sha256(data).hexdigest() != digest:
            raise CapsuleError("blob hash mismatch")
        return data

    def report(self) -> dict[str, Any]:
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        compact_events: list[dict[str, Any]] = []
        for event in self.events:
            data = event.get("data", {})
            compact_events.append(
                {"seq": event["seq"], "t_ns": event["t_ns"], "type": event["type"], "data": data}
            )
            if event.get("type") == "stream.chunk":
                stream = data.get("stream")
                if stream in streams and isinstance(data.get("blob"), dict):
                    blob = self.read_blob(data["blob"])
                    if len(streams[stream]) + len(blob) > MAX_REPORT_STREAM_BYTES:
                        raise CapsuleError("reported stream exceeds safety limit")
                    streams[stream].extend(blob)

        process = self.manifest.get("process", {})
        git = self.manifest.get("git", {})
        replay_state = "eligible" if self.read_state == "valid-complete" and process.get("argv") else "blocked"
        return {
            "read_state": self.read_state,
            "replay_state": replay_state,
            "integrity": "self-consistent/untrusted",
            "process": process,
            "streams": {key: value.decode("utf-8", "replace") for key, value in streams.items()},
            "git": git,
            "redactions": self.manifest.get("redactions", 0),
            "events": compact_events,
            "warnings": self.manifest.get("warnings", []),
            "limitations": self.manifest.get("limitations", []),
        }


def inspect_capsule(path: Path) -> dict[str, Any]:
    try:
        return CapsuleReader(path).report()
    except (OSError, CapsuleError, ValueError, RecursionError) as exc:
        return {
            "read_state": "invalid",
            "replay_state": "blocked",
            "integrity": "invalid",
            "error": str(exc),
            "events": [],
            "streams": {"stdout": "", "stderr": ""},
            "warnings": [],
        }


def build_replay_plan(path: Path) -> dict[str, Any]:
    report = inspect_capsule(path)
    process = report.get("process", {})
    eligible = report.get("read_state") == "valid-complete" and bool(process.get("argv"))
    return {
        "state": "eligible" if eligible else "blocked",
        "executed": False,
        "execution": "not-started",
        "process_spawn": "disabled",
        "mutation": "disabled",
        "capsule_read_state": report.get("read_state"),
        "integrity": report.get("integrity"),
        "argv": process.get("argv", []),
        "cwd": process.get("cwd"),
        "shell": False,
        "stdin": "DEVNULL",
        "environment": "minimal",
        "recorded_returncode": process.get("returncode"),
        "blockers": [] if eligible else [report.get("error", "capsule is incomplete or invalid")],
        "note": "plan describes the captured attempt; it never executes it",
    }


def verify_replay(plan: dict[str, Any]) -> dict[str, Any]:
    if plan.get("state") != "eligible":
        return {
            "state": "blocked",
            "executed": False,
            "execution": "not-started",
            "reason": "plan is not eligible",
            "blockers": plan.get("blockers", []),
        }
    return {
        "state": "verified",
        "executed": False,
        "execution": "not-started",
        "process_spawn": "disabled",
        "integrity": "self-consistent/untrusted",
        "result": "recorded evidence is internally consistent; origin is not authenticated",
    }
