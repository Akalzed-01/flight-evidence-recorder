import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Sequence

from .capsule import CapsuleWriter, _now
from .gitobserver import observe
from .model import CaptureConfig, CaptureResult
from .processutil import process_group_kwargs, read_limited, terminate_process
from .redaction import Redactor


def _resolve_allowed(argv0: str, allowlist: tuple[str, ...]) -> str | None:
    candidate = Path(argv0)
    if not allowlist or not candidate.is_absolute():
        return None
    try:
        resolved_path = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved_path.is_file():
        return None
    for allowed in allowlist:
        allowed_path = Path(allowed)
        if not allowed_path.is_absolute():
            continue
        try:
            if resolved_path == allowed_path.resolve(strict=True):
                return str(resolved_path)
        except OSError:
            continue
    return None


def _persist_git(writer: CapsuleWriter, redactor: Redactor, snapshot: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "available": snapshot.get("available", False),
        "repo_root": snapshot.get("repo_root"),
        "head": snapshot.get("head"),
        "completeness": snapshot.get("completeness", "unavailable"),
        "reason": snapshot.get("reason"),
    }
    if result["repo_root"]:
        result["repo_root"] = redactor.redact(str(result["repo_root"])).value.decode(
            "utf-8", "replace"
        )
    for key in ("status", "diff_worktree", "diff_index"):
        raw = snapshot.get(key)
        if isinstance(raw, bytes):
            sanitized = redactor.redact(raw)
            result[key] = writer.put_blob(sanitized.value, "text/plain; charset=utf-8")
    return result


def capture(argv: Sequence[str], *, config: CaptureConfig) -> CaptureResult:
    argv = tuple(argv)
    if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
        return CaptureResult(config.capsule_dir, "denied", reason="argv must contain non-empty strings")
    cwd = (config.cwd or Path.cwd()).resolve()
    if not cwd.is_dir():
        return CaptureResult(config.capsule_dir, "denied", reason="cwd is not a directory")

    executable = _resolve_allowed(argv[0], config.policy.executable_allowlist)
    if executable is None:
        return CaptureResult(config.capsule_dir, "denied", reason="executable is not allowlisted")

    env = {
        name: os.environ[name]
        for name in config.policy.env_allowlist
        if name in os.environ
    }
    redactor = Redactor(tuple(env.values()) + (str(Path.home()),))
    redacted_argv, argv_redactions = redactor.redact_argv(argv)
    manifest = {
        "schema_version": 1,
        "capsule_id": __import__("uuid").uuid4().hex,
        "created_at": _now(),
        "finished_at": None,
        "tool_version": "0.1.0",
        "platform": {"os": sys.platform, "python": sys.version.split()[0]},
        "capture": {
            "primary_process": True,
            "shell": False,
            "stdin": "DEVNULL",
            "environment": "minimal",
            "pty": False,
        },
        "process": {
            "argv": redacted_argv,
            "cwd": redactor.redact(str(cwd)).value.decode("utf-8", "replace"),
            "returncode": None,
            "duration_s": None,
            "timed_out": False,
            "output_truncated": False,
        },
        "git": {"requested": config.git_snapshot},
        "redactions": 0,
        "warnings": [
            "capture runs the target process with its normal user permissions",
            "redaction is best effort and not a secrecy guarantee",
            "Git observation is read-only but is not a sandbox",
        ],
        "limitations": [
            "subprocess descendants are not fully captured",
            "replay is not deterministic across machines",
            "hashes prove internal consistency, not origin authenticity",
        ],
    }

    writer: CapsuleWriter | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        writer = CapsuleWriter(config.capsule_dir, manifest)
        writer.append("capture.started", {"argv": redacted_argv, "cwd": manifest["process"]["cwd"]})
        redactions = argv_redactions

        if config.git_snapshot:
            before = _persist_git(
                writer,
                redactor,
                observe(
                    cwd,
                    max_output_bytes=config.policy.max_git_blob_bytes,
                    timeout_s=config.policy.max_git_duration_s,
                    git_executable=config.policy.git_executable,
                ),
            )
            manifest["git"]["before"] = before
            writer.append("git.snapshot.before", {"snapshot": before})

        start = time.monotonic()
        try:
            process = subprocess.Popen(
                [executable, *argv[1:]],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                **process_group_kwargs(),
            )
        except OSError as exc:
            writer.append("capture.error", {"reason": f"spawn failed: {type(exc).__name__}"})
            writer.finalize("incomplete", reason="spawn failed", redactions=redactions)
            return CaptureResult(config.capsule_dir, "incomplete", reason="spawn failed")

        writer.append("process.spawned", {"argv": redacted_argv, "shell": False})
        stdout_data = bytearray()
        stderr_data = bytearray()
        overflow = threading.Event()
        stdout_thread = threading.Thread(
            target=read_limited,
            args=(process.stdout, stdout_data, config.policy.max_output_bytes_per_stream, overflow),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=read_limited,
            args=(process.stderr, stderr_data, config.policy.max_output_bytes_per_stream, overflow),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        while process.poll() is None:
            if overflow.is_set():
                terminate_process(process)
                break
            if time.monotonic() - start > config.policy.max_duration_s:
                timed_out = True
                terminate_process(process)
                break
            time.sleep(0.02)
        returncode = process.wait()
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        duration = round(time.monotonic() - start, 6)
        stdout_result = redactor.redact(bytes(stdout_data))
        stderr_result = redactor.redact(bytes(stderr_data))
        redactions += stdout_result.count + stderr_result.count
        stdout_ref = writer.put_blob(stdout_result.value, "application/octet-stream")
        stderr_ref = writer.put_blob(stderr_result.value, "application/octet-stream")
        writer.append("stream.chunk", {"stream": "stdout", "blob": stdout_ref})
        writer.append("stream.chunk", {"stream": "stderr", "blob": stderr_ref})
        writer.append(
            "process.exited",
            {
                "returncode": returncode,
                "duration_s": duration,
                "timed_out": timed_out,
                "output_truncated": overflow.is_set(),
            },
        )
        manifest["process"].update(
            {
                "returncode": returncode,
                "duration_s": duration,
                "timed_out": timed_out,
                "output_truncated": overflow.is_set(),
            }
        )

        if config.git_snapshot:
            after = _persist_git(
                writer,
                redactor,
                observe(
                    cwd,
                    max_output_bytes=config.policy.max_git_blob_bytes,
                    timeout_s=config.policy.max_git_duration_s,
                    git_executable=config.policy.git_executable,
                ),
            )
            manifest["git"]["after"] = after
            writer.append("git.snapshot.after", {"snapshot": after})

        manifest["redactions"] = redactions
        incomplete = timed_out or overflow.is_set() or stdout_thread.is_alive() or stderr_thread.is_alive()
        writer.append("capture.incomplete" if incomplete else "capture.finished", {"status": "incomplete" if incomplete else "complete"})
        status = "incomplete" if incomplete else "complete"
        writer.finalize(status, process=manifest["process"], git=manifest["git"], redactions=redactions)
        return CaptureResult(config.capsule_dir, status, returncode, "capture limit reached" if incomplete else None)
    except Exception as exc:
        if writer is not None:
            try:
                writer.append("capture.error", {"reason": type(exc).__name__})
                writer.finalize("incomplete", reason=type(exc).__name__)
            except Exception:
                pass
        return CaptureResult(config.capsule_dir, "incomplete", reason=type(exc).__name__)
