import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    output_truncated: bool
    timed_out: bool


def process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = os.path.join(system_root, "System32", "taskkill.exe")
        if os.path.isfile(taskkill):
            try:
                subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    check=False,
                    timeout=2,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            process.terminate()
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            process.terminate()

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        process.kill()
        process.wait(timeout=2)


def read_limited(pipe, storage: bytearray, limit: int, overflow: threading.Event) -> None:
    while True:
        chunk = pipe.read(64 * 1024)
        if not chunk:
            return
        remaining = limit - len(storage)
        if remaining > 0:
            storage.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            overflow.set()


def run_bounded(
    args: list[str],
    *,
    cwd,
    env: dict[str, str],
    timeout_s: float,
    max_output_bytes: int,
) -> BoundedProcessResult:
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        **process_group_kwargs(),
    )
    stdout_data = bytearray()
    stderr_data = bytearray()
    overflow = threading.Event()
    stdout_thread = threading.Thread(
        target=read_limited,
        args=(process.stdout, stdout_data, max_output_bytes, overflow),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_limited,
        args=(process.stderr, stderr_data, max_output_bytes, overflow),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    started = time.monotonic()
    while process.poll() is None:
        if overflow.is_set():
            terminate_process(process)
            break
        if time.monotonic() - started > timeout_s:
            timed_out = True
            terminate_process(process)
            break
        time.sleep(0.01)

    returncode = process.wait()
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    return BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(stdout_data),
        stderr=bytes(stderr_data),
        output_truncated=overflow.is_set(),
        timed_out=timed_out,
    )
