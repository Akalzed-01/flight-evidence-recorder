import os
from pathlib import Path
from typing import Any

from .processutil import BoundedProcessResult, run_bounded


def _git_environment() -> dict[str, str]:
    env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_EDITOR": "true",
        "GIT_EXTERNAL_DIFF": "false",
        "PATH": os.environ.get("PATH", ""),
    }
    return env


def _find_git(explicit: str | None = None) -> str | None:
    candidates = [explicit] if explicit else []
    candidates.extend(
        [
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files\Git\bin\git.exe",
            r"C:\Program Files (x86)\Git\cmd\git.exe",
            "/usr/bin/git",
            "/usr/local/bin/git",
            "/opt/homebrew/bin/git",
        ]
    )
    for value in candidates:
        if not value:
            continue
        try:
            candidate = Path(value).resolve(strict=True)
        except OSError:
            continue
        if candidate.is_file():
            return str(candidate)
    return None


def _run_git(
    cwd: Path,
    args: list[str],
    *,
    max_output_bytes: int,
    timeout_s: float,
    git_executable: str | None,
) -> BoundedProcessResult | None:
    executable = _find_git(git_executable)
    if executable is None:
        return None
    return run_bounded(
        [
            executable,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *args,
        ],
        cwd=cwd,
        env=_git_environment(),
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
    )


def _failure_reason(result: BoundedProcessResult | None) -> str | None:
    if result is None:
        return "git-not-found"
    if result.timed_out:
        return "git-timeout"
    if result.output_truncated:
        return "git-output-limit"
    if result.returncode != 0:
        return "git-command-failed"
    return None


def observe(
    cwd: Path,
    *,
    max_output_bytes: int = 16 * 1024 * 1024,
    timeout_s: float = 15.0,
    git_executable: str | None = None,
) -> dict[str, Any]:
    root_result = _run_git(
        cwd,
        ["rev-parse", "--show-toplevel"],
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
        git_executable=git_executable,
    )
    if root_result is None:
        return {"available": False, "completeness": "unavailable", "reason": "git-not-found"}
    if root_result.returncode != 0:
        return {
            "available": False,
            "completeness": "incomplete" if _failure_reason(root_result) != "git-command-failed" else "unavailable",
            "reason": _failure_reason(root_result) or "not-a-git-repository",
        }

    root = root_result.stdout.decode("utf-8", "replace").strip()
    head_result = _run_git(
        cwd,
        ["rev-parse", "--verify", "HEAD"],
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
        git_executable=git_executable,
    )
    status_result = _run_git(
        cwd,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
        git_executable=git_executable,
    )
    worktree_result = _run_git(
        cwd,
        ["diff", "--no-ext-diff", "--no-textconv", "--binary"],
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
        git_executable=git_executable,
    )
    index_result = _run_git(
        cwd,
        ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary"],
        max_output_bytes=max_output_bytes,
        timeout_s=timeout_s,
        git_executable=git_executable,
    )

    command_results = (head_result, status_result, worktree_result, index_result)
    incomplete_reasons = [
        reason
        for result in command_results
        if (reason := _failure_reason(result)) in {"git-timeout", "git-output-limit", "git-command-failed"}
    ]

    return {
        "available": True,
        "repo_root": root,
        "head": (
            head_result.stdout.decode("ascii", "replace").strip()
            if head_result and head_result.returncode == 0
            else None
        ),
        "status": status_result.stdout if status_result and status_result.returncode == 0 else b"",
        "diff_worktree": (
            worktree_result.stdout
            if worktree_result and worktree_result.returncode == 0
            else b""
        ),
        "diff_index": (
            index_result.stdout if index_result and index_result.returncode == 0 else b""
        ),
        "completeness": "incomplete" if incomplete_reasons else "complete",
        "reason": incomplete_reasons[0] if incomplete_reasons else None,
    }
