from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class ExecutionPolicy:
    """Conservative policy for the one process captured by the MVP."""

    executable_allowlist: tuple[str, ...] = ()
    env_allowlist: tuple[str, ...] = ()
    max_duration_s: float = 300.0
    max_output_bytes_per_stream: int = 64 * 1024 * 1024
    max_git_blob_bytes: int = 16 * 1024 * 1024
    max_git_duration_s: float = 15.0
    git_executable: str | None = None

    def __post_init__(self) -> None:
        if self.max_duration_s <= 0 or self.max_git_duration_s <= 0:
            raise ValueError("process time limits must be positive")
        if self.max_output_bytes_per_stream <= 0 or self.max_git_blob_bytes <= 0:
            raise ValueError("output limits must be positive")
        if self.git_executable is not None and not Path(self.git_executable).is_absolute():
            raise ValueError("git_executable must be an absolute path")


@dataclass(frozen=True)
class CaptureConfig:
    capsule_dir: Path
    cwd: Path | None = None
    policy: ExecutionPolicy = ExecutionPolicy()
    git_snapshot: bool = True


@dataclass(frozen=True)
class CaptureResult:
    capsule_dir: Path
    status: Literal["complete", "incomplete", "denied"]
    child_returncode: int | None = None
    reason: str | None = None
