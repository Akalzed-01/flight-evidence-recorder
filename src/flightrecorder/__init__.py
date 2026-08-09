"""Local-first operational flight recorder for developer workflows."""

from .capsule import build_replay_plan, canonical_json_bytes, inspect_capsule, verify_replay
from .model import CaptureConfig, CaptureResult, ExecutionPolicy
from .runner import capture

__all__ = [
    "CaptureConfig",
    "CaptureResult",
    "ExecutionPolicy",
    "build_replay_plan",
    "canonical_json_bytes",
    "capture",
    "inspect_capsule",
    "verify_replay",
]

__version__ = "0.1.0"
