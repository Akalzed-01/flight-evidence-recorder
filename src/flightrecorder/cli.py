import argparse
import json
import secrets
from pathlib import Path
from typing import Sequence

from .capsule import build_replay_plan, inspect_capsule, verify_replay
from .model import CaptureConfig, ExecutionPolicy
from .runner import capture
from .server import serve_capsule


def _dump(value: dict, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
        return
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            print(f"{key}: {json.dumps(item, ensure_ascii=False, sort_keys=True)}")
        else:
            print(f"{key}: {item}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flightrecorder",
        description="Preserve a developer attempt as a local, inspectable evidence capsule.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture", help="record one explicitly authorized process")
    capture_parser.add_argument("--capsule", "--out", dest="capsule", required=True, type=Path)
    capture_parser.add_argument("--cwd", type=Path, default=Path.cwd())
    capture_parser.add_argument(
        "--allow-executable",
        action="append",
        required=True,
        help="absolute executable path; basename-only allowlists are rejected",
    )
    capture_parser.add_argument("--env", action="append", default=[])
    capture_parser.add_argument("program_args", nargs=argparse.REMAINDER)

    inspect_parser = subparsers.add_parser("inspect", help="validate and summarize a capsule")
    inspect_parser.add_argument("capsule", type=Path)
    inspect_parser.add_argument("--json", action="store_true")

    serve_parser = subparsers.add_parser("serve", help="serve one capsule on loopback")
    serve_parser.add_argument("capsule", type=Path)
    serve_parser.add_argument("--host", choices=["127.0.0.1"], default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=0)

    replay_parser = subparsers.add_parser("replay", help="describe or verify without executing")
    replay_parser.add_argument("capsule", type=Path)
    modes = replay_parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--verify", action="store_true")
    replay_parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "capture":
        if args.program_args and args.program_args[0] == "--":
            args.program_args = args.program_args[1:]
        if not args.program_args:
            print("error: capture requires PROGRAM after --")
            return 2
        result = capture(
            args.program_args,
            config=CaptureConfig(
                capsule_dir=args.capsule,
                cwd=args.cwd,
                policy=ExecutionPolicy(
                    executable_allowlist=tuple(args.allow_executable),
                    env_allowlist=tuple(args.env),
                ),
            ),
        )
        payload = {
            "capture": result.status,
            "capsule": str(result.capsule_dir),
            "process_exit_code": result.child_returncode,
            "execution": "started-once" if result.status == "complete" else "not-started",
            "reason": result.reason,
            "next": [
                f"flightrecorder inspect {result.capsule_dir}",
                f"flightrecorder replay {result.capsule_dir} --plan",
                f"flightrecorder replay {result.capsule_dir} --verify",
            ],
        }
        _dump(payload)
        return 0 if result.status == "complete" else 3

    if args.command == "inspect":
        report = inspect_capsule(args.capsule)
        _dump(report, args.json)
        return 0 if report.get("read_state") != "invalid" else 4

    if args.command == "replay":
        plan = build_replay_plan(args.capsule)
        payload = verify_replay(plan) if args.verify else plan
        _dump(payload, args.json)
        if payload.get("state") == "verified" or payload.get("state") == "eligible":
            return 0
        return 4 if plan.get("capsule_read_state") == "invalid" else 3

    if args.command == "serve":
        report = inspect_capsule(args.capsule)
        if report.get("read_state") == "invalid":
            _dump(report)
            return 4

        access_token = secrets.token_urlsafe(32)

        def ready(address: tuple[str, int]) -> None:
            print(f"serve: listening on http://{address[0]}:{address[1]}/{access_token}/")
            print("methods: GET, HEAD")
            print("execution: disabled")

        serve_capsule(
            args.capsule,
            host=args.host,
            port=args.port,
            access_token=access_token,
            on_ready=ready,
        )
        return 0

    return 2
