import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flightrecorder.model import CaptureConfig, ExecutionPolicy
from flightrecorder.runner import capture


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a synthetic failure capsule.")
    parser.add_argument("--output", type=Path, default=Path("demo-capsule"))
    args = parser.parse_args()
    code = "import sys; print('compile started'); print('missing input', file=sys.stderr); sys.exit(2)"
    result = capture(
        [sys.executable, "-c", code],
        config=CaptureConfig(
            capsule_dir=args.output,
            cwd=Path.cwd(),
            policy=ExecutionPolicy(executable_allowlist=(str(Path(sys.executable).resolve()),)),
        ),
    )
    print(f"demo capsule: {result.status} -> {result.capsule_dir}")
    return 0 if result.status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
