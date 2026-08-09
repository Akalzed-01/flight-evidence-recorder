import os
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flightrecorder.capsule import (  # noqa: E402
    build_replay_plan,
    canonical_json_bytes,
    inspect_capsule,
    verify_replay,
)
from flightrecorder.model import CaptureConfig, ExecutionPolicy  # noqa: E402
from flightrecorder.runner import capture  # noqa: E402
from flightrecorder.server import render_report_html  # noqa: E402


class FlightRecorderTests(unittest.TestCase):
    def policy(self, *env_names: str) -> ExecutionPolicy:
        return ExecutionPolicy(
            executable_allowlist=(str(Path(sys.executable).resolve()),),
            env_allowlist=env_names,
            max_duration_s=10.0,
            max_output_bytes_per_stream=1024 * 1024,
        )

    def capture_code(
        self,
        code: str,
        policy: ExecutionPolicy | None = None,
        extra_args: tuple[str, ...] = (),
    ):
        temp_dir = tempfile.TemporaryDirectory()
        capsule_dir = Path(temp_dir.name) / "capsule"
        result = capture(
            [sys.executable, "-c", code, *extra_args],
            config=CaptureConfig(
                capsule_dir=capsule_dir,
                cwd=Path(temp_dir.name),
                policy=policy or self.policy(),
            ),
        )
        return temp_dir, capsule_dir, result

    def test_capture_preserves_nonzero_attempt_and_inspect_reports_it(self):
        temp_dir, capsule_dir, result = self.capture_code(
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(2)"
        )
        self.addCleanup(temp_dir.cleanup)

        self.assertEqual(result.status, "complete")
        self.assertEqual(result.child_returncode, 2)

        report = inspect_capsule(capsule_dir)
        self.assertEqual(report["read_state"], "valid-complete")
        self.assertEqual(report["process"]["returncode"], 2)
        self.assertIn("out", report["streams"]["stdout"])
        self.assertIn("err", report["streams"]["stderr"])

        plan = build_replay_plan(capsule_dir)
        self.assertEqual(plan["state"], "eligible")
        self.assertFalse(plan["executed"])
        verification = verify_replay(plan)
        self.assertEqual(verification["state"], "verified")
        self.assertFalse(verification["executed"])

    def test_redaction_removes_known_environment_value_before_persistence(self):
        secret = "flight-recorder-test-secret-123"
        code = "import os; print(os.environ['FLIGHT_TEST_SECRET'])"
        with mock.patch.dict(os.environ, {"FLIGHT_TEST_SECRET": secret}):
            temp_dir, capsule_dir, result = self.capture_code(
                code, self.policy("FLIGHT_TEST_SECRET")
            )
        self.addCleanup(temp_dir.cleanup)

        self.assertEqual(result.status, "complete")
        report = inspect_capsule(capsule_dir)
        self.assertNotIn(secret, report["streams"]["stdout"])
        self.assertIn("[REDACTED]", report["streams"]["stdout"])
        for path in capsule_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(secret.encode(), path.read_bytes())

    def test_capture_is_denied_without_explicit_executable_allowlist(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        capsule_dir = Path(temp_dir.name) / "capsule"
        result = capture(
            [sys.executable, "-c", "print('must not run')"],
            config=CaptureConfig(
                capsule_dir=capsule_dir,
                cwd=Path(temp_dir.name),
                policy=ExecutionPolicy(),
            ),
        )
        self.assertEqual(result.status, "denied")
        self.assertFalse(capsule_dir.exists())

    def test_capture_rejects_name_only_executable_allowlist(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        capsule_dir = Path(temp_dir.name) / "capsule"
        result = capture(
            [sys.executable, "-c", "print('must not run')"],
            config=CaptureConfig(
                capsule_dir=capsule_dir,
                cwd=Path(temp_dir.name),
                policy=ExecutionPolicy(executable_allowlist=(Path(sys.executable).name,)),
            ),
        )
        self.assertEqual(result.status, "denied")
        self.assertFalse(capsule_dir.exists())

    def test_execution_policy_rejects_relative_git_executable(self):
        with self.assertRaises(ValueError):
            ExecutionPolicy(git_executable="git")

    def test_capture_redacts_sensitive_cli_value_before_persistence(self):
        secret = "flight-recorder-cli-secret-456"
        temp_dir, capsule_dir, result = self.capture_code(
            "import sys; print(sys.argv)",
            extra_args=("--password", secret),
        )
        self.addCleanup(temp_dir.cleanup)
        self.assertEqual(result.status, "complete")

        report = inspect_capsule(capsule_dir)
        all_text = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(secret, all_text)

    def test_reader_rejects_manifest_with_invalid_process_shape(self):
        temp_dir, capsule_dir, result = self.capture_code("print('captured')")
        self.addCleanup(temp_dir.cleanup)
        self.assertEqual(result.status, "complete")

        manifest_path = capsule_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["process"] = []
        manifest.pop("manifest_hash", None)
        manifest["manifest_hash"] = hashlib.sha256(
            canonical_json_bytes(manifest)
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")

        report = inspect_capsule(capsule_dir)
        self.assertEqual(report["read_state"], "invalid")

    def test_verify_does_not_spawn_processes(self):
        temp_dir, capsule_dir, _ = self.capture_code("print('captured')")
        self.addCleanup(temp_dir.cleanup)
        plan = build_replay_plan(capsule_dir)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("spawned")):
            verification = verify_replay(plan)
        self.assertEqual(verification["state"], "verified")

    def test_reader_rejects_tampered_blob(self):
        temp_dir, capsule_dir, _ = self.capture_code("print('captured')")
        self.addCleanup(temp_dir.cleanup)
        blob = next(path for path in (capsule_dir / "blobs").rglob("*") if path.is_file())
        blob.write_bytes(blob.read_bytes() + b"tampered")
        report = inspect_capsule(capsule_dir)
        self.assertEqual(report["read_state"], "invalid")

    def test_canonical_json_is_stable_and_strict(self):
        self.assertEqual(
            canonical_json_bytes({"b": 2, "a": "c"}),
            b'{"a":"c","b":2}',
        )
        with self.assertRaises(ValueError):
            canonical_json_bytes({"bad": float("nan")})

    def test_demo_escapes_untrusted_stream_content(self):
        html = render_report_html(
            {
                "read_state": "valid-complete",
                "replay_state": "eligible",
                "process": {"returncode": 0, "duration_s": 0.1},
                "streams": {"stdout": "<script>alert(1)</script>", "stderr": ""},
                "git": {"before": None, "after": None, "diff": ""},
                "redactions": 0,
                "events": [],
                "warnings": [],
            }
        )
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)


if __name__ == "__main__":
    unittest.main()
