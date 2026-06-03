from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_release_note_check.cli import analyze, audit_proof_packet, main, parse_changed_files, report_to_json


SAMPLE_DIFF = """diff --git a/src/auth/session.py b/src/auth/session.py
index 1111111..2222222 100644
--- a/src/auth/session.py
+++ b/src/auth/session.py
@@ -1,4 +1,7 @@
 def refresh_session(token):
-    return token
+    if token.is_expired:
+        raise ValueError("expired token")
+    return token.rotate()
diff --git a/requirements.txt b/requirements.txt
index 1111111..2222222 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-requests==2.31.0
+requests==2.32.0
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 1111111..2222222 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1,2 @@
 name: CI
+run: make smoke
diff --git a/tests/test_session.py b/tests/test_session.py
index 1111111..2222222 100644
--- a/tests/test_session.py
+++ b/tests/test_session.py
@@ -1 +1,2 @@
 def test_refresh_session():
+    assert True
"""


SAMPLE_CHANGED_FILES = ["src/auth/session.py", "requirements.txt", ".github/workflows/ci.yml", "tests/test_session.py"]


GOOD_NOTES = """# v0.4.0

## Changed
- Updated authenticated session refresh in `src/auth/session.py`.
- Updated dependency lock input in `requirements.txt`.
- Updated CI workflow automation.
- Added tests and verification coverage.

## Security
- Expired tokens are rejected before reuse.

## Verification
- `make test`
- GitHub Actions CI

## Compatibility
- No public API migration is required.
"""


class ReleaseNoteCheckTests(unittest.TestCase):
    def run_main(self, args: list[str]) -> int:
        with redirect_stdout(StringIO()):
            return main(args)

    def run_main_output(self, args: list[str]) -> tuple[int, str]:
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = main(args)
        return code, stdout.getvalue()

    def write_proof_packet(
        self,
        root: Path,
        *,
        changed_files: list[str] | None = None,
        verdict: str = "complete",
        checks: list[dict[str, str]] | None = None,
        missing_evidence: list[str] | None = None,
    ) -> Path:
        payload = {
            "schema_version": "agent-proof-packet.v1",
            "title": "Release verification evidence",
            "verdict": verdict,
            "changed_files": [{"path": path} for path in (changed_files or SAMPLE_CHANGED_FILES)],
            "checks": checks or [{"name": "make test", "status": "pass", "detail": "unit suite passed"}],
            "missing_evidence": missing_evidence or [],
            "open_questions": [],
        }
        path = root / "proof-packet.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_parse_changed_files(self) -> None:
        files = parse_changed_files(SAMPLE_DIFF)

        self.assertEqual([file.path for file in files], SAMPLE_CHANGED_FILES)
        self.assertIn("security", files[0].tags)
        self.assertIn("dependency", files[1].tags)
        self.assertIn("operations", files[2].tags)
        self.assertIn("tests", files[3].tags)

    def test_good_notes_pass(self) -> None:
        report = analyze(GOOD_NOTES, SAMPLE_DIFF)

        self.assertEqual(report.status, "pass")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.findings, [])

    def test_security_change_without_security_note_blocks(self) -> None:
        notes = "# v0.4.0\n\nUpdated session refresh implementation and dependencies. Verification: make test."
        report = analyze(notes, SAMPLE_DIFF)

        self.assertTrue(any(finding.rule == "security-change-not-covered" for finding in report.findings))
        self.assertEqual(report.status, "blocked")

    def test_dependency_change_without_dependency_note_warns(self) -> None:
        notes = "# v0.4.0\n\nSecurity auth update for session refresh. CI workflow updated. Tests verified with make test."
        report = analyze(notes, SAMPLE_DIFF)

        self.assertTrue(any(finding.rule == "dependency-change-not-covered" for finding in report.findings))

    def test_docs_only_claim_is_contradicted_by_code(self) -> None:
        report = analyze("# v0.4.0\n\nDocs only. No code changes.", SAMPLE_DIFF)

        self.assertTrue(any(finding.rule == "docs-only-claim-contradicted" for finding in report.findings))

    def test_breaking_signal_requires_coverage(self) -> None:
        diff = """diff --git a/src/api.py b/src/api.py
deleted file mode 100644
--- a/src/api.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def public_api():
-    return True
"""
        report = analyze("# v1.0.0\n\nUpdated implementation.", diff)

        self.assertTrue(any(finding.rule == "breaking-change-not-covered" for finding in report.findings))

    def test_test_claim_without_named_evidence_warns(self) -> None:
        notes = "# v0.4.0\n\nSecurity auth dependency workflow test update. Fully tested."
        report = analyze(notes, SAMPLE_DIFF)

        self.assertTrue(any(finding.rule == "test-claim-without-evidence" for finding in report.findings))

    def test_proof_packet_supplies_test_claim_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes = "# v0.4.0\n\nSecurity auth dependency workflow test update. Fully tested."
            proof = audit_proof_packet(self.write_proof_packet(root), SAMPLE_CHANGED_FILES)
            report = analyze(notes, SAMPLE_DIFF, [proof])

        self.assertFalse(any(finding.rule == "test-claim-without-evidence" for finding in report.findings))
        self.assertEqual(report.proof_packets[0].status, "pass")
        self.assertIn("proof-packet", report.coverage_terms)

    def test_incomplete_proof_packet_fails_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes_path = root / "notes.md"
            diff_path = root / "change.diff"
            notes_path.write_text(GOOD_NOTES, encoding="utf-8")
            diff_path.write_text(SAMPLE_DIFF, encoding="utf-8")
            proof_path = self.write_proof_packet(root, verdict="incomplete", missing_evidence=["CI run URL"])

            code, output = self.run_main_output([str(notes_path), "--diff", str(diff_path), "--proof-packet", str(proof_path), "--format", "json"])

        payload = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(payload["proof_packets"][0]["status"], "fail")
        self.assertTrue(any(finding["rule"] == "proof-packet-incomplete" for finding in payload["findings"]))

    def test_proof_packet_must_match_diff_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes_path = root / "notes.md"
            diff_path = root / "change.diff"
            notes_path.write_text(GOOD_NOTES, encoding="utf-8")
            diff_path.write_text(SAMPLE_DIFF, encoding="utf-8")
            proof_path = self.write_proof_packet(root, changed_files=["src/auth/session.py"])

            code, output = self.run_main_output([str(notes_path), "--diff", str(diff_path), "--proof-packet", str(proof_path), "--format", "json"])

        payload = json.loads(output)
        self.assertEqual(code, 1)
        self.assertTrue(any(issue["code"] == "proof-packet-diff-mismatch" for issue in payload["proof_packets"][0]["issues"]))

    def test_cli_json_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes_path = root / "notes.md"
            diff_path = root / "change.diff"
            notes_path.write_text(GOOD_NOTES, encoding="utf-8")
            diff_path.write_text(SAMPLE_DIFF, encoding="utf-8")

            self.assertEqual(self.run_main([str(notes_path), "--diff", str(diff_path), "--format", "json", "--min-score", "100"]), 0)

    def test_cli_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes_path = root / "notes.md"
            diff_path = root / "change.diff"
            report_path = root / "report.md"
            notes_path.write_text(GOOD_NOTES, encoding="utf-8")
            diff_path.write_text(SAMPLE_DIFF, encoding="utf-8")

            self.assertEqual(self.run_main([str(notes_path), "--diff", str(diff_path), "--write-report", str(report_path)]), 0)
            self.assertIn("Agent Release Note Check", report_path.read_text(encoding="utf-8"))

    def test_json_output_shape(self) -> None:
        report = analyze(GOOD_NOTES, SAMPLE_DIFF)
        payload = json.loads(report_to_json(report))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["changed_file_count"], 4)
        self.assertEqual(payload["proof_packets"], [])


if __name__ == "__main__":
    unittest.main()
