from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 45}

SECURITY_RE = re.compile(r"(auth|token|secret|password|credential|permission|crypto|encrypt|decrypt|session|oauth)", re.I)
DEPENDENCY_RE = re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|package\.json|requirements.*\.txt|pyproject\.toml|poetry\.lock|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock)$", re.I)
CI_RE = re.compile(r"(^|/)(\.github/workflows/|Makefile$|scripts/|\.gitlab-ci\.yml$|Dockerfile$|docker-compose\.ya?ml$)", re.I)
TEST_RE = re.compile(r"(^|/)(tests?/|test_|.*_test\.|.*\.test\.|.*\.spec\.)", re.I)
DOC_RE = re.compile(r"(^|/)(README|CHANGELOG|docs?/|.*\.md$)", re.I)
CODE_RE = re.compile(r"\.(py|js|ts|tsx|jsx|go|rs|java|kt|swift|rb|php|cs|cpp|c|h|hpp)$", re.I)
DELETED_FILE_RE = re.compile(r"^deleted file mode ", re.M)
REMOVED_PUBLIC_RE = re.compile(r"^-\s*(class|def|function|export|public|interface|type)\b", re.M)
VERSION_HEADING_RE = re.compile(r"(^|\n)#{1,3}\s*(v?\d+\.\d+|\d{4}-\d{2}-\d{2}|release|version|changelog)", re.I)
PASS_CHECK_STATUSES = {"pass", "passed", "success", "ok"}
FAIL_CHECK_STATUSES = {"fail", "failed", "failure", "error", "blocked"}


@dataclass(frozen=True)
class ChangedFile:
    path: str
    added: int
    removed: int
    tags: list[str]


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    message: str
    evidence: str


@dataclass(frozen=True)
class ProofPacketIssue:
    severity: str
    code: str
    message: str
    evidence: str


@dataclass(frozen=True)
class ProofPacketSummary:
    path: str
    status: str
    verdict: str
    changed_files: list[str]
    passing_checks: list[str]
    issues: list[ProofPacketIssue]


@dataclass(frozen=True)
class ReleaseReport:
    status: str
    score: int
    changed_file_count: int
    changed_files: list[ChangedFile]
    findings: list[Finding]
    coverage_terms: list[str]
    proof_packets: list[ProofPacketSummary]
    follow_up_checks: list[str]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def redact(text: str, limit: int = 180) -> str:
    redacted = re.sub(r"(?i)(password|secret|token|key)\s*[:=]\s*[^,\s}]+", r"\1=[redacted]", text)
    if len(redacted) > limit:
        return redacted[: limit - 3] + "..."
    return redacted


def parse_changed_files(diff_text: str) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    current_path = ""
    added = 0
    removed = 0

    def flush() -> None:
        nonlocal current_path, added, removed
        if current_path:
            files.append(ChangedFile(current_path, added, removed, tags_for_path(current_path)))
        current_path = ""
        added = 0
        removed = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            parts = line.split()
            if len(parts) >= 4:
                current_path = parts[3][2:] if parts[3].startswith("b/") else parts[3]
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if not current_path:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    flush()
    return files


def clean_diff_path(path: str) -> str:
    cleaned = path.strip()
    if cleaned.startswith(("a/", "b/")):
        return cleaned[2:]
    return cleaned


def tags_for_path(path: str) -> list[str]:
    tags: list[str] = []
    if SECURITY_RE.search(path):
        tags.append("security")
    if DEPENDENCY_RE.search(path):
        tags.append("dependency")
    if CI_RE.search(path):
        tags.append("operations")
    if TEST_RE.search(path):
        tags.append("tests")
    if DOC_RE.search(path):
        tags.append("docs")
    if CODE_RE.search(path):
        tags.append("code")
    return tags


def notes_include(notes: str, terms: Sequence[str]) -> bool:
    lowered = notes.lower()
    return any(term in lowered for term in terms)


def file_covered(path: str, notes: str) -> bool:
    lowered = notes.lower()
    path_lower = path.lower()
    stem = Path(path).stem.lower()
    parent = Path(path).parent.name.lower()
    if path_lower in lowered or (stem and len(stem) > 3 and stem in lowered):
        return True
    if parent and len(parent) > 3 and parent in lowered:
        return True
    return False


def tag_covered(tags: Sequence[str], notes: str) -> bool:
    term_map = {
        "security": ("security", "auth", "permission", "credential", "token", "secret"),
        "dependency": ("dependency", "dependencies", "package", "lockfile", "supply chain", "version range"),
        "operations": ("ci", "workflow", "automation", "script", "docker", "build", "release process"),
        "tests": ("test", "tests", "verification", "checked", "coverage"),
        "docs": ("docs", "documentation", "readme", "changelog"),
        "code": ("code", "implementation", "fix", "feature", "change", "api"),
    }
    return any(notes_include(notes, term_map.get(tag, (tag,))) for tag in tags)


def diff_has_breaking_signal(diff_text: str, files: Sequence[ChangedFile]) -> bool:
    if DELETED_FILE_RE.search(diff_text) or REMOVED_PUBLIC_RE.search(diff_text):
        return True
    risky_files = [file for file in files if "code" in file.tags and file.removed > 20]
    return bool(risky_files)


def proof_issue(severity: str, code: str, message: str, evidence: str) -> ProofPacketIssue:
    return ProofPacketIssue(severity, code, message, redact(evidence))


def proof_packet_summary(path: Path, status: str, issues: list[ProofPacketIssue]) -> ProofPacketSummary:
    return ProofPacketSummary(str(path), status, "", [], [], issues)


def audit_proof_packet(path: Path, diff_paths: Sequence[str]) -> ProofPacketSummary:
    issues: list[ProofPacketIssue] = []
    packet_files: list[str] = []
    passing_checks: list[str] = []
    check_statuses: list[str] = []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return proof_packet_summary(path, "fail", [proof_issue("high", "proof-packet-unreadable", f"Proof packet could not be read: {exc}", str(path))])
    except json.JSONDecodeError as exc:
        return proof_packet_summary(path, "fail", [proof_issue("high", "proof-packet-invalid-json", f"Proof packet is not valid JSON: {exc}", str(path))])

    if not isinstance(payload, dict):
        return proof_packet_summary(path, "fail", [proof_issue("high", "proof-packet-invalid-shape", "Proof packet must be a JSON object.", str(path))])

    if payload.get("schema_version") != "agent-proof-packet.v1":
        issues.append(proof_issue("high", "proof-packet-wrong-schema", "Proof packet schema_version is not agent-proof-packet.v1.", str(path)))

    verdict = str(payload.get("verdict", "")).strip()
    if verdict != "complete":
        issues.append(proof_issue("high", "proof-packet-incomplete", f"Proof packet verdict is {verdict or 'missing'}, not complete.", str(path)))

    raw_changed_files = payload.get("changed_files")
    if not isinstance(raw_changed_files, list) or not raw_changed_files:
        issues.append(proof_issue("high", "proof-packet-missing-changed-files", "Proof packet has no changed-file evidence.", str(path)))
    else:
        for item in raw_changed_files:
            if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"].strip():
                packet_files.append(clean_diff_path(item["path"]))
            else:
                issues.append(proof_issue("high", "proof-packet-invalid-changed-file", "Proof packet contains an invalid changed_files entry.", str(path)))

    raw_checks = payload.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        issues.append(proof_issue("high", "proof-packet-missing-checks", "Proof packet has no checks.", str(path)))
    else:
        for item in raw_checks:
            if not isinstance(item, dict):
                issues.append(proof_issue("high", "proof-packet-invalid-check", "Proof packet contains an invalid check entry.", str(path)))
                continue
            name = str(item.get("name", "")).strip()
            status = str(item.get("status", "")).strip().lower()
            detail = str(item.get("detail", "")).strip()
            if not name or not status:
                issues.append(proof_issue("high", "proof-packet-invalid-check", "Proof packet contains a nameless or statusless check.", str(path)))
                continue
            check_statuses.append(status)
            if status in PASS_CHECK_STATUSES:
                passing_checks.append(name + (f" - {detail}" if detail else ""))
            elif status not in FAIL_CHECK_STATUSES:
                issues.append(proof_issue("medium", "proof-packet-unknown-check-status", f"Proof packet check `{name}` uses an unrecognized status.", status))

    if any(status in FAIL_CHECK_STATUSES for status in check_statuses):
        issues.append(proof_issue("high", "proof-packet-failing-checks", "Proof packet includes failing checks.", str(path)))
    if not any(status in PASS_CHECK_STATUSES for status in check_statuses):
        issues.append(proof_issue("high", "proof-packet-no-passing-checks", "Proof packet has no passing checks.", str(path)))

    missing_evidence = payload.get("missing_evidence")
    if isinstance(missing_evidence, list) and missing_evidence:
        issues.append(proof_issue("high", "proof-packet-missing-evidence", "Proof packet still has missing evidence.", ", ".join(str(item) for item in missing_evidence[:5])))
    elif missing_evidence is not None and not isinstance(missing_evidence, list):
        issues.append(proof_issue("high", "proof-packet-invalid-missing-evidence", "Proof packet missing_evidence must be a list when present.", str(path)))

    open_questions = payload.get("open_questions")
    if isinstance(open_questions, list) and open_questions:
        issues.append(proof_issue("medium", "proof-packet-open-questions", "Proof packet still has open questions.", ", ".join(str(item) for item in open_questions[:5])))
    elif open_questions is not None and not isinstance(open_questions, list):
        issues.append(proof_issue("medium", "proof-packet-invalid-open-questions", "Proof packet open_questions should be a list when present.", str(path)))

    diff_file_set = {clean_diff_path(path) for path in diff_paths}
    packet_file_set = set(packet_files)
    if diff_file_set and packet_file_set and diff_file_set != packet_file_set:
        issues.append(
            proof_issue(
                "high",
                "proof-packet-diff-mismatch",
                "Proof packet changed files do not match the provided diff.",
                f"diff={sorted(diff_file_set)} packet={sorted(packet_file_set)}",
            )
        )

    status = "fail" if any(issue.severity == "high" for issue in issues) else "pass"
    return ProofPacketSummary(str(path), status, verdict, packet_files, passing_checks, issues)


def analyze(notes: str, diff_text: str, proof_packets: Sequence[ProofPacketSummary] | None = None) -> ReleaseReport:
    findings: list[Finding] = []
    files = parse_changed_files(diff_text)
    notes_clean = notes.strip()
    proof_packet_list = list(proof_packets or [])
    passing_proof_checks = [
        check
        for packet in proof_packet_list
        if packet.status == "pass"
        for check in packet.passing_checks
    ]

    for packet in proof_packet_list:
        for issue in packet.issues:
            findings.append(Finding(issue.severity, issue.code, packet.path, issue.message, issue.evidence))

    if not notes_clean:
        findings.append(Finding("critical", "empty-release-notes", "release-notes", "Release notes are empty.", ""))
    elif len(re.findall(r"\w+", notes_clean)) < 20:
        findings.append(Finding("medium", "thin-release-notes", "release-notes", "Release notes are too short for a non-trivial diff.", redact(notes_clean)))

    if notes_clean and not VERSION_HEADING_RE.search(notes_clean):
        findings.append(Finding("low", "missing-release-heading", "release-notes", "Release notes should include a version, date, or release heading.", ""))

    if not files:
        findings.append(Finding("high", "empty-diff", "diff", "No changed files were detected in the diff.", ""))

    changed_tags = sorted({tag for file in files for tag in file.tags})
    coverage_terms: list[str] = []
    for tag in changed_tags:
        if tag_covered([tag], notes_clean):
            coverage_terms.append(tag)
    if passing_proof_checks:
        coverage_terms.append("proof-packet")

    for file in files:
        if "docs" in file.tags and len(file.tags) == 1:
            continue
        if not file_covered(file.path, notes_clean) and not tag_covered(file.tags, notes_clean):
            findings.append(
                Finding(
                    "medium",
                    "changed-file-not-covered",
                    file.path,
                    "Changed file is not mentioned directly or covered by useful release-note category language.",
                    ",".join(file.tags) or "uncategorized",
                )
            )

    if diff_has_breaking_signal(diff_text, files) and not notes_include(notes_clean, ("breaking", "migration", "compatibility", "removed", "deprecation")):
        findings.append(
            Finding("high", "breaking-change-not-covered", "diff", "Diff has breaking-change signals but release notes do not mention breaking changes or migration.", "removed public symbol or deleted file")
        )

    if any("security" in file.tags for file in files) and not tag_covered(["security"], notes_clean):
        findings.append(Finding("high", "security-change-not-covered", "diff", "Security-sensitive paths changed without security/auth/permission wording.", "security path"))

    if any("dependency" in file.tags for file in files) and not tag_covered(["dependency"], notes_clean):
        findings.append(Finding("medium", "dependency-change-not-covered", "diff", "Dependency manifest or lockfile changed without dependency wording.", "dependency path"))

    if any("operations" in file.tags for file in files) and not tag_covered(["operations"], notes_clean):
        findings.append(Finding("medium", "operations-change-not-covered", "diff", "CI, workflow, script, or automation files changed without operational wording.", "operations path"))

    if any("tests" in file.tags for file in files) and not tag_covered(["tests"], notes_clean):
        findings.append(Finding("low", "test-change-not-covered", "diff", "Test files changed without verification or test wording.", "test path"))

    if any("code" in file.tags for file in files) and notes_include(notes_clean, ("docs only", "documentation only", "no code changes")):
        findings.append(Finding("high", "docs-only-claim-contradicted", "release-notes", "Release notes claim docs-only scope but code files changed.", "code path"))

    if notes_include(notes_clean, ("no breaking changes", "no breaking change")) and diff_has_breaking_signal(diff_text, files):
        findings.append(Finding("high", "no-breaking-claim-contradicted", "release-notes", "Release notes claim no breaking changes but diff has breaking-change signals.", "breaking signal"))

    has_named_test_evidence = notes_include(notes_clean, ("make test", "ci", "github actions", "pytest", "unittest", "npm test")) or bool(passing_proof_checks)
    if notes_include(notes_clean, ("fully tested", "all tests passed", "100% tested")) and not has_named_test_evidence:
        findings.append(Finding("medium", "test-claim-without-evidence", "release-notes", "Release notes claim strong test coverage without naming evidence.", "test claim"))

    if notes_include(notes_clean, ("no security impact", "no security changes")) and any("security" in file.tags for file in files):
        findings.append(Finding("high", "no-security-claim-contradicted", "release-notes", "Release notes claim no security impact while security-sensitive paths changed.", "security path"))

    score = score_findings(findings)
    follow_up_checks = [
        "Confirm release notes include the user-visible impact, not only changed files.",
        "Keep verification evidence separate from marketing claims.",
        "Review breaking, security, dependency, and CI findings before tagging a release.",
    ]
    return ReleaseReport(
        status=status_for(score, findings),
        score=score,
        changed_file_count=len(files),
        changed_files=files,
        findings=findings,
        coverage_terms=coverage_terms,
        proof_packets=proof_packet_list,
        follow_up_checks=follow_up_checks,
    )


def score_findings(findings: Sequence[Finding]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT.get(finding.severity, 0) for finding in findings))


def status_for(score: int, findings: Sequence[Finding]) -> str:
    if any(finding.severity in {"critical", "high"} for finding in findings):
        return "blocked"
    if any(finding.severity == "medium" for finding in findings):
        return "review"
    if score < 100:
        return "pass-with-notes"
    return "pass"


def render_markdown(report: ReleaseReport) -> str:
    lines = [
        "# Agent Release Note Check",
        "",
        f"Status: {report.status}",
        f"Score: {report.score}/100",
        f"Changed files: {report.changed_file_count}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("- none")
    else:
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.rule} `{finding.path}`: {finding.message} Evidence: `{finding.evidence}`")
    lines.extend(["", "## Changed Files", ""])
    if not report.changed_files:
        lines.append("- none")
    else:
        for file in report.changed_files:
            tags = ", ".join(file.tags) if file.tags else "uncategorized"
            lines.append(f"- `{file.path}` +{file.added}/-{file.removed}; tags: {tags}")
    lines.extend(["", "## Coverage Terms", ""])
    lines.append("- " + (", ".join(report.coverage_terms) if report.coverage_terms else "none"))
    lines.extend(["", "## Proof Packets", ""])
    if not report.proof_packets:
        lines.append("- none")
    else:
        for packet in report.proof_packets:
            checks = ", ".join(packet.passing_checks) if packet.passing_checks else "none"
            lines.append(f"- `{packet.path}` status: {packet.status}; verdict: {packet.verdict or 'unknown'}; passing checks: {checks}")
            for issue in packet.issues:
                lines.append(f"- [{issue.severity}] {issue.code}: {issue.message} Evidence: `{issue.evidence}`")
    lines.extend(["", "## Follow-Up Checks", ""])
    for check in report.follow_up_checks:
        lines.append(f"- {check}")
    return "\n".join(lines) + "\n"


def report_to_json(report: ReleaseReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True) + "\n"


def should_fail(report: ReleaseReport, min_score: int, fail_on: str) -> bool:
    if report.score < min_score:
        return True
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold for finding in report.findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit release notes against a unified diff.")
    parser.add_argument("release_notes", type=Path, help="Markdown release notes or changelog draft.")
    parser.add_argument("--diff", required=True, type=Path, help="Unified diff for the release scope.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format.")
    parser.add_argument("--proof-packet", action="append", default=[], type=Path, help="Optional agent-proof-packet.v1 JSON evidence to verify against the diff.")
    parser.add_argument("--write-report", type=Path, help="Optional path to write the rendered report.")
    parser.add_argument("--min-score", type=int, default=0, help="Fail when score is below this value.")
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high", help="Fail when a finding at or above this severity is present.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    diff_text = read_text(args.diff)
    diff_paths = [file.path for file in parse_changed_files(diff_text)]
    proof_packets = [audit_proof_packet(path, diff_paths) for path in args.proof_packet]
    report = analyze(read_text(args.release_notes), diff_text, proof_packets)
    output = report_to_json(report) if args.format == "json" else render_markdown(report)
    if args.write_report:
        args.write_report.write_text(output, encoding="utf-8")
    sys.stdout.write(output)
    return 1 if should_fail(report, args.min_score, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
