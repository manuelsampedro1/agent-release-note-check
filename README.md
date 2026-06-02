# agent-release-note-check

Audit release notes against the diff they claim to describe.

This is a dependency-free Python 3.9+ CLI for maintainers who use coding agents
to prepare changelogs, release notes, or PR-to-release summaries. It does not
call a model or publish anything. It reads a release note and a unified diff,
then reports whether important change categories are missing or overstated.

## Why

Release notes are public promises. Agent-written notes can miss breaking
changes, dependency updates, CI workflow edits, security-sensitive paths, or
documentation-only scope. They can also claim "fully tested" or "no breaking
changes" without evidence in the note.

Use `agent-release-note-check` before:

- publishing a GitHub release,
- merging a generated changelog,
- turning a PR summary into release notes,
- importing release evidence into a proof packet or run ledger,
- asking another agent to continue a release workflow.

## Install

```sh
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -e .
```

## Usage

Audit notes against a diff:

```sh
agent-release-note-check examples/release-notes.md --diff examples/sample.diff --min-score 80
```

Emit JSON:

```sh
agent-release-note-check examples/release-notes.md --diff examples/sample.diff --format json
```

Write a report:

```sh
agent-release-note-check examples/release-notes.md --diff examples/sample.diff --write-report /tmp/release-note-check.md
```

Gate medium findings:

```sh
agent-release-note-check examples/weak-release-notes.md --diff examples/sample.diff --fail-on medium
```

## What It Checks

- Release note presence and version/date-like heading.
- Changed files mentioned directly or covered by useful category language.
- Breaking-change signals in diffs without migration or breaking-change notes.
- Security-sensitive paths without security/auth/secret wording.
- Dependency manifest or lockfile changes without dependency notes.
- CI, workflow, script, or automation changes without operational notes.
- Test changes without verification or test notes.
- Code changes described as docs-only.
- Unsupported claims such as "fully tested", "no breaking changes", or "no
  security impact" when the note lacks evidence or the diff contradicts the
  claim.

## Output

Markdown output includes:

- overall status and score,
- changed-file summary,
- findings with severity and evidence,
- release-note coverage hints,
- reviewer follow-up checks.

JSON output exposes the same shape for automation.

## Limits

- This is a release-note consistency check, not a substitute for human release
  review.
- It reads unified diffs; it does not inspect the full repository history.
- It uses deterministic heuristics, not vulnerability intelligence.
- A clean report means the note covers detected diff signals, not that the
  release is safe or complete.

## Verify

```sh
make test
make lint
make build
make smoke
```

