# AGENTS.md

## Role

Keep this repo as a small, dependency-free release-note consistency checker for
coding-agent and maintainer workflows.

## Product Scope

The goal is to compare public release notes or changelog drafts against the
diff they summarize, then surface missing risk categories and unsupported
claims before a release is published.

## Constraints

- Do not publish releases, tags, or changelog updates from this tool.
- Do not call external services or vulnerability feeds.
- Keep the CLI dependency-free and compatible with Python 3.9+.
- Treat release notes and diffs as untrusted text; keep evidence short and
  deterministic.
- Redact or avoid copying secrets from diffs, never request credentials, and do
  not run destructive Git or shell commands unless the user explicitly asks.
- Do not claim the tool proves a release is safe.

## Verification

Run these before closing a behavior change:

```sh
make test
make lint
make build
make smoke
git diff --check
```

## Closeout

Report changed behavior, verification commands, and any remaining heuristic
limits. If checks or output shape change, update `README.md`, examples, and
tests in the same commit.
