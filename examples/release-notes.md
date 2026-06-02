# v0.4.0

## Changed

- Added authenticated session refresh handling in `src/auth/session.py`.
- Documented the dependency update and lockfile refresh for the release.
- Updated CI workflow automation so release smoke tests run on Python 3.11.
- Added verification coverage for session refresh behavior in tests.

## Security

- The auth change now rejects expired session tokens before reuse.

## Verification

- `make test`
- GitHub Actions CI

## Compatibility

- No public API migration is required.

