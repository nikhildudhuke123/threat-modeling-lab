# BOLA Remediation and Validation

## Finding

- **ID:** I-001
- **Name:** Broken Object Level Authorization (BOLA)
- **Component:** Backend REST API
- **OWASP API Security:** API1 - Broken Object Level Authorization

## Initial Behavior

The API authenticated the caller but did not check whether
the requested account belonged to that caller.

A request authenticated as user-a could retrieve account 202,
which belongs to user-b. The initial demonstration returned HTTP 200.

## Root Cause

Authentication established the caller's identity, but the endpoint
did not enforce object-level authorization.

## Remediation

The API compares the account owner with the authenticated user before
returning account information. Requests for another user's account
receive HTTP 403.

JWT authentication also validates the token signature, expiration,
issuer, and audience. The application requires a JWT signing secret
from the runtime environment.

## Automated Regression Tests

The regression suite contains 13 tests, including:

- Owner can access their own account: HTTP 200.
- User cannot access another user's account: HTTP 403.
- Missing authentication token: HTTP 401.
- Tampered and expired tokens: HTTP 401.
- Successful and invalid login.
- Password-hash storage and malformed login input validation.

## Live API Verification

Manual verification was performed against the locally running API.

| Test | Result | Expected |
|---|---|---|
| Request account 101 without a token | HTTP 401 Unauthorized | HTTP 401 |
| user-a requests account 101 with a valid JWT | HTTP 200 OK | HTTP 200 |
| user-a requests account 202 with the same JWT | HTTP 403 Forbidden | HTTP 403 |

The successful account response identified account 101 as owned by
user-a. The cross-account request returned `{"error":"Forbidden"}`.

## Validation Status

- All 13 automated regression tests passed.
- Manual API checks confirmed authentication enforcement and
  object-level authorization for the tested accounts.
- Semgrep reported zero findings in the scanned application and test files.
- Trivy reported zero dependency vulnerabilities in `requirements.txt`.
- Gitleaks reported no leaks in the scanned Git history.

Scanner results apply only to the configured scans; they do not prove
the application is free of all security issues.

## Limitations

- This is a local educational lab, not a production banking system.
- Account data is stored in memory.
- Demo identities and password hashes are supplied through environment
  variables; there is no production identity-management or account-provisioning system.
- Rate limiting, production-grade audit logging, and persistent storage
  are not implemented.

## Residual Risks

A production implementation requires separate design and validation
for identity management, secret rotation, rate limiting, audit logging,
database access controls, operational monitoring, and other threats.
