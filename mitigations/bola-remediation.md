# BOLA Remediation and Validation

## Finding

ID: I-001
Name: Broken Object Level Authorization (BOLA)
Component: Backend REST API
OWASP API Security: API1 - Broken Object Level Authorization

## Initial Behavior

The API authenticated the caller but did not check whether
the requested account belonged to that caller.

A request authenticated as user-a could retrieve account 202,
which belongs to user-b.

The initial demonstration test returned HTTP 200.

## Root Cause

Authentication established the caller's identity, but the
endpoint did not enforce object-level authorization.

## Remediation

The API now compares the account owner with the authenticated
user before returning account information.

Requests for another user's account receive HTTP 403.

## Regression Tests

- Owner can access their own account: expected HTTP 200.
- User cannot access another user's account: expected HTTP 403.
- Request without authentication: expected HTTP 401.

## Validation Result

All three regression tests passed using Flask's test client.

## Limitations

- Authentication uses hardcoded demo tokens.
- Data is stored in memory.
- No real JWT validation or persistent database is implemented.
- This is a local educational lab, not a production banking system.

## Residual Risks

Production authentication, token management, database access,
logging, rate limiting, and other threats require separate
design and validation.
