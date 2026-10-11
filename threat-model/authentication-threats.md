# SecureBank Authentication Threat Model

## Component

Backend REST API - Authentication and JWT Validation

## Assets

- User identities
- Authentication credentials
- JWT signing key
- Access tokens
- Account information

## Trust Boundary

TB2 - Web Application to Backend REST API

## Threats and Validation

| ID | Threat | Implemented Control | Validation Evidence | Status |
|---|---|---|---|---|
| AUTH-001 | JWT signature tampering | JWT signature verification using the configured algorithm | `test_tampered_token_is_rejected` | Validated in tested scenario |
| AUTH-002 | Expired token reuse | JWT expiration validation | `test_expired_token_is_rejected` | Validated in tested scenario |
| AUTH-003 | Missing object authorization | Server-side account ownership enforcement | `test_user_can_access_own_account`, `test_user_cannot_access_another_users_account` | Mitigated in tested scenarios |
| AUTH-004 | Weak or compromised signing key | `JWT_SECRET` is required through an environment variable; the application fails to start if it is missing | Startup configuration is implemented; production secrets management and key rotation have not been validated | Partially validated |
| AUTH-005 | Credential brute force | Flask-Limiter applies a limit of 5 login requests per minute per client IP and returns HTTP 429 when exceeded | `test_login_rate_limit_returns_429` | Partially validated |

## Additional Controls

- JWT issuer and audience are validated.
- Required JWT claims are checked.
- Missing, malformed, and unsupported authorization headers are rejected.
- Invalid login credentials are rejected.
- Passwords are checked using Werkzeug's `check_password_hash`.
- Password hashes are supplied through environment variables for the lab; test-only hashes are configured by the test module.
- Login and account-access rate limits are configured separately.

## Test Evidence

Automated regression tests are maintained in `tests/test_bola.py`.

Run the suite with:

    JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')" pytest -v

The latest locally verified result was **34 passing tests**. Relevant authentication tests include:

- `test_tampered_token_is_rejected`
- `test_expired_token_is_rejected`
- `test_token_with_wrong_issuer_is_rejected`
- `test_token_with_wrong_audience_is_rejected`
- `test_missing_token_is_rejected`
- `test_empty_bearer_token_is_rejected`
- `test_basic_auth_scheme_is_rejected`
- `test_malformed_authorization_header_is_rejected`
- `test_login_returns_access_token`
- `test_invalid_login_is_rejected`
- `test_users_store_password_hashes_not_plaintext_passwords`
- `test_login_rate_limit_returns_429`

A passing test establishes only the behavior exercised by that test.

## Known Limitations

- The lab has no persistent identity store or production identity lifecycle.
- `JWT_SECRET` is supplied through an environment variable; secure production provisioning, rotation, and revocation have not been validated.
- Login rate limiting is per client IP and uses in-memory storage. Distributed credential abuse and production shared-storage behavior remain unverified.
- Broader credential-stuffing, password policy, and authentication abuse scenarios require further testing.
- Environment variables alone do not constitute a complete production secrets-management design.
- Tests cover defined scenarios, not every possible authentication attack.

## Residual Risks

- AUTH-004 requires production-grade secrets management and a defined key-rotation process.
- AUTH-005 requires broader abuse testing and shared rate-limit storage for multi-worker production deployments.
- Persistent identity management and the authentication lifecycle require further hardening.

## Status

JWT validation, password-hash verification, account ownership checks, and login rate limiting are implemented with regression-test evidence for defined scenarios. Additional authentication hardening and broader abuse testing remain necessary.
