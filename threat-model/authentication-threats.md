# SecureBank Authentication Threat Model

## Component
Backend REST API - Authentication and JWT Validation

## Assets
- User identities
- Authentication credentials
- JWT signing keys
- Access tokens
- Account information

## Trust Boundary
TB2 - Web Application to Backend REST API

## Threats and Validation

| ID | Threat | Implemented Control | Validation |
|---|---|---|---|
| AUTH-001 | JWT signature tampering | Signature verification using HS256 | Tampered-token test passed |
| AUTH-002 | Expired token reuse | Expiration validation | Expired-token test passed |
| AUTH-003 | Missing object authorization | Server-side ownership check | Cross-user access test passed |
| AUTH-004 | Weak signing key | Secret supplied through environment | Configuration implemented; production handling not validated |
| AUTH-005 | Credential brute force | Rate limiting | Not implemented |

## Additional Controls

- Issuer and audience are validated.
- Required JWT claims are checked.
- Missing tokens are rejected.
- Invalid login credentials are rejected.

## Test Evidence

Run:

    pytest -v

Latest recorded result: 7 tests passed.

## Known Limitations

- Demo usernames and passwords are hardcoded.
- No login rate limiting is implemented.
- JWT signing-key rotation is not implemented.
- Environment variables are not a complete production secrets-management solution.
- Tests cover defined scenarios, not all possible attacks.

## Residual Risks

AUTH-004 requires a production-grade secrets-management design.
AUTH-005 requires rate limiting and abuse protection.
Credential storage and authentication lifecycle require further hardening.

## Status

Initial JWT and object-authorization controls implemented.
Additional security hardening remains necessary.
