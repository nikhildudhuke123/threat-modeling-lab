# Threat-to-Test Traceability Matrix

## Purpose

This matrix maps the STRIDE threat register to implemented controls,
automated regression-test evidence, and remaining validation work.

## Traceability Matrix

| Threat ID | STRIDE Category | Mitigation / Control | Test Evidence | Status | Remaining Work |
|---|---|---|---|---|---|
| S-001 | Spoofing | Validate JWT signature, expiry, issuer, and audience; reject malformed or unsupported authorization headers | `test_tampered_token_is_rejected`, `test_expired_token_is_rejected`, `test_token_with_wrong_issuer_is_rejected`, `test_token_with_wrong_audience_is_rejected`, `test_empty_bearer_token_is_rejected`, `test_basic_auth_scheme_is_rejected`, `test_malformed_authorization_header_is_rejected` | Partially validated | Assess broader identity spoofing and credential-abuse scenarios |
| T-001 | Tampering | Enforce account ownership and reject unsupported account modification methods | `test_user_cannot_access_another_users_account`, `test_post_to_get_only_account_endpoint_is_rejected`, `test_account_endpoint_rejects_post_method`, `test_account_endpoint_rejects_put_and_patch_methods` | Partially validated | No account-mutation endpoint exists; validate authorization and integrity if mutation operations are introduced |
| R-001 | Repudiation | Persist structured audit events with restrictive permissions and hash-chain integrity verification | `test_successful_login_is_audited_without_credentials`, `test_failed_login_is_audited`, `test_cross_account_access_is_audited`, `test_missing_token_rejection_is_audited`, `test_audit_event_persists_and_hash_chain_verifies`, `test_audit_log_tampering_is_detected`, `test_audit_log_file_has_restrictive_permissions` | Partially validated | External protection, independent integrity checkpoints, retention, and resistance to privileged rewriting remain unverified |
| I-001 | Information Disclosure | Enforce server-side account ownership checks and avoid logging credentials | `test_user_can_access_own_account`, `test_user_cannot_access_another_users_account`, `test_successful_login_is_audited_without_credentials` | Mitigated in tested scenarios | Extend authorization and sensitive-data exposure testing to additional objects, operations, and response fields |
| D-001 | Denial of Service | Apply per-client-IP rate limits to login, account, and admin health endpoints | `test_login_rate_limit_returns_429`, `test_account_rate_limit_returns_429` | Partially validated | Admin endpoint rate-limit behavior, distributed-client abuse, broad resource exhaustion, and production shared-storage behavior remain unverified |
| E-001 | Elevation of Privilege | Require authentication and an admin role for the admin health endpoint | `test_regular_user_cannot_access_admin_endpoint`, `test_admin_role_can_access_admin_endpoint`, `test_admin_endpoint_rejects_missing_token` | Partially validated | Persistent admin provisioning and equivalent authorization coverage for future privileged operations remain unverified |

## Evidence Notes

- Automated regression tests are in `tests/test_bola.py`.
- BOLA remediation evidence is documented in `mitigations/bola-remediation.md`.
- The STRIDE register is `threat-model/threat-register.csv`.
- Audit logging implementation is in `application/audit.py`.
- Rate limiting and role-based authorization are implemented in `application/app.py`.
- The test suite contains 34 tests in the last verified local run.
- A passing test demonstrates only the behavior exercised by that test.
  It does not establish that every related threat is fully mitigated.
- Manual API checks may supplement automated evidence but should be recorded separately from regression tests.

## Validation Workflow

1. Identify a threat in the STRIDE register.
2. Document the intended security control.
3. Add a test or other appropriate validation evidence.
4. Run the validation and record its result.
5. Update the threat register and this matrix consistently.
6. Keep unresolved risks explicitly marked as requiring validation.
