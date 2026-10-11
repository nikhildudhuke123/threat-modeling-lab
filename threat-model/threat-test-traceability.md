# Threat-to-Test Traceability Matrix

## Purpose

This matrix maps the STRIDE threat register to implemented controls,
available regression-test evidence, and remaining validation work.

## Traceability Matrix

| Threat ID | STRIDE Category | Mitigation / Control | Test Evidence | Status | Remaining Work |
|---|---|---|---|---|---|
| S-001 | Spoofing | Validate JWT signature, expiry, issuer, and audience | `test_tampered_token_is_rejected`, `test_expired_token_is_rejected`, `test_token_with_wrong_issuer_is_rejected`, `test_token_with_wrong_audience_is_rejected` | Partially validated | Assess broader identity spoofing and credential-abuse scenarios |
| T-001 | Tampering | Enforce object-level authorization and reject unsupported methods | `test_user_cannot_access_another_users_account`, `test_post_to_get_only_account_endpoint_is_rejected` | To validate | No account-modification endpoint or mutation tests currently exist |
| R-001 | Repudiation | Implement protected audit logging | No audit logging tests currently exist | To validate | Define required events, log protection, retention, and tests |
| I-001 | Information Disclosure | Enforce server-side account ownership checks | `test_user_can_access_own_account`, `test_user_cannot_access_another_users_account`; manual API checks returned 200 and 403 respectively | Mitigated in tested scenarios | Extend authorization coverage to additional objects and operations |
| D-001 | Denial of Service | Apply rate limits and resource limits | No rate-limit or resource-exhaustion tests currently exist | To validate | Implement limits and add controlled availability tests |
| E-001 | Elevation of Privilege | Enforce server-side permission checks | No privileged-operation or role-authorization tests currently exist | To validate | Define roles and privileged operations, then test unauthorized access |

## Evidence Notes

- Automated regression tests are in `tests/test_bola.py`.
- BOLA remediation evidence is documented in `mitigations/bola-remediation.md`.
- The STRIDE register is `threat-model/threat-register.csv`.
- Manual API verification covered the tested local account scenarios.
- A passing test demonstrates only the behavior exercised by that test.
  It does not establish that every related threat is fully mitigated.

## Validation Workflow

1. Identify a threat in the STRIDE register.
2. Document the intended security control.
3. Add a test or other appropriate validation evidence.
4. Run the validation and record its result.
5. Update the threat register and this matrix consistently.
6. Keep unresolved risks explicitly marked as requiring validation.
