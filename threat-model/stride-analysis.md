# SecureBank - STRIDE Threat Analysis

## 1. Methodology

STRIDE categorizes threats as:

- S: Spoofing
- T: Tampering
- R: Repudiation
- I: Information Disclosure
- D: Denial of Service
- E: Elevation of Privilege

The entries below describe identified threat scenarios, implemented
controls, available validation evidence, and remaining risks.
A tested control does not prove that every related attack scenario is mitigated.

## 2. Threat Analysis

### S-001: Authentication Token Spoofing

**Component:** Backend REST API

**Threat:** An attacker submits a forged, modified, expired, or otherwise invalid JWT to impersonate a user.

**Controls:** Validate JWT signature, expiry, issuer, and audience. Reject malformed tokens and unsupported authorization-header formats.

**Validation evidence:** `test_tampered_token_is_rejected`, `test_expired_token_is_rejected`, `test_token_with_wrong_issuer_is_rejected`, `test_token_with_wrong_audience_is_rejected`, `test_empty_bearer_token_is_rejected`, `test_basic_auth_scheme_is_rejected`, and `test_malformed_authorization_header_is_rejected`.

**Status:** Partially validated.

**Residual risk:** Broader identity spoofing, credential abuse, and additional authentication scenarios remain unassessed.

### T-001: Unauthorized Account Modification

**Component:** Backend REST API

**Threat:** A user attempts to alter another user's account or submit unsupported modification requests.

**Controls:** Enforce server-side account ownership checks and reject unsupported POST, PUT, PATCH, and DELETE methods on the account endpoint with HTTP 405.

**Validation evidence:** `test_user_cannot_access_another_users_account`, `test_post_to_get_only_account_endpoint_is_rejected`, `test_account_endpoint_rejects_post_method`, and `test_account_endpoint_rejects_put_and_patch_methods`.

**Status:** Partially validated.

**Residual risk:** No account-mutation endpoint currently exists. Authorization and integrity controls for future mutation operations require separate testing.

### R-001: Insufficient Audit Evidence

**Component:** Audit Logging

**Threat:** Security-relevant actions cannot be reliably attributed, or audit records are modified without detection.

**Controls:** Persist structured JSON Lines audit events, restrict local log-file and directory permissions, filter sensitive detail fields, and verify a SHA-256 hash chain.

**Validation evidence:** `test_successful_login_is_audited_without_credentials`, `test_failed_login_is_audited`, `test_cross_account_access_is_audited`, `test_missing_token_rejection_is_audited`, `test_audit_event_persists_and_hash_chain_verifies`, `test_audit_log_tampering_is_detected`, and `test_audit_log_file_has_restrictive_permissions`.

**Status:** Partially validated.

**Residual risk:** Logs are stored locally. External protection, independent integrity checkpoints, retention controls, and resistance to privileged rewriting remain unverified. A hash chain alone does not prevent a privileged attacker from rewriting the entire log and recomputing its hashes.

### I-001: Cross-User Data Exposure

**Component:** Backend REST API

**Threat:** A user retrieves another user's account information by changing the account identifier.

**Controls:** Enforce server-side account ownership checks for account access and avoid including credentials in successful-login audit details.

**Validation evidence:** `test_user_can_access_own_account`, `test_user_cannot_access_another_users_account`, and `test_successful_login_is_audited_without_credentials`.

**Status:** Mitigated in tested scenarios.

**Residual risk:** Additional objects, operations, response fields, and sensitive-data exposure scenarios require assessment.

### D-001: API Resource Exhaustion

**Component:** Backend REST API

**Threat:** Excessive requests consume application resources or prevent legitimate users from accessing the API.

**Controls:** Flask-Limiter applies per-client-IP limits of 5 requests per minute to `POST /api/login` and 30 requests per minute to `GET /api/accounts/<account_id>` and `GET /api/admin/health`. Excess requests receive HTTP 429.

**Validation evidence:** `test_login_rate_limit_returns_429` and `test_account_rate_limit_returns_429`.

**Status:** Partially validated.

**Residual risk:** Admin-endpoint rate-limit behavior, distributed-client abuse, broader resource-exhaustion scenarios, and production shared-storage behavior remain unverified. The lab uses in-memory rate-limit storage. Request-size limits, timeouts, and resource quotas are not established by the evidence documented here.

### E-001: Privilege Escalation

**Component:** Backend REST API

**Threat:** A regular user attempts to perform an administrator-only action.

**Controls:** The example `GET /api/admin/health` endpoint requires authentication and the `admin` role through the `require_role("admin")` guard.

**Validation evidence:** `test_regular_user_cannot_access_admin_endpoint`, `test_admin_role_can_access_admin_endpoint`, and `test_admin_endpoint_rejects_missing_token`.

**Status:** Partially validated.

**Residual risk:** Persistent admin provisioning and equivalent authorization enforcement for future privileged operations remain unverified.

## 3. Validation Approach

For each threat:

1. Identify the affected component and data flow.
2. Document attack preconditions and potential impact.
3. Identify implemented controls and their limitations.
4. Map the threat to automated tests or other explicit evidence.
5. Run validation and record the result.
6. Keep the threat register and traceability matrix consistent.
7. Reassess residual risk when controls or application behavior change.

## 4. Evidence and Limitations

- Automated regression tests are maintained in `tests/test_bola.py`.
- Threat-to-test mappings are maintained in `threat-model/threat-test-traceability.md`.
- Threat priorities, mitigations, and statuses are recorded in `threat-model/threat-register.csv`.
- Audit logging is implemented in `application/audit.py`.
- Authentication, authorization, and rate limiting are implemented in `application/app.py`.
- A passing test demonstrates only the behavior exercised by that test.
- The project is an educational lab, not a production banking service.

These entries describe threat scenarios and the evidence available for their controls; they do not claim that all attack paths have been eliminated.
