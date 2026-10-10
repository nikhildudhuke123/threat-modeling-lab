# SecureBank - STRIDE Threat Analysis

## 1. Methodology

STRIDE categorizes threats as:

- S: Spoofing
- T: Tampering
- R: Repudiation
- I: Information Disclosure
- D: Denial of Service
- E: Elevation of Privilege

The entries below are initial threat hypotheses.
They must be validated against the implemented application.

## 2. Initial Threats

### S-001: Authentication Token Spoofing
Component: Backend REST API
Threat: An attacker submits a forged or modified token.
Mitigation: Verify token integrity, issuer, audience, and expiry.

### T-001: Unauthorized Account Modification
Component: Backend REST API
Threat: A user modifies another user's account information.
Mitigation: Enforce server-side object-level authorization.

### R-001: Insufficient Audit Evidence
Component: Audit Logging
Threat: Security-relevant actions cannot be reliably attributed.
Mitigation: Record appropriate events with timestamps and
authenticated actor identifiers; restrict log modification.

### I-001: Cross-User Data Exposure
Component: Backend REST API
Threat: A user retrieves another user's account information.
Mitigation: Check authorization on every object access.

### D-001: API Resource Exhaustion
Component: Backend REST API
Threat: Excessive requests exhaust available resources.
Mitigation: Apply rate limits, request-size limits, timeouts,
and appropriate resource quotas.

### E-001: Privilege Escalation
Component: Backend REST API
Threat: A regular user performs an administrator-only action.
Mitigation: Enforce server-side role and permission checks.

## 3. Validation Plan

For each threat:

1. Identify the affected component and data flow.
2. Document the attack preconditions.
3. Estimate likelihood and impact.
4. Identify existing security controls.
5. Select an appropriate validation test.
6. Record evidence and remediation.
7. Reassess residual risk after mitigation.

## 4. Important Note

These entries describe possible threats, not confirmed
vulnerabilities. Actual findings require testing.
