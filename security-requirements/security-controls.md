# SecureBank Security Requirements and Traceability

## Purpose

This document maps security requirements to implementation evidence and remaining gaps. Documentation or scanner configuration alone does not prove a control is fully implemented.

## Requirements Matrix

| ID | Requirement | Evidence / Status | Remaining Gap |
|---|---|---|---|
| SEC-01 | Protected endpoints require authentication. | JWT authentication and rejection tests; partially validated. | Review new endpoints as they are added. |
| SEC-02 | Users can access only authorized account objects. | Ownership enforcement and own/cross-account tests; validated for tested scenarios. | Extend tests when new object types or access paths are added. |
| SEC-03 | Tokens must be cryptographically validated in production. | JWT signature, expiry, issuer, and audience checks with negative tests; partially validated. | Production key management and deployment configuration remain unverified. |
| SEC-04 | Database queries must use parameterized statements. | No database query path is established in the current in-memory demo; not applicable currently. | Reassess when database access is introduced. |
| SEC-05 | Secrets must not be committed to source control. | Gitleaks history scan configured in CI; a previous local scan reported no leaks; partially validated. | Re-scan the current revision and investigate findings. |
| SEC-06 | Dependencies and container images must be scanned. | CI configures Trivy filesystem scanning for vulnerabilities, misconfigurations, and secrets; partially validated. | Container image scanning is not established in the current workflow. |
| SEC-07 | Security-relevant events must be logged safely. | Persistent structured audit logs, sensitive-field filtering, restrictive permissions, hash-chain and tampering tests; partially validated. | External log protection, independent checkpoints, and retention remain unimplemented. |
| SEC-08 | API resources must have appropriate limits. | Login and account rate-limit tests verify HTTP 429; partially validated. | Admin rate-limit testing, shared production storage, and broader resource-exhaustion tests remain outstanding. |
| SEC-09 | Administrative actions require explicit permissions. | Admin-role authorization tests cover regular-user denial, admin access, and missing tokens; partially validated. | Persistent admin provisioning and future privileged operations remain unverified. |
| SEC-10 | Security checks must run in CI/CD. | GitHub Actions defines pytest, Semgrep, Trivy, and Gitleaks jobs; configuration present. | Verify that all required jobs pass on the current commit. |

## Validation Guidance

- **Validated for tested scenarios** means evidence supports only the tested behavior.
- **Partially validated** means relevant controls exist but gaps remain.
- **Not applicable currently** means the relevant technology or code path is absent and must be reassessed if introduced.
- A configured CI job does not, by itself, prove a successful run.

## Test Evidence

The last recorded test-suite result was 34 passing tests. Re-run before using that count as evidence for the current revision:

`JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')" pytest -q`

## Scope and Limitations

This is a security lab and portfolio project, not evidence of production security certification. Results apply only to tested scenarios. Production readiness also depends on deployment configuration, key management, operational monitoring, external log protection, and controls for any infrastructure added later.
