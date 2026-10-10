# SecureBank Security Requirements

| ID | Requirement | Validation |
|---|---|---|
| SEC-01 | Protected endpoints require authentication | Unauthenticated request returns 401 |
| SEC-02 | Users can access only authorized account objects | Cross-user request returns 403 |
| SEC-03 | Tokens must be cryptographically validated in production | Authentication design review and tests |
| SEC-04 | Database queries must use parameterized statements | Code review and SQL injection tests |
| SEC-05 | Secrets must not be committed to source control | Gitleaks scan |
| SEC-06 | Dependencies and container images must be scanned | Trivy scan |
| SEC-07 | Security-relevant events must be logged safely | Logging tests and review |
| SEC-08 | API resources must have appropriate limits | Rate-limit and resource tests |
| SEC-09 | Administrative actions require explicit permissions | Authorization tests |
| SEC-10 | Security checks must run in CI/CD | GitHub Actions results |

These are design requirements. Each must be validated before
claiming it is implemented.
