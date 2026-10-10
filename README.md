# Threat Modeling Lab

A hands-on security engineering project covering system
architecture, STRIDE threat modeling, API security, risk
assessment, mitigations, and automated security validation.

## Objectives

- Create a system context and data-flow diagram.
- Identify threats using STRIDE.
- Maintain a threat register and security requirements.
- Demonstrate and remediate a BOLA authorization flaw.
- Validate security controls using automated tests.
- Integrate static analysis and dependency scanning into CI/CD.

## Current Implementation

- Python and Flask
- Pytest
- Mermaid diagrams
- CSV threat register
- Git version control

## Demonstrated Security Scenario

The initial API allowed an authenticated user to retrieve
another user's account because object-level authorization
was missing.

A server-side ownership check was added.

Three regression tests verify:
1. Access to an owned account.
2. Denial of access to another user's account.
3. Denial of unauthenticated access.

## Run the Tests

Activate the virtual environment:

    source .venv/bin/activate

Run:

    pytest -v

## Repository Structure

- application/: Sample API
- architecture/: System context and data-flow diagrams
- threat-model/: STRIDE analysis and threat register
- security-requirements/: Security controls
- mitigations/: Remediation documentation
- tests/: Automated security tests
- .github/workflows/: Planned CI/CD automation

## Limitations

This is an educational lab using fictional data and demo-only
credentials. It is not production-ready software.

## Planned Enhancements

- Improve authentication design.
- Add further threat validation tests.
- Integrate Semgrep, Trivy, and Gitleaks.
- Automate security checks using GitHub Actions.
- Expand cloud architecture threat modeling.
