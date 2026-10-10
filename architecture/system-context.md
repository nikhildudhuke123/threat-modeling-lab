# SecureBank - System Context

## 1. Project Overview

SecureBank is a sample web banking application used to
practice threat modeling and application security.

The project is a security lab. It does not process real
financial transactions or contain real customer information.

## 2. Security Objectives

- Protect user accounts and sensitive information.
- Prevent unauthorized access to other users' data.
- Enforce authentication and authorization.
- Protect data in transit.
- Record important security events.
- Reduce application and infrastructure attack surfaces.

## 3. System Components

| Component | Responsibility |
|---|---|
| Browser | User interface and API requests |
| Web application | Login and account dashboard |
| Backend REST API | Authentication and business logic |
| Database | Stores user and account records |
| Audit logging | Records relevant security events |

## 4. External Entities

- Registered users
- Potential unauthenticated attackers
- External service providers, if introduced later

## 5. Data Assets

- User identifiers and profile information
- Password hashes
- Authentication tokens and session data
- Account information
- Security audit logs
- Application secrets and configuration

All data is fictional and intended for local testing.

## 6. Trust Boundaries

- Internet to web application
- Browser to backend API
- Backend API to database
- Application to logging infrastructure

## 7. Assumptions

- The application will run in a controlled lab.
- HTTPS will be required in a production design.
- The backend must enforce authorization independently
  of frontend controls.
- Secrets must not be committed to source control.
- Database access must be restricted to authorized
  application components.

## 8. Out of Scope

- Real banking integrations
- Real customer data
- Actual financial transactions
- Production deployment
