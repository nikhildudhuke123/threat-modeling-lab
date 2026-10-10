# SecureBank - Data Flow Diagram (DFD)

## 1. Purpose

This document describes how data moves through SecureBank
and identifies the trust boundaries that require security controls.

## 2. Data Flow

1. A user accesses SecureBank through a browser.
2. The browser sends HTTPS requests to the web application.
3. The web application sends API requests to the backend.
4. The backend authenticates the user and authorizes each request.
5. The backend reads or writes data in the database.
6. Security-relevant events are sent to audit logging.
7. The backend returns an appropriate response to the browser.

## 3. Components

| ID | Component Type | Name |
|---|---|---|
| E1 | External Entity | User / Potential Attacker |
| P1 | Process | Web Application |
| P2 | Process | Backend REST API |
| D1 | Data Store | User and Account Database |
| D2 | Data Store | Security Audit Logs |

## 4. Data Flows

| ID | Source | Destination | Data |
|---|---|---|---|
| F1 | E1 | P1 | Login details and user requests |
| F2 | P1 | P2 | API requests and authentication tokens |
| F3 | P2 | D1 | Authorized database queries |
| F4 | D1 | P2 | Requested account and user records |
| F5 | P2 | D2 | Security events and audit records |
| F6 | P2 | P1 | API responses and error messages |
| F7 | P1 | E1 | Rendered application responses |

## 5. Trust Boundaries

### TB1 - Internet to Web Application
Untrusted users can submit requests and potentially malicious input.

### TB2 - Web Application to Backend API
Requests and tokens must be validated. The backend must not
trust client-supplied identity or authorization claims without
proper verification.

### TB3 - Backend API to Database
Only authorized application components should access the database.
Parameterized queries and least-privilege database access are required.

### TB4 - Application to Audit Logging
Logs must be protected against unauthorized modification and
must not expose passwords, session tokens, or other secrets.

## 6. Initial Security Questions

- Can an unauthenticated user access protected endpoints?
- Can one user retrieve another user's account information?
- Are authentication tokens validated correctly?
- Can user input manipulate database queries?
- Are sensitive values exposed in responses or logs?
- Can excessive requests exhaust application resources?

## 7. Status

This is an initial logical DFD. Actual implementation details,
data formats, protocols, and trust boundaries must be validated
as the application is built.
