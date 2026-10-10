# SecureBank Data Flow Diagram

```mermaid
flowchart TD
    U[External User / Attacker]
    W[Web Application]
    API[Backend REST API]
    DB[(User and Account Database)]
    LOG[(Security Audit Logs)]

    U -->|F1: Login and user requests| W
    W -->|F2: API requests and token| API
    API -->|F3: Database queries| DB
    DB -->|F4: Account records| API
    API -->|F5: Security events| LOG
    API -->|F6: API responses| W
    W -->|F7: Rendered responses| U

    TB1{{Trust Boundary: Internet to Web}}
    TB2{{Trust Boundary: Web to API}}
    TB3{{Trust Boundary: API to Data Stores}}
