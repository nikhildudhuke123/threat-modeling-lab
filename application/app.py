import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from audit import audit_event

app = Flask(__name__)
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
)

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGORITHM = "HS256"

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

# Load precomputed password hashes from the runtime environment.
# Provision hashes securely; never store plaintext passwords in application code.
USER_A_PASSWORD_HASH = os.environ.get("USER_A_PASSWORD_HASH")
USER_B_PASSWORD_HASH = os.environ.get("USER_B_PASSWORD_HASH")

if not USER_A_PASSWORD_HASH or not USER_B_PASSWORD_HASH:
    raise RuntimeError(
        "USER_A_PASSWORD_HASH and USER_B_PASSWORD_HASH environment variables are required"
    )

USERS = {
    "user-a": {"password_hash": USER_A_PASSWORD_HASH, "role": "user"},
    "user-b": {"password_hash": USER_B_PASSWORD_HASH, "role": "user"},
}

ACCOUNTS = {
    101: {"owner": "user-a", "balance": 1500},
    202: {"owner": "user-b", "balance": 2400},
}


def create_token(username, lifetime=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "iat": now,
        "exp": now + lifetime,
        "iss": "securebank-lab",
        "aud": "securebank-api",
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def require_role(required_role):
    """Require the authenticated user to have a specific role."""
    def decorator(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            username = getattr(request, "authenticated_user", None)
            user = USERS.get(username)
            if not user or user.get("role") != required_role:
                audit_event(
                    "authorization_denied",
                    "failure",
                    username=username if isinstance(username, str) else "unknown",
                    required_role=required_role,
                    path=request.path,
                )
                return jsonify({"error": "Forbidden"}), 403
            return handler(*args, **kwargs)
        return wrapper
    return decorator


def require_authentication(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")

        if scheme.lower() != "bearer" or not token:
            audit_event("authentication_rejected", "failure", path=request.path, method=request.method)
            return jsonify({"error": "Unauthorized"}), 401

        try:
            claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                issuer="securebank-lab",
                audience="securebank-api",
                options={"require": ["sub", "iat", "exp", "iss", "aud"]},
            )
        except (jwt.InvalidTokenError, ValueError):
            audit_event("authentication_rejected", "failure", path=request.path, method=request.method)
            return jsonify({"error": "Unauthorized"}), 401

        username = claims.get("sub")

        if username not in USERS:
            audit_event("authentication_rejected", "failure", path=request.path, method=request.method)
            return jsonify({"error": "Unauthorized"}), 401

        request.authenticated_user = username
        return handler(*args, **kwargs)

    return wrapper


@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        audit_event("login_attempt", "failure", username="invalid")
        return jsonify({"error": "Invalid credentials"}), 401

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        audit_event("login_attempt", "failure", username=username if isinstance(username, str) else "invalid")
        return jsonify({"error": "Invalid credentials"}), 401

    user = USERS.get(username)

    if not user or not check_password_hash(user["password_hash"], password):
        audit_event("login_attempt", "failure", username=username)
        return jsonify({"error": "Invalid credentials"}), 401

    audit_event("login_attempt", "success", username=username)
    return jsonify({"access_token": create_token(username)}), 200


@app.route("/api/accounts/<int:account_id>", methods=["GET"])
@limiter.limit("30 per minute")
@require_authentication
def get_account(account_id):
    username = request.authenticated_user
    account = ACCOUNTS.get(account_id)

    if account is None:
        audit_event("account_access", "not_found", username=username, account_id=account_id)
        return jsonify({"error": "Account not found"}), 404

    # Object-level authorization: authentication alone is not enough.
    if account["owner"] != username:
        audit_event("account_access", "denied", username=username, account_id=account_id)
        return jsonify({"error": "Forbidden"}), 403

    audit_event("account_access", "success", username=username, account_id=account_id)
    return jsonify({
        "account_id": account_id,
        "owner": account["owner"],
        "balance": account["balance"],
    }), 200


@app.route("/api/admin/health", methods=["GET"])
@limiter.limit("30 per minute")
@require_authentication
@require_role("admin")
def admin_health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
