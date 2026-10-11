import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGORITHM = "HS256"

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

# Fictional users for this local security lab.
# Production applications must use securely stored password hashes.
USERS = {
    "user-a": {"password": "LabPass-A-Only", "role": "user"},
    "user-b": {"password": "LabPass-B-Only", "role": "user"},
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


def require_authentication(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")

        if scheme.lower() != "bearer" or not token:
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
            return jsonify({"error": "Unauthorized"}), 401

        username = claims.get("sub")

        if username not in USERS:
            return jsonify({"error": "Unauthorized"}), 401

        request.authenticated_user = username
        return handler(*args, **kwargs)

    return wrapper


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)

    if not user or password != user["password"]:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"access_token": create_token(username)}), 200


@app.route("/api/accounts/<int:account_id>", methods=["GET"])
@require_authentication
def get_account(account_id):
    username = request.authenticated_user
    account = ACCOUNTS.get(account_id)

    if account is None:
        return jsonify({"error": "Account not found"}), 404

    # Object-level authorization: authentication alone is not enough.
    if account["owner"] != username:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({
        "account_id": account_id,
        "owner": account["owner"],
        "balance": account["balance"],
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
