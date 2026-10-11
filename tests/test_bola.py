import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from werkzeug.security import generate_password_hash

# Test-only credentials; never use these in a deployed environment.
os.environ["USER_A_PASSWORD_HASH"] = generate_password_hash("LabPass-A-Only")
os.environ["USER_B_PASSWORD_HASH"] = generate_password_hash("LabPass-B-Only")

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "application")
)

from app import app, create_token, JWT_SECRET, JWT_ALGORITHM


def test_user_can_access_own_account():
    client = app.test_client()
    token = create_token("user-a")

    response = client.get(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.get_json()["owner"] == "user-a"


def test_user_cannot_access_another_users_account():
    client = app.test_client()
    token = create_token("user-a")

    response = client.get(
        "/api/accounts/202",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_missing_token_is_rejected():
    response = app.test_client().get("/api/accounts/101")

    assert response.status_code == 401


def test_tampered_token_is_rejected():
    client = app.test_client()
    token = create_token("user-a")
    parts = token.split(".")

    parts[1] = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    tampered_token = ".".join(parts)

    response = client.get(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )

    assert response.status_code == 401


def test_expired_token_is_rejected():
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": "user-a",
            "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=5),
            "iss": "securebank-lab",
            "aud": "securebank-api",
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    response = app.test_client().get(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_login_returns_access_token():
    response = app.test_client().post(
        "/api/login",
        json={"username": "user-a", "password": "LabPass-A-Only"},
    )

    assert response.status_code == 200
    assert "access_token" in response.get_json()


def test_invalid_login_is_rejected():
    response = app.test_client().post(
        "/api/login",
        json={"username": "user-a", "password": "wrong-password"},
    )

    assert response.status_code == 401


def test_users_store_password_hashes_not_plaintext_passwords():
    from app import USERS

    for user in USERS.values():
        assert "password_hash" in user
        assert "password" not in user


def test_login_rejects_missing_password():
    response = app.test_client().post(
        "/api/login",
        json={"username": "user-a"},
    )

    assert response.status_code == 401


def test_login_rejects_null_password():
    response = app.test_client().post(
        "/api/login",
        json={"username": "user-a", "password": None},
    )

    assert response.status_code == 401


def test_login_rejects_non_string_password():
    client = app.test_client()

    for password in [12345, ["LabPass-A-Only"], {"value": "LabPass-A-Only"}]:
        response = client.post(
            "/api/login",
            json={"username": "user-a", "password": password},
        )

        assert response.status_code == 401


def test_login_rejects_non_string_usernames():
    client = app.test_client()

    for username in [None, 123, ["user-a"], {"name": "user-a"}]:
        response = client.post(
            "/api/login",
            json={"username": username, "password": "LabPass-A-Only"},
        )

        assert response.status_code == 401


def test_login_rejects_non_object_json():
    client = app.test_client()

    for payload in [[], "user-a", 123, None]:
        response = client.post("/api/login", json=payload)

        assert response.status_code == 401


def test_token_with_wrong_issuer_is_rejected():
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": "user-a",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "iss": "untrusted-issuer",
            "aud": "securebank-api",
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    response = app.test_client().get(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_token_with_wrong_audience_is_rejected():
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": "user-a",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "iss": "securebank-lab",
            "aud": "different-api",
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    response = app.test_client().get(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_empty_bearer_token_is_rejected():
    response = app.test_client().get(
        "/api/accounts/101",
        headers={"Authorization": "Bearer "},
    )

    assert response.status_code == 401


def test_basic_auth_scheme_is_rejected():
    response = app.test_client().get(
        "/api/accounts/101",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )

    assert response.status_code == 401


def test_malformed_authorization_header_is_rejected():
    client = app.test_client()

    for header in ["invalid-header", "Bearer", "Bearer token extra"]:
        response = client.get(
            "/api/accounts/101",
            headers={"Authorization": header},
        )

        assert response.status_code == 401
