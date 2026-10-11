import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

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
