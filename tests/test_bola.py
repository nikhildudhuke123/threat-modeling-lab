import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from werkzeug.security import generate_password_hash

# Test-only credentials; never use these in a deployed environment.
os.environ["USER_A_PASSWORD_HASH"] = generate_password_hash("LabPass-A-Only")
os.environ["USER_B_PASSWORD_HASH"] = generate_password_hash("LabPass-B-Only")

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "application")
)

from app import app, create_token, JWT_SECRET, JWT_ALGORITHM

@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Keep rate-limit state isolated between tests."""
    for limiter in app.extensions["limiter"]:
        limiter._storage.reset()
    yield
    for limiter in app.extensions["limiter"]:
        limiter._storage.reset()



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


def test_post_to_get_only_account_endpoint_is_rejected():
    token = create_token("user-a")

    response = app.test_client().post(
        "/api/accounts/101",
        headers={"Authorization": f"Bearer {token}"},
        json={"balance": 999999},
    )

    assert response.status_code == 405


def test_unknown_account_returns_404():
    token = create_token("user-a")

    response = app.test_client().get(
        "/api/accounts/999",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert response.get_json()["error"] == "Account not found"


def test_successful_login_is_audited_without_credentials(caplog):
    import json
    import logging

    with caplog.at_level(logging.INFO, logger="securebank.audit"):
        response = app.test_client().post(
            "/api/login",
            json={"username": "user-a", "password": "LabPass-A-Only"},
        )

    assert response.status_code == 200
    records = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "securebank.audit"
    ]
    assert any(
        record["event"] == "login_attempt"
        and record["outcome"] == "success"
        and record["details"]["username"] == "user-a"
        for record in records
    )
    logged_text = "\n".join(record.message for record in caplog.records)
    assert "LabPass-A-Only" not in logged_text
    assert response.get_json()["access_token"] not in logged_text


def test_failed_login_is_audited(caplog):
    import json
    import logging

    with caplog.at_level(logging.INFO, logger="securebank.audit"):
        response = app.test_client().post(
            "/api/login",
            json={"username": "user-a", "password": "wrong-password"},
        )

    assert response.status_code == 401
    records = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "securebank.audit"
    ]
    assert any(
        record["event"] == "login_attempt"
        and record["outcome"] == "failure"
        and record["details"]["username"] == "user-a"
        for record in records
    )
    assert "wrong-password" not in "\n".join(
        record.message for record in caplog.records
    )


def test_cross_account_access_is_audited(caplog):
    import json
    import logging

    token = create_token("user-a")
    with caplog.at_level(logging.INFO, logger="securebank.audit"):
        response = app.test_client().get(
            "/api/accounts/202",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 403
    records = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "securebank.audit"
    ]
    assert any(
        record["event"] == "account_access"
        and record["outcome"] == "denied"
        and record["details"]["username"] == "user-a"
        and record["details"]["account_id"] == 202
        for record in records
    )
    assert token not in "\n".join(
        record.message for record in caplog.records
    )


def test_missing_token_rejection_is_audited(caplog):
    import json
    import logging

    with caplog.at_level(logging.INFO, logger="securebank.audit"):
        response = app.test_client().get("/api/accounts/101")

    assert response.status_code == 401
    records = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "securebank.audit"
    ]
    assert any(
        record["event"] == "authentication_rejected"
        and record["outcome"] == "failure"
        and record["details"]["path"] == "/api/accounts/101"
        for record in records
    )


def test_audit_event_persists_and_hash_chain_verifies(tmp_path, monkeypatch):
    import json
    import audit

    monkeypatch.setattr(audit, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(audit, "_LOG_FILE", tmp_path / "audit.log")

    audit.audit_event("test_event", "success", username="user-a")
    audit.audit_event("test_event", "failure", username="user-b")

    records = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().splitlines()
    ]
    assert len(records) == 2
    assert records[0]["event"] == "test_event"
    assert records[0]["details"]["username"] == "user-a"
    assert records[1]["previous_hash"] == records[0]["record_hash"]
    assert audit.verify_audit_log(tmp_path / "audit.log")


def test_audit_log_tampering_is_detected(tmp_path, monkeypatch):
    import json
    import audit

    monkeypatch.setattr(audit, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(audit, "_LOG_FILE", tmp_path / "audit.log")

    audit.audit_event("test_event", "success", username="user-a")
    log_path = tmp_path / "audit.log"
    record = json.loads(log_path.read_text().splitlines()[0])
    record["details"]["username"] = "user-b"
    log_path.write_text(json.dumps(record) + "\n")

    assert not audit.verify_audit_log(log_path)


def test_audit_log_file_has_restrictive_permissions(tmp_path, monkeypatch):
    import os
    import stat
    import audit

    monkeypatch.setattr(audit, "_LOG_DIR", tmp_path / "audit")
    monkeypatch.setattr(audit, "_LOG_FILE", tmp_path / "audit" / "audit.log")

    audit.audit_event("test_event", "success", username="user-a")

    mode = stat.S_IMODE(os.stat(tmp_path / "audit" / "audit.log").st_mode)
    assert mode == 0o600


def test_login_rate_limit_returns_429():
    from app import limiter

    client = app.test_client()
    for _ in range(5):
        response = client.post(
            "/api/login",
            json={"username": "user-a", "password": "wrong-password"},
        )
        assert response.status_code == 401

    response = client.post(
        "/api/login",
        json={"username": "user-a", "password": "wrong-password"},
    )
    assert response.status_code == 429


def test_account_rate_limit_returns_429():
    client = app.test_client()
    token = create_token("user-a")
    headers = {"Authorization": f"Bearer {token}"}

    for _ in range(30):
        response = client.get("/api/accounts/101", headers=headers)
        assert response.status_code == 200

    response = client.get("/api/accounts/101", headers=headers)
    assert response.status_code == 429
