import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "application")
)

from app import app


def test_user_can_access_own_account():
    client = app.test_client()

    response = client.get(
        "/api/accounts/101",
        headers={"Authorization": "Bearer user-a-demo-token"},
    )

    assert response.status_code == 200
    assert response.get_json()["owner"] == "user-a"


def test_user_cannot_access_another_users_account():
    client = app.test_client()

    response = client.get(
        "/api/accounts/202",
        headers={"Authorization": "Bearer user-a-demo-token"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Forbidden"


def test_unauthenticated_user_cannot_access_account():
    client = app.test_client()

    response = client.get("/api/accounts/101")

    assert response.status_code == 401
