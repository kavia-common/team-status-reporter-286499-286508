import os
import sys
from importlib import import_module

from fastapi.testclient import TestClient


def _fresh_app_with_env(tmp_db_path: str):
    """
    Import the FastAPI app with a fresh environment:
    - Uses SQLite file DB for isolation
    - Sets a test JWT secret
    Ensures modules are imported AFTER env is set so settings pick up new values.
    """
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db_path}"
    os.environ["JWT_SECRET"] = "test-secret"
    os.environ["ENV"] = "test"

    # Remove possibly cached modules to ensure settings are read from env
    for mod in list(sys.modules.keys()):
        if mod.startswith("src.api"):
            sys.modules.pop(mod)

    main = import_module("src.api.main")
    return main.app


def test_register_creates_user_and_returns_token(tmp_path):
    app = _fresh_app_with_env(str(tmp_path / "auth_test.db"))
    client = TestClient(app)

    payload = {
        "email": "new.user@example.com",
        "password": "supersecret",
        "display_name": "New User",
    }
    resp = client.post("/auth/register", json=payload)

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "access_token" in data and isinstance(data["access_token"], str)
    assert data.get("token_type") == "bearer"


def test_register_duplicate_email_returns_400(tmp_path):
    app = _fresh_app_with_env(str(tmp_path / "auth_test_dupe.db"))
    client = TestClient(app)

    payload = {
        "email": "dupe@example.com",
        "password": "somepassword",
    }

    first = client.post("/auth/register", json=payload)
    assert first.status_code == 201, first.text

    second = client.post("/auth/register", json=payload)
    assert second.status_code == 400, second.text
    assert "already" in second.json().get("detail", "").lower()
