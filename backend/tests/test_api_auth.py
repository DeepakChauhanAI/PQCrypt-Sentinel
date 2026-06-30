"""
Tests for `app.api.auth` - login / refresh / logout / me endpoints.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user


app = create_app()


def _user_row(
    user_id: str = "11111111-1111-1111-1111-111111111111",
    email: str = "user@pqc.local",
    is_active: bool = True,
    password_hash: str | None = "$2b$12$fakehashfakehashfakehash.fakehashvalue",
):
    return SimpleNamespace(
        id=user_id,
        email=email,
        full_name="Test User",
        role="analyst",
        is_active=is_active,
        password_hash=password_hash,
        last_login_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        deleted_at=None,
    )


def _scalar_one_or_none(value):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    return r


@pytest.fixture
def mock_db():
    session = AsyncMock()
    from app.db import get_session

    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def auth_user():
    user = _user_row()
    app.dependency_overrides[get_current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(get_current_user, None)


# -------------------------------------------------- POST /auth/login ---


def test_login_success(mock_db):
    user = _user_row()
    mock_db.execute.return_value = _scalar_one_or_none(user)

    with patch("app.api.auth.verify_password", return_value=True):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@pqc.local",
                "password": "correct-password",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body


def test_login_invalid_email(mock_db):
    """No user found -> 401."""
    mock_db.execute.return_value = _scalar_one_or_none(None)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "email": "nope@pqc.local",
            "password": "x",
        },
    )
    assert resp.status_code == 401
    assert "Invalid" in resp.json()["detail"]


def test_login_wrong_password(mock_db):
    user = _user_row()
    mock_db.execute.return_value = _scalar_one_or_none(user)
    with patch("app.api.auth.verify_password", return_value=False):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@pqc.local",
                "password": "wrong",
            },
        )
    assert resp.status_code == 401


def test_login_disabled_account(mock_db):
    user = _user_row(is_active=False)
    mock_db.execute.return_value = _scalar_one_or_none(user)
    with patch("app.api.auth.verify_password", return_value=True):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@pqc.local",
                "password": "correct",
            },
        )
    assert resp.status_code == 401
    assert "Disabled" in resp.json()["detail"]


# ---------------------------------------------- POST /auth/refresh ----


def test_refresh_invalid_token_returns_401(mock_db):
    with patch("app.api.auth.decode_token", return_value=None):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "bad"})
    assert resp.status_code == 401


def test_refresh_wrong_token_type_returns_401(mock_db):
    fake_decoded = SimpleNamespace(type="access", jti="xxx", sub="y", exp=None)
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x"})
    assert resp.status_code == 401


def test_refresh_revoked_token_returns_401(mock_db):
    fake_decoded = SimpleNamespace(type="refresh", jti="xxx", sub="user-id", exp=None)
    stored = SimpleNamespace(
        revoked=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(stored)
        return _scalar_one_or_none(None)

    mock_db.execute.side_effect = _execute
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x"})
    assert resp.status_code == 401


def test_refresh_expired_token_returns_401(mock_db):
    fake_decoded = SimpleNamespace(type="refresh", jti="xxx", sub="user-id", exp=None)
    stored = SimpleNamespace(
        revoked=False,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),  # expired
    )
    mock_db.execute.return_value = _scalar_one_or_none(stored)
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x"})
    assert resp.status_code == 401


def test_refresh_success(mock_db):
    """Happy path: stored token found, user found, active -> new tokens."""
    fake_decoded_old = SimpleNamespace(
        type="refresh", jti="old-jti", sub="user-id", exp=None
    )
    fake_decoded_new = SimpleNamespace(
        type="refresh", jti="new-jti", sub="user-id", exp=None
    )
    user = _user_row()
    stored = SimpleNamespace(
        revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(stored)
        if call_count["n"] == 2:
            return _scalar_one_or_none(user)
        return _scalar_one_or_none(None)

    mock_db.execute.side_effect = _execute
    with patch(
        "app.api.auth.decode_token", side_effect=[fake_decoded_old, fake_decoded_new]
    ):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["refresh_token"]  # new refresh token
    assert stored.revoked is True


def test_refresh_user_disabled(mock_db):
    fake_decoded = SimpleNamespace(type="refresh", jti="xxx", sub="user-id", exp=None)
    stored = SimpleNamespace(
        revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    user = _user_row(is_active=False)
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_one_or_none(stored)
        if call_count["n"] == 2:
            return _scalar_one_or_none(user)
        return _scalar_one_or_none(None)

    mock_db.execute.side_effect = _execute
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "x"})
    assert resp.status_code == 401


# ---------------------------------------------- POST /auth/logout ----


def test_logout_with_no_token_returns_200(mock_db):
    """Logout with no token parameter is a no-op success."""
    client = TestClient(app)
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 200
    assert resp.json() == {"detail": "Logged out"}


def test_logout_with_valid_token_revokes(mock_db):
    fake_decoded = SimpleNamespace(
        type="refresh", jti="my-jti", sub="user-id", exp=None
    )
    stored = SimpleNamespace(revoked=False)
    mock_db.execute.return_value = _scalar_one_or_none(stored)
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/logout?refresh_token=valid-token")
    assert resp.status_code == 200
    assert stored.revoked is True


def test_logout_with_already_revoked_token(mock_db):
    """Logout of an already-revoked token is a no-op."""
    fake_decoded = SimpleNamespace(
        type="refresh", jti="my-jti", sub="user-id", exp=None
    )
    stored = SimpleNamespace(revoked=True)
    mock_db.execute.return_value = _scalar_one_or_none(stored)
    with patch("app.api.auth.decode_token", return_value=fake_decoded):
        client = TestClient(app)
        resp = client.post("/api/v1/auth/logout?refresh_token=valid-token")
    assert resp.status_code == 200


# ---------------------------------------------- GET /auth/me --------


def test_get_me_returns_user(auth_user):
    client = TestClient(app)
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == auth_user.email
    assert body["id"] == auth_user.id
