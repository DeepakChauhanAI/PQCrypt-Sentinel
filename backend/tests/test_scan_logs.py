import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


NOW = datetime.now(timezone.utc)


def _scan_row(scan_id: str = "33333333-3333-3333-3333-333333333333"):
    return SimpleNamespace(
        id=scan_id,
        scan_type="tls_only",
        target="example.com",
        status="completed",
    )


def _scan_log_row(
    log_id: str = "44444444-4444-4444-4444-444444444444",
    scan_id: str = "33333333-3333-3333-3333-333333333333",
):
    return SimpleNamespace(
        id=log_id,
        scan_id=scan_id,
        level="info",
        phase="discovery",
        message="Scan started",
        details=None,
        timestamp=NOW,
    )


def _make_scalar_one_or_none(value):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    return r


def _make_scalars_all(items):
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    return r


@pytest.fixture
def mock_db():
    from app.db import get_session
    from app.main import app

    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def auth_user():
    from app.api.auth import get_current_user
    from app.main import app

    user = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        email="analyst@pqc.local",
        role="analyst",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def client(auth_user):
    from app.main import app
    with TestClient(app) as c:
        yield c


SCAN_ID = "33333333-3333-3333-3333-333333333333"


class TestCreateScanLog:
    def test_create_scan_log_success(self, mock_db, client):
        scan = _scan_row()
        log = _scan_log_row()

        call_count = {"n": 0}

        async def _execute(stmt):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _make_scalar_one_or_none(scan)
            return _make_scalar_one_or_none(log)

        mock_db.execute.side_effect = _execute

        async def _refresh(obj):
            obj.id = "44444444-4444-4444-4444-444444444444"
            obj.timestamp = NOW

        mock_db.refresh = AsyncMock(side_effect=_refresh)

        resp = client.post(
            f"/api/v1/scans/{SCAN_ID}/logs",
            json={"level": "INFO", "message": "Scan started", "phase": "discovery"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["message"] == "Scan started"
        assert body["level"] == "info"

    def test_create_scan_log_scan_not_found(self, mock_db, client):
        mock_db.execute.return_value = _make_scalar_one_or_none(None)
        resp = client.post(
            f"/api/v1/scans/{SCAN_ID}/logs",
            json={"level": "INFO", "message": "test"},
        )
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Scan not found"


class TestListScanLogs:
    def test_list_scan_logs_success(self, mock_db, client):
        scan = _scan_row()
        logs = [_scan_log_row(log_id=f"log-{i}") for i in range(3)]

        call_count = {"n": 0}

        async def _execute(stmt):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _make_scalar_one_or_none(scan)
            return _make_scalars_all(logs)

        mock_db.execute.side_effect = _execute

        resp = client.get(f"/api/v1/scans/{SCAN_ID}/logs")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 3

    def test_list_scan_logs_scan_not_found(self, mock_db, client):
        mock_db.execute.return_value = _make_scalar_one_or_none(None)
        resp = client.get(f"/api/v1/scans/{SCAN_ID}/logs")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Scan not found"
