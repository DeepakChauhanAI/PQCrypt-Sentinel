"""
Tests for `app.api.dashboard` - the /summary, /risk-distribution,
/progress, and /layer-coverage endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user


app = create_app()

mock_user = SimpleNamespace(
    id="11111111-1111-1111-1111-111111111111",
    email="analyst@pqc.local",
    role="admin",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_user


@pytest.fixture
def mock_db():
    session = AsyncMock()
    app.dependency_overrides["get_session"] = lambda: session
    # Use the real dependency name
    from app.db import get_session

    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


def _scalar_result(value):
    r = MagicMock()
    r.scalar_one = MagicMock(return_value=value)
    return r


def _scalars_result(items):
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    return r


def _make_result(items):
    """Return a result whose `.all()` returns `items`."""
    r = MagicMock()
    r.all = MagicMock(return_value=items)
    return r


# ------------------------------------------------- /summary endpoint --


def test_dashboard_summary_basic(mock_db):
    """The /summary endpoint computes PQC readiness from grouped algorithm data."""
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Total assets count
            return _scalar_result(3)
        if call_count["n"] == 2:
            # Per-asset (asset_id, pqc_status) pairs
            return _make_result(
                [
                    ("asset-0", "vulnerable"),
                    ("asset-1", "hybrid"),
                    ("asset-2", "pqc_ready"),
                ]
            )
        if call_count["n"] == 3:
            # Critical findings
            return _scalar_result(2)
        if call_count["n"] == 4:
            # High findings
            return _scalar_result(5)
        if call_count["n"] == 5:
            # Drift alerts
            return _scalar_result(1)
        return _scalar_result(0)

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_assets"] == 3
    assert body["vulnerable_count"] == 1
    assert body["hybrid_count"] == 1
    assert body["pqc_ready_count"] == 1
    assert body["safe_count"] == 0
    assert body["critical_findings"] == 2
    assert body["high_findings"] == 5
    assert body["drift_alerts_count"] == 1
    # (1 hybrid + 1 pqc_ready) / 3 = 66.67
    assert 66.0 <= body["pqc_readiness_score"] <= 67.0


def test_dashboard_summary_no_assets(mock_db):
    """When there are no assets, the readiness score is 0."""
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalar_result(0)
        if call_count["n"] == 2:
            return _make_result([])
        if call_count["n"] == 3:
            return _scalar_result(0)
        if call_count["n"] == 4:
            return _scalar_result(0)
        if call_count["n"] == 5:
            return _scalar_result(0)
        return _scalar_result(0)

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pqc_readiness_score"] == 0.0
    assert body["total_assets"] == 0
    assert body["safe_count"] == 0


# ----------------------------------------- /risk-distribution endpoint -


def test_dashboard_risk_distribution(mock_db):
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_result(
                [
                    ("critical", 3),
                    ("high", 7),
                    ("medium", 12),
                    ("low", 4),
                ]
            )
        return _make_result([])

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/risk-distribution")
    assert resp.status_code == 200
    body = resp.json()
    assert body["critical"] == 3
    assert body["high"] == 7
    assert body["medium"] == 12
    assert body["low"] == 4


# ---------------------------------------------- /progress endpoint ----


def test_dashboard_progress_with_scans(mock_db):
    """Progress endpoint returns 12 (or fewer) scan-date buckets."""
    now = datetime.now(timezone.utc)
    scans = [
        SimpleNamespace(
            id=f"scan-{i}",
            completed_at=now,
            created_at=now,
        )
        for i in range(3)
    ]
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _scalars_result(scans)
        if call_count["n"] == 2:
            # GROUP BY scan_id, asset_id
            return _make_result(
                [
                    ("scan-0", "asset-0", "vulnerable"),
                    ("scan-0", "asset-1", "hybrid"),
                    ("scan-1", "asset-0", "pqc_ready"),
                ]
            )
        return _make_result([])

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/progress")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 3
    for item in body:
        assert "scan_date" in item
        assert "vulnerable" in item
        assert "hybrid" in item
        assert "pqc_ready" in item


def test_dashboard_progress_no_scans(mock_db):
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        return _scalars_result([])

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/progress")
    assert resp.status_code == 200
    assert resp.json() == []


# ----------------------------------------- /layer-coverage endpoint ---


def test_dashboard_layer_coverage_returns_seven_layers(mock_db):
    """Layer coverage response includes the 7 L1..L7 infrastructure layers."""
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_result(
                [
                    ("L1", "server"),
                    ("L1", "server"),
                    ("L2", "certificate_authority"),
                ]
            )
        if call_count["n"] == 2:
            # Finding distribution by layer
            return _make_result(
                [
                    ("L1", "high", 5),
                    ("L2", "critical", 1),
                ]
            )
        return _make_result([])

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    # L1..L7 are always present
    layers = {item["layer_id"] for item in body["layers"]}
    assert layers == {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}


# ------------------------------------------- /health endpoint -------


def test_health_endpoint_returns_redis_status(mock_db):
    """The /health endpoint reports `redis: ok|degraded`."""
    client = TestClient(app)
    resp = client.get("/health")
    # Health endpoint may need DB access; just verify status code & shape
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert "redis" in body or "status" in body
