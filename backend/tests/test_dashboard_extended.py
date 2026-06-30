from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user
from app.api.dashboard import (
    _worst_pqc_status,
    clear_dashboard_cache,
    get_summary,
    get_risk_distribution,
    get_progress,
    get_layer_coverage,
)


app = create_app()
mock_user = SimpleNamespace(
    id="11111111-1111-1111-1111-111111111111",
    email="a@b.c",
    role="admin",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_user


@pytest.fixture(autouse=True)
def mock_dashboard_redis():
    """Avoid real Redis connections in dashboard endpoint tests."""
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value=None)
    fake_cache.set = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=AsyncMock())
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        yield


@pytest.fixture
def mock_db():
    session = AsyncMock()
    from app.db import get_session
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


# --- _worst_pqc_status ---


def test_worst_pqc_status_empty():
    assert _worst_pqc_status([]) == "vulnerable"


def test_worst_pqc_status_only_none():
    assert _worst_pqc_status([None, "", None]) == "vulnerable"


def test_worst_pqc_status_only_hybrid():
    assert _worst_pqc_status(["hybrid"]) == "hybrid"


def test_worst_pqc_status_only_pqc_ready():
    assert _worst_pqc_status(["pqc_ready"]) == "pqc_ready"


def test_worst_pqc_status_only_safe():
    assert _worst_pqc_status(["safe"]) == "safe"


def test_worst_pqc_status_mixed_vulnerable_wins():
    assert _worst_pqc_status(["safe", "hybrid", "vulnerable", "pqc_ready"]) == "vulnerable"


def test_worst_pqc_status_mixed_no_vulnerable():
    assert _worst_pqc_status(["safe", "pqc_ready", "hybrid"]) == "hybrid"


def test_worst_pqc_status_mixed_pqc_ready_and_safe():
    assert _worst_pqc_status(["pqc_ready", "safe"]) == "pqc_ready"


def test_worst_pqc_status_all_none_filtered():
    assert _worst_pqc_status([None, None]) == "vulnerable"


def test_worst_pqc_status_unknown_value():
    assert _worst_pqc_status(["unknown_status"]) == "vulnerable"


# --- /summary with safe_count > 0 ---


def test_summary_safe_count(mock_db):
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(scalar_one=MagicMock(return_value=4))
        if call_count["n"] == 2:
            r = MagicMock()
            r.all = MagicMock(return_value=[
                ("a-0", "safe"),
                ("a-1", "safe"),
                ("a-2", "hybrid"),
                ("a-3", "pqc_ready"),
            ])
            return r
        if call_count["n"] == 3:
            return MagicMock(scalar_one=MagicMock(return_value=0))
        if call_count["n"] == 4:
            return MagicMock(scalar_one=MagicMock(return_value=0))
        if call_count["n"] == 5:
            return MagicMock(scalar_one=MagicMock(return_value=0))
        return MagicMock(scalar_one=MagicMock(return_value=0))

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["safe_count"] == 2
    assert body["hybrid_count"] == 1
    assert body["pqc_ready_count"] == 1
    assert body["vulnerable_count"] == 0
    assert body["total_assets"] == 4
    assert body["pqc_readiness_score"] == 100.0


# --- /risk-distribution with actual result iteration ---


def test_risk_distribution_iterates_severities(mock_db):
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.all = MagicMock(return_value=[
                ("Critical", 5),
                ("HIGH", 3),
                ("Medium", 8),
                ("low", 1),
                ("info", 2),
            ])
            return r
        r = MagicMock()
        r.all = MagicMock(return_value=[])
        return r

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/risk-distribution")
    assert resp.status_code == 200
    body = resp.json()
    assert body["critical"] == 5
    assert body["high"] == 3
    assert body["medium"] == 8
    assert body["low"] == 1
    assert body["info"] == 2


def test_risk_distribution_empty(mock_db):
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.all = MagicMock(return_value=[])
            return r
        r = MagicMock()
        r.all = MagicMock(return_value=[])
        return r

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/risk-distribution")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


# --- /progress with multiple scans and algorithm data ---


def test_progress_full_processing_loop(mock_db):
    now = datetime.now(timezone.utc)
    scans = [
        SimpleNamespace(id=f"scan-{i}", completed_at=now, created_at=now)
        for i in range(3)
    ]
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.scalars.return_value.all.return_value = scans
            return r
        if call_count["n"] == 2:
            r = MagicMock()
            r.all = MagicMock(return_value=[
                ("scan-0", "asset-a", "vulnerable"),
                ("scan-0", "asset-b", "hybrid"),
                ("scan-0", "asset-c", "pqc_ready"),
                ("scan-1", "asset-a", "vulnerable"),
                ("scan-1", "asset-b", "vulnerable"),
                ("scan-2", "asset-a", "safe"),
            ])
            return r
        r = MagicMock()
        r.all = MagicMock(return_value=[])
        return r

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/progress")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 3
    assert body[0]["scan_date"] == now.strftime("%Y-%m-%d")
    assert body[1]["scan_date"] == now.strftime("%Y-%m-%d")
    assert body[2]["scan_date"] == now.strftime("%Y-%m-%d")
    vuln_vals = {item["vulnerable"] for item in body}
    hyb_vals = {item["hybrid"] for item in body}
    pqc_vals = {item["pqc_ready"] for item in body}
    assert 1 in vuln_vals
    assert 2 in vuln_vals
    assert 1 in hyb_vals
    assert 1 in pqc_vals
    vuln_total = sum(item["vulnerable"] for item in body)
    hyb_total = sum(item["hybrid"] for item in body)
    pqc_total = sum(item["pqc_ready"] for item in body)
    assert vuln_total == 3
    assert hyb_total == 1
    assert pqc_total == 1


# --- /layer-coverage with various pqc_status values ---


def _make_asset(asset_id, asset_type, discovery_source=None, last_verified_at=None,
                pqc_status=None, risk_score=None, asset_metadata=None):
    return SimpleNamespace(
        id=asset_id,
        asset_type=asset_type,
        discovery_source=discovery_source,
        asset_metadata=asset_metadata or {},
        last_verified_at=last_verified_at,
        pqc_status=pqc_status,
        risk_score=risk_score,
    )


def test_layer_coverage_pqc_status_classification(mock_db):
    now = datetime.now(timezone.utc)
    assets = [
        _make_asset("a-1", "server", last_verified_at=now, pqc_status="vulnerable"),
        _make_asset("a-2", "server", last_verified_at=now, pqc_status="hybrid"),
        _make_asset("a-3", "server", last_verified_at=now, pqc_status="pqc_ready"),
        _make_asset("a-4", "server", last_verified_at=now, pqc_status=None),
    ]

    r = MagicMock()
    r.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = r
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    l1 = next(item for item in body["layers"] if item["layer_id"] == "L1")
    assert l1["total_assets"] == 4
    assert l1["scanned_assets"] == 4
    assert l1["vulnerable_assets"] == 1
    assert l1["hybrid_assets"] == 1
    assert l1["pqc_ready_assets"] == 1


def test_layer_coverage_risk_score_none(mock_db):
    now = datetime.now(timezone.utc)
    assets = [
        _make_asset("a-1", "server", last_verified_at=now, risk_score=None),
        _make_asset("a-2", "server", last_verified_at=now, risk_score=None),
    ]

    r = MagicMock()
    r.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = r
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    l1 = next(item for item in body["layers"] if item["layer_id"] == "L1")
    assert l1["risk_score_avg"] == 0.0


def test_layer_coverage_overall_coverage_pct_with_assets(mock_db):
    now = datetime.now(timezone.utc)
    assets = [
        _make_asset("a-1", "server", last_verified_at=now, risk_score=50),
        _make_asset("a-2", "server", last_verified_at=None, risk_score=30),
        _make_asset("a-3", "database", last_verified_at=now, risk_score=70),
    ]

    r = MagicMock()
    r.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = r
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall_coverage_pct"] > 0
    total = sum(item["total_assets"] for item in body["layers"])
    scanned = sum(item["scanned_assets"] for item in body["layers"])
    expected = round((scanned / total) * 100, 1) if total > 0 else 0.0
    assert body["overall_coverage_pct"] == expected


def test_layer_coverage_unmapped_asset_defaults_l1(mock_db):
    assets = [
        _make_asset("a-1", "mystery_type", discovery_source="mystery_source"),
    ]

    r = MagicMock()
    r.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = r
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    l1 = next(item for item in body["layers"] if item["layer_id"] == "L1")
    assert l1["total_assets"] == 1


def test_layer_coverage_unknown_layer_id_skipped(mock_db):
    """Assets mapped to a layer not in LAYER_DEFINITIONS are skipped (line 423)."""
    assets = [
        _make_asset("a-1", "server", last_verified_at=datetime.now(timezone.utc)),
    ]

    r = MagicMock()
    r.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = r

    with patch("app.api.dashboard._determine_layer_for_asset", return_value="UNKNOWN_LAYER"):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/layer-coverage")

    assert resp.status_code == 200
    body = resp.json()
    total = sum(item["total_assets"] for item in body["layers"])
    assert total == 0


# --- clear_dashboard_cache exception during scan/delete ---


def test_clear_dashboard_cache_scan_exception():
    fake_client = MagicMock()
    fake_client.scan = AsyncMock(side_effect=Exception("scan broke"))
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())


def test_clear_dashboard_cache_delete_exception():
    fake_client = MagicMock()
    fake_client.scan = AsyncMock(return_value=(0, ["pqc:dashboard:key1"]))
    fake_client.delete = AsyncMock(side_effect=Exception("delete broke"))
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())


def test_clear_dashboard_cache_get_client_exception():
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(side_effect=Exception("redis down"))
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())


# --- Direct async unit tests for dashboard endpoints (no TestClient) ---


def _make_counting_session(results):
    """Return an AsyncMock session whose execute() yields results in order.

    results is a list of callables or values.  Each value is returned from
    execute(); if it is callable it is called with no arguments to get the
    return value.
    """
    session = AsyncMock()
    calls = {"n": 0}

    async def _execute(stmt):
        calls["n"] += 1
        idx = calls["n"] - 1
        value = results[idx] if idx < len(results) else MagicMock()
        return value() if callable(value) else value

    session.execute = _execute
    return session


@pytest.mark.asyncio
async def test_get_summary_direct():
    def total_assets_result():
        r = MagicMock()
        r.scalar_one = MagicMock(return_value=4)
        return r

    def pairs_result():
        r = MagicMock()
        r.all = MagicMock(return_value=[
            ("a-0", "safe"),
            ("a-1", "vulnerable"),
            ("a-2", "hybrid"),
            ("a-3", "pqc_ready"),
        ])
        return r

    def zero_result():
        r = MagicMock()
        r.scalar_one = MagicMock(return_value=0)
        return r

    session = _make_counting_session([
        total_assets_result,
        pairs_result,
        zero_result,
        zero_result,
        zero_result,
    ])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()) as mock_set:
            result = await get_summary(session, mock_user)

    assert result["total_assets"] == 4
    assert result["safe_count"] == 1
    assert result["vulnerable_count"] == 1
    assert result["hybrid_count"] == 1
    assert result["pqc_ready_count"] == 1
    assert result["pqc_readiness_score"] == 75.0
    mock_set.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_risk_distribution_direct():
    def dist_result():
        r = MagicMock()
        r.all = MagicMock(return_value=[
            ("critical", 5),
            ("high", 3),
            ("medium", 8),
            ("low", 1),
            ("info", 2),
        ])
        return r

    session = _make_counting_session([dist_result])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()) as mock_set:
            result = await get_risk_distribution(session, mock_user)

    assert result == {"critical": 5, "high": 3, "medium": 8, "low": 1, "info": 2}
    mock_set.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_progress_direct():
    now = datetime.now(timezone.utc)
    scans = [
        SimpleNamespace(id=f"scan-{i}", completed_at=now, created_at=now)
        for i in range(3)
    ]

    def scans_result():
        r = MagicMock()
        r.scalars.return_value.all.return_value = scans
        return r

    def algo_result():
        r = MagicMock()
        r.all = MagicMock(return_value=[
            ("scan-0", "asset-a", "vulnerable"),
            ("scan-0", "asset-b", "hybrid"),
            ("scan-0", "asset-c", "pqc_ready"),
            ("scan-1", "asset-a", "vulnerable"),
            ("scan-1", "asset-b", "vulnerable"),
            ("scan-2", "asset-a", "safe"),
        ])
        return r

    session = _make_counting_session([scans_result, algo_result])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()) as mock_set:
            result = await get_progress(session, mock_user)

    assert len(result) == 3
    assert all(item["scan_date"] == now.strftime("%Y-%m-%d") for item in result)
    assert sum(item["vulnerable"] for item in result) == 3
    assert sum(item["hybrid"] for item in result) == 1
    assert sum(item["pqc_ready"] for item in result) == 1
    mock_set.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_layer_coverage_direct():
    now = datetime.now(timezone.utc)

    def assets_result():
        r = MagicMock()
        r.scalars.return_value.all.return_value = [
            SimpleNamespace(
                id="a-1",
                asset_type="server",
                discovery_source=None,
                asset_metadata={},
                last_verified_at=now,
                pqc_status="vulnerable",
                risk_score=50,
            ),
            SimpleNamespace(
                id="a-2",
                asset_type="database",
                discovery_source=None,
                asset_metadata={},
                last_verified_at=now,
                pqc_status="hybrid",
                risk_score=70,
            ),
            SimpleNamespace(
                id="a-3",
                asset_type="unknown",
                discovery_source=None,
                asset_metadata={"provider": "kms"},
                last_verified_at=None,
                pqc_status=None,
                risk_score=None,
            ),
        ]
        return r

    session = _make_counting_session([assets_result])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()) as mock_set:
            result = await get_layer_coverage(session, mock_user)

    layers = {layer["layer_id"]: layer for layer in result["layers"]}
    assert layers["L1"]["total_assets"] == 1
    assert layers["L1"]["vulnerable_assets"] == 1
    assert layers["L5"]["total_assets"] == 1
    assert layers["L5"]["hybrid_assets"] == 1
    assert layers["L3"]["total_assets"] == 1
    assert layers["L3"]["scanned_assets"] == 0
    assert result["overall_coverage_pct"] > 0
    mock_set.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_layer_coverage_cache_hit():
    cached = {"layers": [], "overall_coverage_pct": 0.0}
    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=cached)):
        result = await get_layer_coverage(AsyncMock(), mock_user)
    assert result is cached


@pytest.mark.asyncio
async def test_get_layer_coverage_unmapped_branches():
    now = datetime.now(timezone.utc)

    def assets_result():
        r = MagicMock()
        r.scalars.return_value.all.return_value = [
            # discovered by source
            SimpleNamespace(
                id="a-1", asset_type="unknown", discovery_source="database",
                asset_metadata={}, last_verified_at=now, pqc_status="pqc_ready", risk_score=10,
            ),
            # metadata provider hint
            SimpleNamespace(
                id="a-2", asset_type="unknown", discovery_source=None,
                asset_metadata={"provider": "kubernetes"}, last_verified_at=now, pqc_status=None, risk_score=20,
            ),
            # metadata key_type hsm/kms hint
            SimpleNamespace(
                id="a-3", asset_type="unknown", discovery_source=None,
                asset_metadata={"key_type": "cloud_hsm"}, last_verified_at=now, pqc_status=None, risk_score=30,
            ),
            # completely unknown -> should be skipped by counts.get (line 423)
            SimpleNamespace(
                id="a-4", asset_type="totally_unknown", discovery_source=None,
                asset_metadata={}, last_verified_at=now, pqc_status=None, risk_score=None,
            ),
        ]
        return r

    session = _make_counting_session([assets_result])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()):
            result = await get_layer_coverage(session, mock_user)

    layers = {layer["layer_id"]: layer for layer in result["layers"]}
    assert layers["L5"]["total_assets"] == 1
    assert layers["L5"]["pqc_ready_assets"] == 1
    assert layers["L4"]["total_assets"] == 1
    assert layers["L3"]["total_assets"] == 1


# --- clear_dashboard_cache remaining branches ---


def test_clear_dashboard_cache_no_client():
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=None)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())


def test_clear_dashboard_cache_successful_clear():
    fake_client = MagicMock()
    fake_client.scan = AsyncMock(return_value=(0, ["pqc:dashboard:key1", "pqc:dashboard:key2"]))
    fake_client.delete = AsyncMock()
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())
    fake_client.delete.assert_awaited_once()


# --- cache-hit paths for remaining endpoints ---


@pytest.mark.asyncio
async def test_get_summary_cache_hit():
    cached = {"total_assets": 1}
    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=cached)):
        result = await get_summary(AsyncMock(), mock_user)
    assert result is cached


@pytest.mark.asyncio
async def test_get_risk_distribution_cache_hit():
    cached = {"critical": 1}
    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=cached)):
        result = await get_risk_distribution(AsyncMock(), mock_user)
    assert result is cached


@pytest.mark.asyncio
async def test_get_progress_cache_hit():
    cached = [{"scan_date": "2026-06-30"}]
    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=cached)):
        result = await get_progress(AsyncMock(), mock_user)
    assert result is cached


@pytest.mark.asyncio
async def test_get_progress_no_scans():
    def scans_result():
        r = MagicMock()
        r.scalars.return_value.all.return_value = []
        return r

    session = _make_counting_session([scans_result])

    with patch("app.api.dashboard.get_cache", new=AsyncMock(return_value=None)):
        with patch("app.api.dashboard.set_cache", new=AsyncMock()) as mock_set:
            result = await get_progress(session, mock_user)

    assert result == []
    mock_set.assert_awaited_once()
