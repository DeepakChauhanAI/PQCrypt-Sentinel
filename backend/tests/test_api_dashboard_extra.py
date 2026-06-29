"""
Additional tests for `app.api.dashboard`:
- cache helpers (get_cache, set_cache, clear_dashboard_cache)
- _determine_layer_for_asset with various asset types and metadata
- layer-coverage with assets that have risk_score
- summary with cache hit
- risk-distribution with cache hit
- progress with completed_at=None fallback
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user
from app.api.dashboard import (
    ASSET_TO_LAYER,
    LAYER_DEFINITIONS,
    _determine_layer_for_asset,
    clear_dashboard_cache,
    get_cache,
    set_cache,
)


app = create_app()
mock_user = SimpleNamespace(
    id="11111111-1111-1111-1111-111111111111",
    email="a@b.c",
    role="admin",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_user


@pytest.fixture
def mock_db():
    session = AsyncMock()
    from app.db import get_session
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


# ------------------- cache helpers --------------------


def test_get_cache_returns_value():
    """get_cache delegates to RedisCache.get with the prefix."""
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value={"x": 1})
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        out = asyncio.run(get_cache("summary"))
    assert out == {"x": 1}
    fake_cache.get.assert_called_once()
    call_arg = fake_cache.get.call_args[0][0]
    assert call_arg.startswith("dashboard:")


def test_set_cache_calls_redis():
    """set_cache delegates to RedisCache.set with prefix and TTL."""
    fake_cache = AsyncMock()
    fake_cache.set = AsyncMock()
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(set_cache("summary", {"a": 1}, ttl=60))
    fake_cache.set.assert_called_once()
    args = fake_cache.set.call_args
    assert args[0][0].startswith("dashboard:")
    assert args[0][1] == {"a": 1}
    assert args[1]["ttl"] == 60


def test_clear_dashboard_cache_no_client():
    """When the cache client can't be obtained, clear is a no-op."""
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(side_effect=Exception("no redis"))
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())  # should not raise


def test_clear_dashboard_cache_client_none():
    """When _get_client returns None, clear is a no-op."""
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=None)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())  # should not raise


def test_clear_dashboard_cache_deletes_keys():
    """When client returns keys, delete is called for them."""
    fake_client = MagicMock()
    fake_client.scan = AsyncMock(side_effect=[(1, ["pqc:dashboard:x"]), (0, [])])
    fake_client.delete = AsyncMock()
    fake_cache = AsyncMock()
    fake_cache._get_client = AsyncMock(return_value=fake_client)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        import asyncio
        asyncio.run(clear_dashboard_cache())
    fake_client.delete.assert_called_once_with("pqc:dashboard:x")


# ------------------- _determine_layer_for_asset --------------------


def _asset(asset_type=None, discovery_source=None, asset_metadata=None,
           last_verified_at=None, pqc_status=None, risk_score=None):
    return SimpleNamespace(
        asset_type=asset_type,
        discovery_source=discovery_source,
        asset_metadata=asset_metadata,
        last_verified_at=last_verified_at,
        pqc_status=pqc_status,
        risk_score=risk_score,
    )


def test_determine_layer_by_asset_type():
    """Asset type takes priority over discovery_source."""
    a = _asset(asset_type="database")
    assert _determine_layer_for_asset(a) == "L5"


def test_determine_layer_by_discovery_source():
    """Falls back to discovery_source when asset_type is unknown."""
    a = _asset(asset_type="unknown", discovery_source="ct_log")
    assert _determine_layer_for_asset(a) == "L2"


def test_determine_layer_by_metadata_provider():
    """Metadata provider field is used as a fallback hint."""
    a = _asset(asset_type="", discovery_source="", asset_metadata={"provider": "aws_kms"})
    assert _determine_layer_for_asset(a) == "L3"


def test_determine_layer_by_metadata_key_type_hsm():
    """Metadata key_type='hsm' maps to L3."""
    a = _asset(asset_type="", discovery_source="", asset_metadata={"key_type": "hsm"})
    assert _determine_layer_for_asset(a) == "L3"


def test_determine_layer_by_metadata_key_type_kms():
    """Metadata key_type='kms' maps to L3."""
    a = _asset(asset_type="", discovery_source="", asset_metadata={"key_type": "kms"})
    assert _determine_layer_for_asset(a) == "L3"


def test_determine_layer_default_l1():
    """Unknown asset type defaults to L1."""
    a = _asset(asset_type="mystery", discovery_source="mystery")
    assert _determine_layer_for_asset(a) == "L1"


def test_determine_layer_metadata_not_dict():
    """Non-dict asset_metadata is gracefully ignored."""
    a = _asset(asset_type="mystery", discovery_source="mystery", asset_metadata="not a dict")
    assert _determine_layer_for_asset(a) == "L1"


def test_determine_layer_asset_type_case_insensitive():
    """Asset type lookup is case-insensitive."""
    a = _asset(asset_type="DATABASE")
    assert _determine_layer_for_asset(a) == "L5"


# ------------------- /summary cache hit --------------------


def test_summary_cache_hit_returns_cached(mock_db):
    """If the cache has a value, no SQL is executed and the cached value is returned."""
    cached_value = {
        "pqc_readiness_score": 88.0,
        "total_assets": 100,
        "vulnerable_count": 5,
        "hybrid_count": 7,
        "pqc_ready_count": 88,
        "critical_findings": 1,
        "high_findings": 2,
        "drift_alerts_count": 0,
    }
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value=cached_value)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200
    assert resp.json() == cached_value


# ------------------- /risk-distribution cache hit --------------------


def test_risk_distribution_cache_hit(mock_db):
    cached = {"critical": 9, "high": 8, "medium": 7, "low": 6, "info": 5}
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value=cached)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/risk-distribution")
    assert resp.status_code == 200
    assert resp.json() == cached


# ------------------- /progress cache hit --------------------


def test_progress_cache_hit(mock_db):
    cached = [{"scan_date": "2026-01-01", "vulnerable": 1, "hybrid": 0, "pqc_ready": 2}]
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value=cached)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/progress")
    assert resp.status_code == 200
    assert resp.json() == cached


def test_progress_with_completed_at_none(mock_db):
    """Falls back to created_at when completed_at is None."""
    now = datetime.now(timezone.utc)
    scans = [
        SimpleNamespace(id="s-1", completed_at=None, created_at=now),
    ]
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.scalars.return_value.all.return_value = scans
            return r
        return MagicMock(all=MagicMock(return_value=[]))

    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/progress")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["scan_date"] == now.strftime("%Y-%m-%d")


# ------------------- /layer-coverage with risk scores --------------------


def test_layer_coverage_with_risk_scores(mock_db):
    """Assets with risk_scores contribute to per-layer risk_score_avg."""
    def _execute(stmt):
        # First call returns all assets
        r = MagicMock()
        assets = [
            SimpleNamespace(
                id="a-1", asset_type="server", discovery_source="tls_scan",
                asset_metadata={}, last_verified_at=datetime.now(timezone.utc),
                pqc_status="vulnerable", risk_score=80,
            ),
            SimpleNamespace(
                id="a-2", asset_type="database", discovery_source=None,
                asset_metadata={}, last_verified_at=datetime.now(timezone.utc),
                pqc_status=None, risk_score=20,
            ),
        ]
        r.scalars.return_value.all.return_value = assets
        return r
    mock_db.execute.side_effect = _execute
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    # L1 has 1 asset (server), L5 has 1 (database)
    l1 = next(item for item in body["layers"] if item["layer_id"] == "L1")
    l5 = next(item for item in body["layers"] if item["layer_id"] == "L5")
    assert l1["total_assets"] == 1
    assert l1["risk_score_avg"] == 80.0
    assert l5["total_assets"] == 1
    assert l5["risk_score_avg"] == 20.0


def test_layer_coverage_overall_calculation(mock_db):
    """overall_coverage_pct is the mean of per-layer coverage_pcts."""
    r = MagicMock()
    r.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = r
    client = TestClient(app)
    resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    body = resp.json()
    # No assets => every layer's coverage_pct is 0, overall is 0
    assert body["overall_coverage_pct"] == 0


def test_layer_coverage_cache_hit(mock_db):
    """If cache is populated, no SQL is executed."""
    cached = {
        "layers": [{"layer_id": "L1", "layer_name": "Network", "description": "x",
                    "total_assets": 0, "scanned_assets": 0, "vulnerable_assets": 0,
                    "hybrid_assets": 0, "pqc_ready_assets": 0, "coverage_pct": 0,
                    "risk_score_avg": 0}],
        "overall_coverage_pct": 0,
    }
    fake_cache = AsyncMock()
    fake_cache.get = AsyncMock(return_value=cached)
    with patch("app.api.dashboard.get_redis_cache", new=AsyncMock(return_value=fake_cache)):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/layer-coverage")
    assert resp.status_code == 200
    assert resp.json() == cached


# ------------------- Layer definitions --------------------


def test_layer_definitions_contains_seven_layers():
    """LAYER_DEFINITIONS has L1..L7 in order."""
    ids = [layer["id"] for layer in LAYER_DEFINITIONS]
    assert ids == ["L1", "L2", "L3", "L4", "L5", "L6", "L7"]


def test_asset_to_layer_completeness():
    """ASSET_TO_LAYER has at least one entry per layer."""
    layers_used = set(ASSET_TO_LAYER.values())
    assert layers_used == {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}
