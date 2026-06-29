"""Tests for `app.api.assets` - list / get assets + scan-group enrichment.

The enrichment helpers on this module (added as part of the Phase B
correlation work) attach ``last_scan_group_id`` / ``last_scan_group_name``
and the matching ``first_scan_*`` pair to each Asset so the UI can render
"Last Scan Group" badges in the Assets page without a second round-trip
per row.

These tests pin:
  * the field-shape contract (the new fields are populated from the
    scan that the asset points at, falling through to None when there
    is no group),
  * the no-asset edge case (enrichment is a no-op),
  * the asset-without-scan-id case (no group lookup happens).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


# Helpers --------------------------------------------------------------------

def _asset_row(
    asset_id: str = "a-1",
    last_scan_id: str | None = "s-1",
    first_scan_id: str | None = "s-1",
):
    return SimpleNamespace(
        id=asset_id,
        name=f"asset-{asset_id}",
        asset_type="server",
        ip_address="10.0.0.1",
        fqdn=None,
        port=443,
        protocol="tcp",
        os=None,
        environment="production",
        business_service=None,
        owner_id=None,
        discovery_source="tls_scan",
        first_scan_id=first_scan_id,
        last_scan_id=last_scan_id,
        first_discovered_at="2026-06-18T00:00:00Z",
        last_verified_at="2026-06-18T00:00:00Z",
        asset_metadata={},
        created_at="2026-06-18T00:00:00Z",
        updated_at="2026-06-18T00:00:00Z",
        algorithms=[],
        certificates=[],
        findings=[],
    )


def _scan_row(scan_id: str, group_id: str | None):
    return SimpleNamespace(
        id=scan_id,
        scan_group_id=group_id,
    )


def _group_row(group_id: str, name: str):
    return SimpleNamespace(
        id=group_id,
        name=name,
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


# Tests ----------------------------------------------------------------------


def test_list_assets_enriched_with_scan_group_context(mock_db, client):
    """The list endpoint must run the enrichment and populate
    ``last_scan_group_id`` / ``last_scan_group_name`` on each asset.
    """
    asset = _asset_row(last_scan_id="s-1", first_scan_id="s-1")
    scan = _scan_row("s-1", group_id="g-1")
    group = _group_row("g-1", "Q2 Estate Audit")

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        # Call 1: primary asset list
        # Call 2: scan-by-id batch lookup
        # Call 3: group-by-id batch lookup
        if call_count["n"] == 1:
            return _make_scalars_all([asset])
        if call_count["n"] == 2:
            return _make_scalars_all([scan])
        return _make_scalars_all([group])

    mock_db.execute.side_effect = _execute

    resp = client.get("/api/v1/assets")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    a = body[0]
    # The new fields are present and non-null because the scan links to a group
    assert a["last_scan_group_id"] == "g-1"
    assert a["last_scan_group_name"] == "Q2 Estate Audit"
    assert a["first_scan_group_id"] == "g-1"
    assert a["first_scan_group_name"] == "Q2 Estate Audit"


def test_list_assets_no_group_leaves_fields_null(mock_db, client):
    """If the asset's scan has no scan_group_id, the enrichment fields
    must be set to None (not crash, not error).
    """
    asset = _asset_row(last_scan_id="s-1", first_scan_id="s-1")
    scan = _scan_row("s-1", group_id=None)  # scan is ungrouped

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalars_all([asset])
        # Only scan lookup is needed; no group lookup because group_ids is empty.
        return _make_scalars_all([scan])

    mock_db.execute.side_effect = _execute

    resp = client.get("/api/v1/assets")
    assert resp.status_code == 200
    a = resp.json()[0]
    assert a["last_scan_group_id"] is None
    assert a["last_scan_group_name"] is None


def test_list_assets_without_scan_id_skips_enrichment(mock_db, client):
    """If an asset has no last_scan_id / first_scan_id, the enrichment
    should be a no-op (no scan lookup, no group lookup, all fields None).
    """
    asset = _asset_row(last_scan_id=None, first_scan_id=None)

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        return _make_scalars_all([asset])

    mock_db.execute.side_effect = _execute

    resp = client.get("/api/v1/assets")
    assert resp.status_code == 200
    a = resp.json()[0]
    assert a["last_scan_group_id"] is None
    assert a["last_scan_group_name"] is None
    assert a["first_scan_group_id"] is None
    assert a["first_scan_group_name"] is None


def test_get_asset_enriched_with_scan_group_context(mock_db, client):
    """The single-asset endpoint runs the same enrichment."""
    asset = _asset_row(last_scan_id="s-1", first_scan_id="s-1")
    scan = _scan_row("s-1", group_id="g-1")
    group = _group_row("g-1", "Q2 Estate Audit")

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar_one_or_none(asset)
        if call_count["n"] == 2:
            return _make_scalars_all([scan])
        return _make_scalars_all([group])

    mock_db.execute.side_effect = _execute

    resp = client.get(f"/api/v1/assets/{asset.id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["last_scan_group_id"] == "g-1"
    assert body["last_scan_group_name"] == "Q2 Estate Audit"
