"""Tests for the ScanGroup API (Phase B - correlation model)."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user


app = create_app()

mock_user = SimpleNamespace(
    id="11111111-1111-1111-1111-111111111111",
    email="admin@pqc.local",
    role="admin",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_user


def _make_scalar(value):
    """Mock that returns value from both scalar_one and scalar_one_or_none."""
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    r.scalar_one = MagicMock(return_value=value)
    return r


def _make_scalars_all(items):
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    r.scalar_one = MagicMock(return_value=len(items))
    return r


def _group_row(
    group_id="44444444-4444-4444-4444-444444444444",
    name="Q2 Estate Audit",
    status="running",
    members=0,
    assets=0,
    findings=0,
):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=group_id,
        name=name,
        description=None,
        status=status,
        started_at=now,
        completed_at=None,
        created_at=now,
        updated_at=now,
        member_count=members,
        assets_found=assets,
        findings_created=findings,
    )


def _scan_row(
    scan_id="33333333-3333-3333-3333-333333333333",
    scan_type="tls_only",
    target="example.com",
    status="queued",
    group_id="44444444-4444-4444-4444-444444444444",
):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=scan_id,
        scan_type=scan_type,
        target=target,
        status=status,
        target_label=None,
        target_kind=None,
        scan_group_id=group_id,
        config=None,
        credential_profile=None,
        advanced_tools=False,
        error_message=None,
        assets_found=0,
        findings_created=0,
        created_by=mock_user.id,
        created_at=now,
        updated_at=now,
        started_at=None,
        completed_at=None,
        duration_seconds=None,
    )


@pytest.fixture
def mock_db():
    session = AsyncMock()
    from app.db import get_session
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def client():
    return TestClient(app)


# --- POST /scan-groups ---


def test_create_scan_group_basic(mock_db, client):
    """Two-member group: both scans persisted, both Celery tasks dispatched."""
    call_count = {"n": 0}

    async def _refresh(obj):
        obj.id = "55555555-5555-5555-5555-555555555555"
        obj.started_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        # _compute_group_rollups: count(2) / sum(0) / sum(0)
        if call_count["n"] == 1:
            return _make_scalar(2)  # member count
        if call_count["n"] == 2:
            return _make_scalar(0)  # assets sum
        return _make_scalar(0)  # findings sum

    mock_db.execute.side_effect = _execute
    mock_db.refresh = AsyncMock(side_effect=_refresh)

    with patch("app.api.scan_groups.execute_scan") as mock_task:
        resp = client.post(
            "/api/v1/scan-groups",
            json={
                "name": "Q2 Estate Audit",
                "members": [
                    {"scan_type": "tls_only", "target": "api.example.com"},
                    {"scan_type": "cloud_sync", "target": "aws:us-east-1"},
                ],
            },
        )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "Q2 Estate Audit"
    assert body["member_count"] == 2
    assert body["assets_found"] == 0
    assert body["findings_created"] == 0
    # Celery task dispatched once per member
    assert mock_task.delay.call_count == 2


def test_create_scan_group_empty_members_returns_400(mock_db, client):
    resp = client.post(
        "/api/v1/scan-groups",
        json={"name": "Empty", "members": []},
    )
    assert resp.status_code == 400
    assert "at least one member" in resp.json()["detail"]


# --- GET /scan-groups ---


def test_list_scan_groups_returns_rollups(mock_db, client):
    """The list endpoint returns groups with member/asset/finding roll-ups."""
    groups_data = [
        ("g-1", "Q1 Audit", 3, 12, 4),
        ("g-2", "Production TLS Sweep", 1, 5, 1),
    ]
    groups = [
        _group_row(group_id=g[0], name=g[1], members=g[2], assets=g[3], findings=g[4])
        for g in groups_data
    ]
    # The endpoint does: 1 list query + (1 count + 2 sum queries) per group.
    # Use a simple cycling helper that returns the right rollups per call.
    call_n = {"n": 0}
    rollup_values = [3, 12, 4, 1, 5, 1]  # count/assets/findings per group, x2

    async def _execute(*args, **kwargs):
        call_n["n"] += 1
        if call_n["n"] == 1:
            return _make_scalars_all(groups)
        idx = call_n["n"] - 2
        if idx < len(rollup_values):
            return _make_scalar(rollup_values[idx])
        return _make_scalar(0)

    mock_db.execute.side_effect = _execute
    resp = client.get("/api/v1/scan-groups")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert body[0]["name"] == "Q1 Audit"
    assert body[0]["member_count"] == 3
    assert body[0]["assets_found"] == 12
    assert body[0]["findings_created"] == 4
    assert body[1]["name"] == "Production TLS Sweep"
    assert body[1]["member_count"] == 1
    assert body[1]["assets_found"] == 5


# --- GET /scan-groups/{id} ---


def test_get_scan_group_detail(mock_db, client):
    group = _group_row(group_id="g-1", name="Q1 Audit", members=2)
    member_scans = [
        _scan_row(scan_id="s-1", scan_type="tls_only", target="api.example.com", group_id="g-1"),
        _scan_row(scan_id="s-2", scan_type="cloud_sync", target="aws:us-east-1", group_id="g-1"),
    ]
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar(group)
        if call_count["n"] == 2:
            return _make_scalars_all(member_scans)
        # _compute_group_rollups: count, sum, sum
        if call_count["n"] == 3:
            return _make_scalar(2)
        return _make_scalar(0)

    mock_db.execute.side_effect = _execute
    resp = client.get("/api/v1/scan-groups/g-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Q1 Audit"
    assert len(body["members"]) == 2
    assert body["members"][0]["scan_type"] == "tls_only"
    assert body["members"][1]["scan_type"] == "cloud_sync"


def test_get_scan_group_not_found(mock_db, client):
    mock_db.execute.return_value = _make_scalar(None)
    resp = client.get("/api/v1/scan-groups/missing-id")
    assert resp.status_code == 404


# --- DELETE /scan-groups/{id} ---


def test_cancel_scan_group_cancels_members(mock_db, client):
    group = _group_row(group_id="g-1", members=2)
    running_scans = [_scan_row(scan_id="s-1", status="running", group_id="g-1")]
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar(group)
        if call_count["n"] == 2:
            return _make_scalars_all(running_scans)
        # rollups: count, sum, sum
        return _make_scalar(0)

    mock_db.execute.side_effect = _execute
    resp = client.delete("/api/v1/scan-groups/g-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "cancelled"


# --- /scans/{id}/assets ---


def test_scans_assets_endpoint_returns_scoped_assets(mock_db, client):
    """The /scans/{id}/assets endpoint returns assets where the scan is the first or last."""
    from app.models.models import Asset
    now = datetime.now(timezone.utc)
    # Use a real Asset ORM object so Pydantic can serialize it cleanly
    asset = Asset(
        id="00000000-0000-0000-0000-000000000001",
        name="api.example.com:443",
        asset_type="server",
        ip_address="1.2.3.4",
        fqdn="api.example.com",
        port=443,
        protocol="tcp",
        environment="production",
        first_discovered_at=now,
        last_verified_at=now,
        asset_metadata={},
        created_at=now,
        updated_at=now,
    )
    call_n = {"n": 0}

    async def _execute(*args, **kwargs):
        call_n["n"] += 1
        if call_n["n"] == 1:
            return _make_scalar(_scan_row(scan_id="scan-1"))
        return _make_scalars_all([asset])

    mock_db.execute.side_effect = _execute
    resp = client.get("/api/v1/scans/scan-1/assets")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "api.example.com:443"
    assert body[0]["fqdn"] == "api.example.com"
    assert body[0]["port"] == 443


def test_scans_assets_endpoint_scan_not_found(mock_db, client):
    mock_db.execute.return_value = _make_scalar(None)
    resp = client.get("/api/v1/scans/missing-scan/assets")
    assert resp.status_code == 404


# --- scan context enrichment ---


def test_finding_enrichment_populates_scan_group_name(mock_db, client):
    finding = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity="high",
        title="t",
        description=None,
        algorithm="RSA",
        algorithm_type="signature",
        pqc_status="vulnerable",
        risk_score=70,
        layer="L2",
        hndl_exposure=None,
        evidence=None,
        remediation=None,
        recommended_algorithm="ML-DSA-65",
        status="open",
        assigned_to=None,
        asset=SimpleNamespace(
            id="a-1", name="api.example.com:443", asset_type="server",
            fqdn="api.example.com", ip_address=None, port=443, environment="production",
        ),
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=None,
        resolved_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        deleted_at=None,
    )
    scan = SimpleNamespace(
        id="s-1",
        scan_type="tls_only",
        target="api.example.com",
        target_label="api-prod",
        target_kind="host",
        scan_group_id="g-1",
    )
    group = SimpleNamespace(id="g-1", name="Q2 Estate Audit")
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalars_all([finding])
        if call_count["n"] == 2:
            return _make_scalars_all([scan])
        return _make_scalars_all([group])

    mock_db.execute.side_effect = _execute
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body[0]["scan_type"] == "tls_only"
    assert body[0]["scan_target"] == "api.example.com"
    assert body[0]["scan_target_label"] == "api-prod"
    assert body[0]["scan_group_id"] == "g-1"
    assert body[0]["scan_group_name"] == "Q2 Estate Audit"


def test_finding_enrichment_handles_missing_scan_gracefully(mock_db, client):
    finding = SimpleNamespace(
        id="f-1", asset_id="a-1", scan_id="missing-scan",
        finding_type="weak_algorithm", severity="high", title="t",
        description=None, algorithm=None, algorithm_type=None,
        pqc_status=None, risk_score=None, layer=None, hndl_exposure=None,
        evidence=None, remediation=None, recommended_algorithm=None,
        status="open", assigned_to=None, asset=None,
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=None, resolved_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        deleted_at=None,
    )
    call_count = {"n": 0}

    async def _execute(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalars_all([finding])
        return _make_scalars_all([])

    mock_db.execute.side_effect = _execute
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["scan_type"] is None
    assert body[0]["scan_group_name"] is None
