"""
Tests for `app.api.scans` - create / list / get / findings endpoints.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# Helpers --------------------------------------------------------------------

def _scan_row(
    scan_id: str = "33333333-3333-3333-3333-333333333333",
    scan_type: str = "tls_only",
    target: str = "example.com",
    status: str = "completed",
):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=scan_id,
        scan_type=scan_type,
        target=target,
        status=status,
        advanced_tools=False,
        assets_found=1,
        findings_created=0,
        error_message=None,
        created_by="11111111-1111-1111-1111-111111111111",
        created_at=now,
        updated_at=now,
        started_at=None,
        completed_at=now,
        config=None,
        credential_profile=None,
        deleted_at=None,
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
    """An AsyncMock session, with `get_session` override installed."""
    from app.db import get_session
    from app.main import app

    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def auth_user():
    """A canonical user installed as the get_current_user override."""
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


def test_create_scan_basic(mock_db, client):
    """A fresh scan is queued and a Celery task is dispatched."""
    async def _refresh(obj):
        obj.id = "11111111-2222-3333-4444-555555555555"
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_db.refresh = AsyncMock(side_effect=_refresh)
    mock_db.execute.return_value = _make_scalars_all([])

    with patch("app.tasks.execute_scan") as mock_task:
        resp = client.post(
            "/api/v1/scans",
            json={"scan_type": "tls_only", "target": "example.com"},
        )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["scan_type"] == "tls_only"
    assert body["target"] == "example.com"
    assert body["status"] == "queued"
    mock_task.delay.assert_called_once()


def test_create_scan_dedup_returns_existing(mock_db, client):
    """When a recent QUEUED scan exists for the same target+type, return it."""
    existing = _scan_row(scan_id="deduped-id", status="queued")
    mock_db.execute.return_value = _make_scalars_all([existing])

    with patch("app.tasks.execute_scan") as mock_task:
        resp = client.post(
            "/api/v1/scans",
            json={"scan_type": "tls_only", "target": "example.com"},
        )
    assert resp.status_code == 202
    body = resp.json()
    assert body["id"] == "deduped-id"
    # No new task dispatched when dedup hits
    mock_task.delay.assert_not_called()


def test_create_scan_cidr_auto_creates_group(mock_db, client):
    """A CIDR-range scan must be auto-wrapped in a ScanGroup so it
    surfaces in the Scan Groups tab and its findings inherit
    ``scan_group_name`` in the Findings page.

    The auto-wrap happens by:
      1. Adding a ``ScanGroup`` row to the session with status=running.
      2. Setting ``scan.scan_group_id = group.id`` after the flush
         populates the group id.
      3. Setting ``scan.target_kind = "network_range"``.

    The test inspects what was added to the mock session rather than
    patching the DB, so it pins the actual code path the user hits.
    """
    async def _refresh(obj):
        obj.id = "cidr-scan-id"
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_db.refresh = AsyncMock(side_effect=_refresh)
    mock_db.execute.return_value = _make_scalars_all([])  # no recent scans → no dedup

    added: list = []
    flushed_ids: list = []

    def _add(obj):
        added.append(obj)
        # Mimic a primary key / FK assignment that flush() would do.
        if not hasattr(obj, "id") or obj.id is None:
            obj.id = "group-uuid-from-flush"
        if not getattr(obj, "_flush_counted", False):
            flushed_ids.append(obj.id)
            obj._flush_counted = True

    async def _flush():
        # No-op — we just want the auto-wrap to be able to read group.id.
        return None

    mock_db.add = MagicMock(side_effect=_add)
    mock_db.flush = AsyncMock(side_effect=_flush)

    with patch("app.tasks.execute_scan") as mock_task:
        resp = client.post(
            "/api/v1/scans",
            json={"scan_type": "full", "target": "192.168.1.0/24"},
        )
    assert resp.status_code == 202, resp.text
    # Two ORM objects were added: a ScanGroup, then a Scan.
    assert len(added) == 2, f"expected ScanGroup + Scan, got {added!r}"
    group_obj, scan_obj = added[0], added[1]
    # Group is a ScanGroup
    from app.models.models import ScanGroup, Scan
    assert isinstance(group_obj, ScanGroup)
    # The scan was linked to the group via scan_group_id
    assert scan_obj.scan_group_id == "group-uuid-from-flush"
    # The scan got the right target_kind
    assert scan_obj.target_kind == "network_range"
    # The group name is human-readable
    assert "192.168.1.0/24" in group_obj.name
    # The Celery task was dispatched with the scan id
    mock_task.delay.assert_called_once()
    # The new scan, not the group, is what the response returns
    assert resp.json()["id"] == "cidr-scan-id"


def test_create_scan_single_host_does_not_create_group(mock_db, client):
    """A single-IP scan is NOT groupable, so no ScanGroup is added.

    The scan row still gets ``target_kind = "host"`` and
    ``target_label = "10.0.0.1"`` from the classifier, but no group row
    is created.
    """
    async def _refresh(obj):
        obj.id = "single-host-scan"
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_db.refresh = AsyncMock(side_effect=_refresh)
    mock_db.execute.return_value = _make_scalars_all([])

    added: list = []
    mock_db.add = MagicMock(side_effect=added.append)
    mock_db.flush = AsyncMock(return_value=None)

    with patch("app.tasks.execute_scan"):
        resp = client.post(
            "/api/v1/scans",
            json={"scan_type": "tls_only", "target": "10.0.0.1"},
        )
    assert resp.status_code == 202, resp.text
    # Only the Scan was added, no ScanGroup
    assert len(added) == 1
    assert added[0].target_kind == "host"
    assert added[0].target_label == "10.0.0.1"
    assert added[0].scan_group_id is None


def test_create_scan_explicit_scan_group_id_not_overridden(mock_db, client):
    """When the client supplies a scan_group_id in the payload, the
    auto-wrap must not create a new group. The user-supplied id wins.
    """
    async def _refresh(obj):
        obj.id = "explicit-group-scan"
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_db.refresh = AsyncMock(side_effect=_refresh)
    mock_db.execute.return_value = _make_scalars_all([])

    added: list = []
    mock_db.add = MagicMock(side_effect=added.append)
    mock_db.flush = AsyncMock(return_value=None)

    with patch("app.tasks.execute_scan"):
        resp = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "full",
                "target": "192.168.1.0/24",
                "scan_group_id": "user-supplied-group",
            },
        )
    assert resp.status_code == 202
    assert len(added) == 1  # only the scan, no auto-created group
    assert added[0].scan_group_id == "user-supplied-group"


def test_list_scans_returns_all(mock_db, client):
    scans = [_scan_row(scan_id=f"scan-{i}") for i in range(3)]
    mock_db.execute.return_value = _make_scalars_all(scans)
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 3


def test_get_scan_success(mock_db, client):
    scan = _scan_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(scan)
    resp = client.get(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == scan.id


def test_get_scan_not_found(mock_db, client):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_list_scan_findings_invalid_layer_returns_400(mock_db, client):
    scan = _scan_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(scan)
    resp = client.get(f"/api/v1/scans/{scan.id}/findings?layer=L99")
    assert resp.status_code == 400
    assert "L1..L7" in resp.json()["detail"] or "Invalid" in resp.json()["detail"]


def test_list_scan_findings_not_found(mock_db, client):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/findings")
    assert resp.status_code == 404


def test_list_scan_findings_no_filters(mock_db, client):
    """Findings list returns the list of Finding dicts."""
    from app.models.schemas import FindingOut
    scan = _scan_row()
    finding = FindingOut(
        id="f-1",
        asset_id="a-1",
        scan_id=scan.id,
        finding_type="weak_algorithm",
        severity="high",
        title="test",
        risk_score=70,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar_one_or_none(scan)
        return _make_scalars_all([finding])

    mock_db.execute.side_effect = _execute
    resp = client.get(f"/api/v1/scans/{scan.id}/findings")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, list)
    assert body[0]["finding_type"] == "weak_algorithm"


def test_delete_scan_success(mock_db, client):
    scan = _scan_row(status="running")
    mock_db.execute.return_value = _make_scalar_one_or_none(scan)
    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == scan.id


def test_delete_scan_terminal_422(mock_db, client):
    scan = _scan_row(status="completed")
    mock_db.execute.return_value = _make_scalar_one_or_none(scan)
    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 422


def test_delete_scan_not_found(mock_db, client):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    resp = client.delete("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
