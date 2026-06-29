"""
Tests for `app.api.findings` - list / get / update / rescan endpoints.
"""
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
    email="analyst@pqc.local",
    role="analyst",
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


def _find_row(
    finding_id: str = "11111111-1111-1111-1111-111111111111",
    asset_id: str = "22222222-2222-2222-2222-222222222222",
):
    return SimpleNamespace(
        id=finding_id,
        asset_id=asset_id,
        scan_id="33333333-3333-3333-3333-333333333333",
        finding_type="weak_algorithm",
        severity="high",
        title="Test finding",
        description=None,
        algorithm="RSA-2048",
        algorithm_type="cert",
        pqc_status="vulnerable",
        risk_score=75.0,
        layer="L2",
        hndl_exposure=None,
        evidence=None,
        remediation=None,
        recommended_algorithm="ML-DSA-65",
        status="open",
        assigned_to=None,
        asset=SimpleNamespace(
            id=asset_id,
            name="test-asset:443",
            asset_type="server",
            fqdn="test.example.com",
            ip_address=None,
            port=443,
            environment="production",
        ),
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        resolved_at=None,
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


# ---------------------------------------------- GET /findings ----------


def test_list_findings_no_filters(mock_db):
    finding = _find_row()
    mock_db.execute.return_value = _make_scalars_all([finding])
    client = TestClient(app)
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == finding.id


def test_list_findings_invalid_layer_returns_400(mock_db):
    client = TestClient(app)
    resp = client.get("/api/v1/findings?layer=L99")
    assert resp.status_code == 400
    body = resp.json()
    assert "L1..L7" in body["detail"] or "Invalid" in body["detail"]


def test_list_findings_valid_layer_filter(mock_db):
    finding = _find_row()
    mock_db.execute.return_value = _make_scalars_all([finding])
    client = TestClient(app)
    resp = client.get("/api/v1/findings?layer=L2")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_list_findings_layer_lowercase_normalized(mock_db):
    """`layer=l2` (lowercase) is normalized to L2."""
    finding = _find_row()
    mock_db.execute.return_value = _make_scalars_all([finding])
    client = TestClient(app)
    resp = client.get("/api/v1/findings?layer=l2")
    assert resp.status_code == 200


# ---------------------------------------------- GET /findings/{id} -----


def test_get_finding_success(mock_db):
    finding = _find_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(finding)
    client = TestClient(app)
    resp = client.get(f"/api/v1/findings/{finding.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == finding.id


def test_get_finding_not_found(mock_db):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    client = TestClient(app)
    resp = client.get("/api/v1/findings/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


# ---------------------------------------------- PATCH /findings/{id} ---


def test_update_finding_status_resolved_sets_resolved_at(mock_db):
    finding = _find_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(finding)
    client = TestClient(app)
    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"status": "resolved", "reason": "replaced by ML-DSA cert"},
    )
    assert resp.status_code == 200
    # After commit+refresh, finding.resolved_at should be set
    assert finding.resolved_at is not None
    assert finding.status == "resolved"
    assert finding.evidence["status_change_reason"] == "replaced by ML-DSA cert"


def test_update_finding_not_found_returns_404(mock_db):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    client = TestClient(app)
    resp = client.patch(
        "/api/v1/findings/00000000-0000-0000-0000-000000000000",
        json={"status": "resolved"},
    )
    assert resp.status_code == 404


def test_update_finding_assign_to_non_admin_returns_403(mock_db):
    """A non-admin user trying to assign a finding -> 403."""
    finding = _find_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(finding)
    client = TestClient(app)
    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"assigned_to": "99999999-9999-9999-9999-999999999999"},
    )
    assert resp.status_code == 403
    assert "admin" in resp.json()["detail"].lower()


def test_update_finding_assign_to_admin_success(mock_db):
    """An admin assigning to a real user succeeds."""
    finding = _find_row()
    # First execute -> the finding; second -> user lookup
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar_one_or_none(finding)
        if call_count["n"] == 2:
            user = SimpleNamespace(id="99999999-9999-9999-9999-999999999999", email="admin2@pqc.local")
            return _make_scalar_one_or_none(user)
        return _make_scalar_one_or_none(None)

    mock_db.execute.side_effect = _execute

    # Switch the mock user to admin
    admin_user = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        email="admin@pqc.local",
        role="admin",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: admin_user
    client = TestClient(app)
    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"assigned_to": "99999999-9999-9999-9999-999999999999"},
    )
    assert resp.status_code == 200
    assert finding.assigned_to == "99999999-9999-9999-9999-999999999999"
    # Restore
    app.dependency_overrides[get_current_user] = lambda: mock_user


def test_update_finding_assign_to_invalid_user_returns_400(mock_db):
    """Admin assigning to a non-existent user -> 400."""
    finding = _find_row()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_scalar_one_or_none(finding)
        if call_count["n"] == 2:
            return _make_scalar_one_or_none(None)  # user not found
        return _make_scalar_one_or_none(None)

    mock_db.execute.side_effect = _execute

    admin_user = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        email="admin@pqc.local",
        role="admin",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: admin_user
    client = TestClient(app)
    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"assigned_to": "ffffffff-ffff-ffff-ffff-ffffffffffff"},
    )
    assert resp.status_code == 400
    assert "Assigned user not found" in resp.json()["detail"]
    app.dependency_overrides[get_current_user] = lambda: mock_user


# ---------------------------------------------- POST /findings/{id}/rescan -


def test_rescan_finding_creates_new_scan(mock_db):
    finding = _find_row()
    mock_db.execute.return_value = _make_scalar_one_or_none(finding)

    with patch("app.tasks.execute_scan") as mock_task:
        client = TestClient(app)
        resp = client.post(f"/api/v1/findings/{finding.id}/rescan")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert "scan_id" in body
    # Celery task should be enqueued
    mock_task.delay.assert_called_once()


def test_rescan_finding_not_found(mock_db):
    mock_db.execute.return_value = _make_scalar_one_or_none(None)
    client = TestClient(app)
    resp = client.post("/api/v1/findings/00000000-0000-0000-0000-000000000000/rescan")
    assert resp.status_code == 404
