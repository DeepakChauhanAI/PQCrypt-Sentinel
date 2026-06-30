import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from app.main import create_app
from app.config import settings
from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import User, Finding, Asset, Report

# Create test app
app = create_app()

# Mock user for auth
mock_user = User(
    id="12345678-1234-1234-1234-123456789012",
    email="analyst@pqc.local",
    full_name="Test Analyst",
    role="analyst",
    is_active=True,
)

app.dependency_overrides[get_current_user] = lambda: mock_user


@pytest.fixture
def mock_db():
    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


client = TestClient(app)


def test_list_findings(mock_db):
    mock_finding = Finding(
        id="11111111-1111-1111-1111-111111111111",
        asset_id="22222222-2222-2222-2222-222222222222",
        scan_id="33333333-3333-3333-3333-333333333333",
        finding_type="weak_algorithm",
        severity="high",
        title="Test Finding",
        status="open",
        first_detected_at="2026-06-03T12:00:00Z",
        created_at="2026-06-03T12:00:00Z",
        updated_at="2026-06-03T12:00:00Z",
        asset=Asset(
            id="22222222-2222-2222-2222-222222222222",
            name="test-asset:443",
            asset_type="server",
            environment="production",
            first_discovered_at="2026-06-03T12:00:00Z",
            asset_metadata={},
            created_at="2026-06-03T12:00:00Z",
            updated_at="2026-06-03T12:00:00Z",
        ),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_finding]
    mock_db.execute.return_value = mock_result

    response = client.get("/api/v1/findings?severity=high")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Test Finding"
    assert data[0]["asset"]["name"] == "test-asset:443"


def test_get_finding_detail(mock_db):
    mock_finding = Finding(
        id="11111111-1111-1111-1111-111111111111",
        asset_id="22222222-2222-2222-2222-222222222222",
        scan_id="33333333-3333-3333-3333-333333333333",
        finding_type="weak_algorithm",
        severity="high",
        title="Test Finding",
        status="open",
        first_detected_at="2026-06-03T12:00:00Z",
        created_at="2026-06-03T12:00:00Z",
        updated_at="2026-06-03T12:00:00Z",
        asset=Asset(
            id="22222222-2222-2222-2222-222222222222",
            name="test-asset:443",
            asset_type="server",
            environment="production",
            first_discovered_at="2026-06-03T12:00:00Z",
            asset_metadata={},
            created_at="2026-06-03T12:00:00Z",
            updated_at="2026-06-03T12:00:00Z",
        ),
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_finding
    mock_db.execute.return_value = mock_result

    response = client.get("/api/v1/findings/11111111-1111-1111-1111-111111111111")
    assert response.status_code == 200
    assert response.json()["id"] == "11111111-1111-1111-1111-111111111111"


def test_list_assets(mock_db):
    mock_asset = Asset(
        id="22222222-2222-2222-2222-222222222222",
        name="test-asset:443",
        asset_type="server",
        environment="production",
        first_discovered_at="2026-06-03T12:00:00Z",
        asset_metadata={},
        created_at="2026-06-03T12:00:00Z",
        updated_at="2026-06-03T12:00:00Z",
        findings=[],
        algorithms=[],
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_asset]
    mock_db.execute.return_value = mock_result

    response = client.get("/api/v1/assets?environment=production")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "test-asset:443"
    assert data[0]["pqc_status"] == "unknown"
    assert data[0]["risk_score"] == 0


@patch("app.api.dashboard.get_cache", return_value=None)
@patch("app.api.dashboard.set_cache")
def test_dashboard_summary(mock_set_cache, mock_get_cache, mock_db):
    mock_asset = Asset(
        id="22222222-2222-2222-2222-222222222222",
        name="test-asset:443",
        asset_type="server",
        environment="production",
        first_discovered_at="2026-06-03T12:00:00Z",
        asset_metadata={},
        created_at="2026-06-03T12:00:00Z",
        updated_at="2026-06-03T12:00:00Z",
        findings=[],
        algorithms=[],
    )

    mock_total_assets = MagicMock()
    mock_total_assets.scalar_one.return_value = 1

    mock_pqc_summary = MagicMock()
    mock_pqc_summary.all.return_value = [("vulnerable", 1)]

    mock_crit_result = MagicMock()
    mock_crit_result.scalar_one.return_value = 1

    mock_high_result = MagicMock()
    mock_high_result.scalar_one.return_value = 2

    mock_drift_result = MagicMock()
    mock_drift_result.scalar_one.return_value = 0

    mock_db.execute.side_effect = [
        mock_total_assets,
        mock_pqc_summary,
        mock_crit_result,
        mock_high_result,
        mock_drift_result,
    ]

    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["total_assets"] == 1
    assert data["critical_findings"] == 1
    assert data["high_findings"] == 2
    assert data["drift_alerts_count"] == 0
    assert data["pqc_readiness_score"] == 0.0


@patch("app.tasks.execute_report")
def test_create_report(mock_execute_report, mock_db):
    mock_report = Report(
        id="99999999-9999-9999-9999-999999999999",
        report_type="cbom",
        format="json",
        scope_filters={},
        status="pending",
        created_by=mock_user.id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    mock_db.execute.return_value.scalar_one_or_none.return_value = mock_report

    def mock_refresh(obj):
        obj.id = "99999999-9999-9999-9999-999999999999"
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)

    mock_db.refresh.side_effect = mock_refresh

    response = client.post(
        "/api/v1/reports", json={"report_type": "cbom", "format": "json"}
    )
    assert response.status_code == 202
    assert response.json()["report_type"] == "cbom"
    mock_execute_report.delay.assert_called_once_with(
        "99999999-9999-9999-9999-999999999999", []
    )


def test_list_reports(mock_db):
    mock_report = Report(
        id="99999999-9999-9999-9999-999999999999",
        report_type="cbom",
        format="json",
        scope_filters={},
        status="ready",
        created_by=mock_user.id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_report]
    mock_db.execute.return_value = mock_result

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["status"] == "ready"


# --- Phase 1.1: scan creation requires auth and records created_by ---


@patch("app.tasks.execute_scan")
def test_create_scan_requires_auth(mock_execute_scan, mock_db):
    """Without an auth override, the create_scan endpoint must reject unauthenticated requests."""
    # Temporarily drop the module-level auth override
    saved = app.dependency_overrides.pop(get_current_user, None)
    try:
        response = client.post(
            "/api/v1/scans",
            json={"scan_type": "tls_only", "target": "example.com"},
        )
        assert response.status_code == 401
        # Also confirm Celery was NOT dispatched
        mock_execute_scan.delay.assert_not_called()
    finally:
        if saved is not None:
            app.dependency_overrides[get_current_user] = saved


@patch("app.tasks.execute_scan")
def test_create_scan_records_created_by(mock_execute_scan, mock_db):
    """When auth is present, the new Scan row must carry created_by=current_user.id."""
    new_scan_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    # dedup query: return empty list
    dedup_result = MagicMock()
    dedup_result.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = dedup_result
    saved_scan = {}

    def _refresh(obj):
        obj.id = new_scan_id
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        obj.error_message = None
        saved_scan["obj"] = obj

    mock_db.refresh.side_effect = _refresh

    response = client.post(
        "/api/v1/scans",
        json={"scan_type": "tls_only", "target": "example.com"},
    )
    assert response.status_code == 202
    assert saved_scan.get("obj") is not None
    assert saved_scan["obj"].created_by == mock_user.id
    mock_execute_scan.delay.assert_called_once_with(new_scan_id)


@patch("app.tasks.execute_scan")
def test_create_scan_dedup_uses_advisory_lock(mock_execute_scan, mock_db):
    """The dedup path must take a transaction-scoped advisory lock keyed on scan_type+target."""
    dedup_result = MagicMock()
    dedup_result.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = dedup_result
    saved_scan = {}

    def _refresh(obj):
        obj.id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)
        obj.status = "queued"
        obj.advanced_tools = False
        obj.assets_found = 0
        obj.findings_created = 0
        saved_scan["obj"] = obj

    mock_db.refresh.side_effect = _refresh

    response = client.post(
        "/api/v1/scans",
        json={"scan_type": "tls_only", "target": "example.com"},
    )
    assert response.status_code == 202
    if settings.SCAN_DEDUP_WINDOW_HOURS > 0:
        executed = []
        for c in mock_db.execute.call_args_list:
            for arg in c.args:
                executed.append(str(arg))
            for v in (c.kwargs or {}).values():
                executed.append(str(v))
        assert any(
            "pg_advisory_xact_lock" in s for s in executed
        ), f"expected pg_advisory_xact_lock; got {executed}"
