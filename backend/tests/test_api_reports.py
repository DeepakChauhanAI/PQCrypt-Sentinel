import pytest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user
from app.db import get_session

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
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


def _scalar_result(value):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    return r


def _scalars_result(items):
    r = MagicMock()
    r.scalars.return_value.all.return_value = items
    return r


class TestCreateReport:
    def test_create_report_success(self, mock_db):
        async def _refresh(obj):
            obj.id = "report-1"
            obj.status = "pending"
            obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
            obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        mock_db.refresh = AsyncMock(side_effect=_refresh)

        with patch("app.tasks.execute_report") as mock_task:
            client = TestClient(app)
            resp = client.post("/api/v1/reports", json={
                "report_type": "cbom",
                "format": "json",
            })
        assert resp.status_code == 202
        mock_task.delay.assert_called_once()

    def test_create_report_unsupported_format(self, mock_db):
        client = TestClient(app)
        resp = client.post("/api/v1/reports", json={
            "report_type": "cbom",
            "format": "xml",
        })
        assert resp.status_code == 400
        assert "Unsupported" in resp.json()["detail"]

    def test_create_report_unsupported_type_format_combo(self, mock_db):
        client = TestClient(app)
        resp = client.post("/api/v1/reports", json={
            "report_type": "executive",
            "format": "csv",
        })
        assert resp.status_code == 400


class TestListReports:
    def test_list_reports_success(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            scope_filters={},
            file_path="/tmp/report.json",
            created_by="user-1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalars_result([report])
        client = TestClient(app)
        resp = client.get("/api/v1/reports")
        assert resp.status_code == 200
        assert len(resp.json()) == 1


class TestGetReport:
    def test_get_report_success(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            scope_filters={},
            file_path="/tmp/report.json",
            created_by="user-1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-1")
        assert resp.status_code == 200
        assert resp.json()["id"] == "r-1"

    def test_get_report_not_found(self, mock_db):
        mock_db.execute.return_value = _scalar_result(None)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/nonexistent")
        assert resp.status_code == 404


class TestDownloadReport:
    def test_download_report_not_found(self, mock_db):
        mock_db.execute.return_value = _scalar_result(None)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/nonexistent/download")
        assert resp.status_code == 404

    def test_download_report_not_ready(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="pending",
            file_path=None,
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-1/download")
        assert resp.status_code == 400
        assert "not ready" in resp.json()["detail"].lower()

    def test_download_report_file_not_on_disk(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            file_path="/nonexistent/report.json",
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-1/download")
        assert resp.status_code == 404
        assert "not found on server" in resp.json()["detail"].lower()

    def test_download_report_success(self, mock_db, tmp_path):
        report_file = tmp_path / "report.json"
        report_file.write_text('{"test": true}')
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            file_path=str(report_file),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-1/download")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

    def test_download_report_csv_format(self, mock_db, tmp_path):
        report_file = tmp_path / "report.csv"
        report_file.write_text("col1,col2\nval1,val2")
        report = SimpleNamespace(
            id="r-2",
            report_type="findings",
            format="csv",
            status="ready",
            file_path=str(report_file),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-2/download")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_download_report_sarif_format(self, mock_db, tmp_path):
        report_file = tmp_path / "report.sarif"
        report_file.write_text('{"version": "2.1.0"}')
        report = SimpleNamespace(
            id="r-3",
            report_type="sast",
            format="sarif",
            status="ready",
            file_path=str(report_file),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-3/download")
        assert resp.status_code == 200
        assert "sarif" in resp.headers["content-type"]

    def test_download_report_html_format(self, mock_db, tmp_path):
        report_file = tmp_path / "report.html"
        report_file.write_text("<html></html>")
        report = SimpleNamespace(
            id="r-4",
            report_type="executive",
            format="html",
            status="ready",
            file_path=str(report_file),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-4/download")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_download_report_unknown_extension(self, mock_db, tmp_path):
        report_file = tmp_path / "report.dat"
        report_file.write_text("binary data")
        report = SimpleNamespace(
            id="r-5",
            report_type="custom",
            format="dat",
            status="ready",
            file_path=str(report_file),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.get("/api/v1/reports/r-5/download")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"


class TestDeleteReport:
    def test_delete_report_not_found(self, mock_db):
        mock_db.execute.return_value = _scalar_result(None)
        client = TestClient(app)
        resp = client.delete("/api/v1/reports/nonexistent")
        assert resp.status_code == 404

    def test_delete_report_success(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            file_path=None,
            scope_filters={},
            scan_ids=None,
            created_by="user-1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.delete("/api/v1/reports/r-1")
        assert resp.status_code == 200
        assert report.deleted_at is not None

    def test_delete_report_removes_file(self, mock_db, tmp_path):
        report_file = tmp_path / "report.json"
        report_file.write_text('{"test": true}')
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            file_path=str(report_file),
            scope_filters={},
            scan_ids=None,
            created_by="user-1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        resp = client.delete("/api/v1/reports/r-1")
        assert resp.status_code == 200
        assert not report_file.exists()

    def test_delete_report_file_removal_failure_is_logged(self, mock_db):
        report = SimpleNamespace(
            id="r-1",
            report_type="cbom",
            format="json",
            status="ready",
            file_path="/locked/report.json",
            scope_filters={},
            scan_ids=None,
            created_by="user-1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deleted_at=None,
        )
        mock_db.execute.return_value = _scalar_result(report)
        client = TestClient(app)
        with patch("os.path.exists", return_value=True), \
             patch("os.remove", side_effect=PermissionError("file locked")):
            resp = client.delete("/api/v1/reports/r-1")
        assert resp.status_code == 200
