from __future__ import annotations

from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.main import _sync_url, _sync_missing_columns, create_app


# --- _sync_url ---


def test_sync_url_replaces_asyncpg():
    assert _sync_url("postgresql+asyncpg://u:p@host/db") == "postgresql://u:p@host/db"


def test_sync_url_replaces_aiosqlite():
    assert _sync_url("sqlite+aiosqlite:///:memory:") == "sqlite:///:memory:"


def test_sync_url_no_async_driver():
    assert _sync_url("postgresql://u:p@host/db") == "postgresql://u:p@host/db"


# --- _sync_missing_columns ---


def _make_mock_engine(tables, columns_per_table):
    engine = MagicMock()
    inspector = MagicMock()
    inspector.get_table_names.return_value = tables

    def _get_columns(table):
        return [{"name": c} for c in columns_per_table.get(table, [])]

    inspector.get_columns.side_effect = _get_columns

    conn = MagicMock()
    conn_ctx = MagicMock()
    conn_ctx.__enter__ = MagicMock(return_value=conn)
    conn_ctx.__exit__ = MagicMock(return_value=False)
    engine.begin.return_value = conn_ctx

    return engine, conn, inspector


def test_sync_missing_columns_findings_table():
    engine, conn, inspector = _make_mock_engine(
        tables=["findings"],
        columns_per_table={"findings": ["id", "severity"]},
    )
    with patch("app.main.inspect", return_value=inspector):
        _sync_missing_columns(engine)
    executed = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert any("layer" in s for s in executed)
    assert any("hndl_exposure" in s for s in executed)


def test_sync_missing_columns_scans_table():
    engine, conn, inspector = _make_mock_engine(
        tables=["scans"],
        columns_per_table={"scans": ["id", "status"]},
    )
    with patch("app.main.inspect", return_value=inspector):
        _sync_missing_columns(engine)
    executed = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert any("created_by" in s for s in executed)
    assert any("scan_group_id" in s for s in executed)
    assert any("target_label" in s for s in executed)
    assert any("target_kind" in s for s in executed)


def test_sync_missing_columns_algorithms_table():
    engine, conn, inspector = _make_mock_engine(
        tables=["algorithms"],
        columns_per_table={"algorithms": ["id", "name"]},
    )
    with patch("app.main.inspect", return_value=inspector):
        _sync_missing_columns(engine)
    executed = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert any("scan_id" in s for s in executed)


def test_sync_missing_columns_all_present():
    engine, conn, inspector = _make_mock_engine(
        tables=["findings", "scans", "algorithms"],
        columns_per_table={
            "findings": ["id", "layer", "hndl_exposure"],
            "scans": [
                "id",
                "created_by",
                "scan_group_id",
                "target_label",
                "target_kind",
            ],
            "algorithms": ["id", "scan_id"],
        },
    )
    with patch("app.main.inspect", return_value=inspector):
        _sync_missing_columns(engine)
    assert conn.execute.call_count == 0


def test_sync_missing_columns_table_not_present():
    engine, conn, inspector = _make_mock_engine(
        tables=[],
        columns_per_table={},
    )
    with patch("app.main.inspect", return_value=inspector):
        _sync_missing_columns(engine)
    assert conn.execute.call_count == 0


# --- create_app ---


def test_create_app_returns_fastapi():
    application = create_app()
    assert application.title == "PQCrypt Sentinel API"


def test_docs_endpoint():
    application = create_app()
    from app.api.auth import get_current_user

    mock_user = SimpleNamespace(id="u", email="e", role="admin", is_active=True)
    application.dependency_overrides[get_current_user] = lambda: mock_user
    client = TestClient(application)
    resp = client.get("/api/v1/auth/docs")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_endpoint_shape():
    application = create_app()
    from app.api.auth import get_current_user

    mock_user = SimpleNamespace(id="u", email="e", role="admin", is_active=True)
    application.dependency_overrides[get_current_user] = lambda: mock_user
    client = TestClient(application)
    resp = client.get("/health")
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert "status" in body
