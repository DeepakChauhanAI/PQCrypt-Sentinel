"""Tests for the CSV CMDB connector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import IntegrityError

from app.connectors.csv_connector import CSVCMDBConnector


@pytest.fixture
def connector():
    return CSVCMDBConnector()


@pytest.mark.asyncio
async def test_sync_empty_csv(connector):
    session = AsyncMock()
    result = await connector.sync("", session)
    assert result["status"] == "error"
    assert "empty or missing headers" in result["error"]


@pytest.mark.asyncio
async def test_sync_missing_name_skipped(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    csv_content = "name,asset_type,environment\n,server,production"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["skipped"] == 1
    assert "Missing 'name' field" in result["errors"][0]


@pytest.mark.asyncio
async def test_sync_duplicate_name_skipped(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    csv_content = (
        "name,asset_type,environment\ndup,server,production\ndup,database,staging"
    )
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["imported"] == 1
    assert result["skipped"] == 1
    assert "Duplicate name" in result["errors"][0]


@pytest.mark.asyncio
async def test_sync_invalid_asset_type_normalized(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    csv_content = "name,asset_type,environment\ns1,unknown_type,production"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["imported"] == 1


@pytest.mark.asyncio
async def test_sync_invalid_environment_normalized(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    csv_content = "name,asset_type,environment\ns1,server,invalid_env"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["imported"] == 1


@pytest.mark.asyncio
async def test_sync_updates_existing_asset(connector):
    existing = MagicMock()
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=existing)
    )
    csv_content = "name,asset_type,environment\ns1,server,production"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["updated"] == 1
    assert existing.asset_type == "server"
    assert existing.environment == "production"
    assert existing.discovery_source == "csv_cmdb"


@pytest.mark.asyncio
async def test_sync_row_db_error(connector):
    session = AsyncMock()
    session.execute.side_effect = IntegrityError("stmt", {}, Exception("dup"))
    csv_content = "name,asset_type,environment\ns1,server,production"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["skipped"] == 1
    assert "Database error" in result["errors"][0]


@pytest.mark.asyncio
async def test_sync_commit_failure(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    session.commit.side_effect = IntegrityError("stmt", {}, Exception("dup"))
    csv_content = "name,asset_type,environment\ns1,server,production"
    result = await connector.sync(csv_content, session)
    assert result["status"] == "error"
    assert "Database commit failed" in result["error"]


@pytest.mark.asyncio
async def test_sync_full_row(connector):
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )
    csv_content = (
        "name,asset_type,environment,ip_address,fqdn,port,protocol,os,business_service,cmdb_ci_id\n"
        "srv-1,server,production,10.0.0.1,srv-1.example.com,443,https,Linux,payments,CI123"
    )
    result = await connector.sync(csv_content, session)
    assert result["status"] == "success"
    assert result["imported"] == 1
    session.add.assert_called_once()
