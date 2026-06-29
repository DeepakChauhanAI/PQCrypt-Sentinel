import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.connectors.vault_scanner import VaultScannerConnector


class TestVaultScannerInit:
    def test_init_defaults(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        assert connector.vault_url == "https://vault:8200"
        assert connector.token == "s.token"
        assert connector.mount_point == "secret"
        assert connector.path == ""

    def test_init_strips_trailing_slash(self):
        connector = VaultScannerConnector("https://vault:8200/", "tok", mount_point="kv/", path="app/data/")
        assert connector.vault_url == "https://vault:8200"
        assert connector.mount_point == "kv"
        assert connector.path == "app/data"


class TestVaultRequest:
    @pytest.mark.asyncio
    async def test_success_json(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"keys": ["a", "b"]}}
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await connector._vault_request("GET", "secret/metadata?list=true")
            assert result == {"data": {"keys": ["a", "b"]}}

    @pytest.mark.asyncio
    async def test_404_returns_empty(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await connector._vault_request("GET", "secret/metadata/nonexistent")
            assert result == {}

    @pytest.mark.asyncio
    async def test_204_returns_empty(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await connector._vault_request("DELETE", "secret/data/item")
            assert result == {}

    @pytest.mark.asyncio
    async def test_json_parse_error_returns_empty(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await connector._vault_request("GET", "secret/data/item")
            assert result == {}

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=MagicMock(), response=mock_resp
        )

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await connector._vault_request("GET", "secret/metadata")


class TestListKvPaths:
    @pytest.mark.asyncio
    async def test_success(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"data": {"keys": ["cert1/", "cert2"]}}
            keys = await connector._list_kv_paths("app/")
            assert keys == ["cert1/", "cert2"]
            mock_req.assert_called_once_with("GET", "secret/metadata/app/?list=true")

    @pytest.mark.asyncio
    async def test_empty_keys(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"data": {"keys": []}}
            keys = await connector._list_kv_paths("")
            assert keys == []

    @pytest.mark.asyncio
    async def test_none_keys(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"data": {"keys": None}}
            keys = await connector._list_kv_paths("")
            assert keys == []

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock, side_effect=Exception("timeout")):
            keys = await connector._list_kv_paths("app/")
            assert keys == []


class TestReadKvEntry:
    @pytest.mark.asyncio
    async def test_success(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"data": {"data": {"cert": "PEM...", "key": "KEY..."}}}
            data = await connector._read_kv_entry("app/tls")
            assert data == {"cert": "PEM...", "key": "KEY..."}
            mock_req.assert_called_once_with("GET", "secret/data/app/tls")

    @pytest.mark.asyncio
    async def test_empty_data(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}
            data = await connector._read_kv_entry("app/tls")
            assert data == {}

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token")
        with patch.object(connector, "_vault_request", new_callable=AsyncMock, side_effect=Exception("denied")):
            data = await connector._read_kv_entry("app/tls")
            assert data == {}


class TestUpsertSecret:
    @pytest.mark.asyncio
    async def test_import_new_crypto_secret(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret")
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        with patch.object(connector, "_read_kv_entry", new_callable=AsyncMock) as mock_read:
            mock_read.return_value = {"cert": "PEM...", "private_key": "KEY..."}
            status = await connector._upsert_secret(session, "app/tls")

        assert status == "imported"
        session.add.assert_called_once()
        asset = session.add.call_args[0][0]
        assert asset.name == "vault:secret:app/tls"
        assert asset.asset_type == "saas"
        assert asset.environment == "cloud"
        assert asset.discovery_source == "vault_secrets"
        assert asset.asset_metadata["has_certificate"] is True
        assert asset.asset_metadata["has_private_key"] is True

    @pytest.mark.asyncio
    async def test_update_existing_secret(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret")
        session = AsyncMock()
        existing = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing
        session.execute.return_value = mock_result

        with patch.object(connector, "_read_kv_entry", new_callable=AsyncMock) as mock_read:
            mock_read.return_value = {"password": "s3cret"}
            status = await connector._upsert_secret(session, "app/db")

        assert status == "updated"
        assert existing.asset_type == "saas"
        session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_crypto_material(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret")
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        with patch.object(connector, "_read_kv_entry", new_callable=AsyncMock) as mock_read:
            mock_read.return_value = {"username": "admin", "password": "s3cret"}
            status = await connector._upsert_secret(session, "app/config")

        assert status == "imported"
        asset = session.add.call_args[0][0]
        assert asset.asset_metadata["has_certificate"] is False
        assert asset.asset_metadata["has_private_key"] is False

    @pytest.mark.asyncio
    async def test_partial_crypto_material_cert_only(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="kv")
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        with patch.object(connector, "_read_kv_entry", new_callable=AsyncMock) as mock_read:
            mock_read.return_value = {"tls_cert": "PEM...", "domain": "example.com"}
            status = await connector._upsert_secret(session, "web/tls")

        asset = session.add.call_args[0][0]
        assert asset.asset_metadata["has_certificate"] is True
        assert asset.asset_metadata["has_private_key"] is False


class TestSync:
    @pytest.mark.asyncio
    async def test_sync_flat_keys(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="app")
        session = AsyncMock()

        with patch.object(connector, "_list_kv_paths", new_callable=AsyncMock) as mock_list, \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_list.return_value = ["cert1", "cert2"]
            mock_upsert.return_value = "imported"

            result = await connector.sync(session)

        assert result["status"] == "success"
        assert result["imported"] == 2
        assert result["updated"] == 0
        assert result["total_processed"] == 2

    @pytest.mark.asyncio
    async def test_sync_nested_keys(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="")
        session = AsyncMock()

        async def mock_list(path):
            if path == "":
                return ["app/"]
            if path == "app":
                return ["tls", "db"]
            return []

        with patch.object(connector, "_list_kv_paths", side_effect=mock_list), \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_upsert.return_value = "imported"
            result = await connector.sync(session)

        assert result["status"] == "success"
        assert mock_upsert.call_count == 2

    @pytest.mark.asyncio
    async def test_sync_mixed_import_update(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="data")
        session = AsyncMock()

        with patch.object(connector, "_list_kv_paths", new_callable=AsyncMock) as mock_list, \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_list.return_value = ["cert1", "cert2", "cert3"]
            mock_upsert.side_effect = ["imported", "updated", "imported"]

            result = await connector.sync(session)

        assert result["imported"] == 2
        assert result["updated"] == 1
        assert result["total_processed"] == 3

    @pytest.mark.asyncio
    async def test_sync_with_errors(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="data")
        session = AsyncMock()

        with patch.object(connector, "_list_kv_paths", new_callable=AsyncMock) as mock_list, \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_list.return_value = ["good", "bad"]
            mock_upsert.side_effect = ["imported", Exception("permission denied")]

            result = await connector.sync(session)

        assert result["imported"] == 1
        assert result["updated"] == 0
        assert len(result["errors"]) == 1
        assert "permission denied" in result["errors"][0]

    @pytest.mark.asyncio
    async def test_sync_nested_keys_skip_subdirs(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="")
        session = AsyncMock()

        async def mock_list(path):
            if path == "":
                return ["app/"]
            if path == "app":
                return ["subdir/", "cert"]
            return []

        with patch.object(connector, "_list_kv_paths", side_effect=mock_list), \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_upsert.return_value = "imported"
            result = await connector.sync(session)

        assert result["imported"] == 1

    @pytest.mark.asyncio
    async def test_sync_nested_with_error(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="")
        session = AsyncMock()

        async def mock_list(path):
            if path == "":
                return ["app/"]
            if path == "app":
                return ["bad_cert"]
            return []

        with patch.object(connector, "_list_kv_paths", side_effect=mock_list), \
             patch.object(connector, "_upsert_secret", new_callable=AsyncMock) as mock_upsert:
            mock_upsert.side_effect = Exception("read error")
            result = await connector.sync(session)

        assert result["imported"] == 0
        assert len(result["errors"]) == 1

    @pytest.mark.asyncio
    async def test_sync_empty_keys(self):
        connector = VaultScannerConnector("https://vault:8200", "s.token", mount_point="secret", path="empty")
        session = AsyncMock()

        with patch.object(connector, "_list_kv_paths", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = []
            result = await connector.sync(session)

        assert result["status"] == "success"
        assert result["total_processed"] == 0
