import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from app.connectors.vault_helper import _redact_sensitive, _get_env_fallback, get_vault_secret

def test_redact_sensitive():
    assert _redact_sensitive(None) == "<empty>"
    assert _redact_sensitive("") == "<empty>"
    assert _redact_sensitive("abc") == "****"
    assert _redact_sensitive("abcd") == "****"
    assert _redact_sensitive("abcde") == "ab*de"
    assert _redact_sensitive("abcdef") == "ab**ef"
    assert _redact_sensitive("sensitive_value") == "se***********ue"


def test_get_env_fallback(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws_id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_secret")
    monkeypatch.setenv("AZURE_CLIENT_ID", "azure_id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "azure_secret")
    monkeypatch.setenv("AZURE_TENANT_ID", "azure_tenant")
    monkeypatch.setenv("GCP_CREDENTIALS_JSON", '{"type": "service_account"}')

    res = _get_env_fallback()
    assert res["aws_access_key_id"] == "aws_id"
    assert res["aws_secret_access_key"] == "aws_secret"
    assert res["client_id"] == "azure_id"
    assert res["client_secret"] == "azure_secret"
    assert res["tenant_id"] == "azure_tenant"
    assert res["credentials_json"] == '{"type": "service_account"}'


@pytest.mark.asyncio
async def test_get_vault_secret_no_config(monkeypatch):
    monkeypatch.delenv("VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("ALLOW_ENV_FALLBACK", raising=False)
    
    # 1. Without ALLOW_ENV_FALLBACK
    res = await get_vault_secret("secret/data")
    assert res == {}

    # 2. With ALLOW_ENV_FALLBACK
    monkeypatch.setenv("ALLOW_ENV_FALLBACK", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "env_aws_key")
    res = await get_vault_secret("secret/data")
    assert res["aws_access_key_id"] == "env_aws_key"


@pytest.mark.asyncio
async def test_get_vault_secret_empty_path(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    
    res = await get_vault_secret("")
    assert res == {}
    
    res = await get_vault_secret("/")
    assert res == {}


@pytest.mark.asyncio
async def test_get_vault_secret_kv2_success(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    monkeypatch.setenv("VAULT_NAMESPACE", "test-namespace")

    # KV v2 JSON response structure with data.data
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "data": {
                "foo": "bar"
            }
        }
    }

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp

    mock_async_client_cm = MagicMock()
    mock_async_client_cm.__aenter__.return_value = mock_client
    mock_async_client_cm.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_async_client_cm):
        res = await get_vault_secret("secret/my-mount/my-secret", version="2")
        assert res == {"foo": "bar"}
        # Check call arguments
        mock_client.get.assert_called_once()
        args, kwargs = mock_client.get.call_args
        assert args[0] == "http://vault:8200/v1/secret/data/my-mount/my-secret"
        assert kwargs["headers"]["X-Vault-Token"] == "test-token"
        assert kwargs["headers"]["X-Vault-Namespace"] == "test-namespace"
        assert kwargs["params"] == {"version": "2"}


@pytest.mark.asyncio
async def test_get_vault_secret_kv2_data_only(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    # KV v2 structure with data but no data.data
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "foo2": "bar2"
        }
    }

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp

    mock_async_client_cm = MagicMock()
    mock_async_client_cm.__aenter__.return_value = mock_client
    mock_async_client_cm.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_async_client_cm):
        res = await get_vault_secret("secret/my-secret")
        assert res == {"foo2": "bar2"}


@pytest.mark.asyncio
async def test_get_vault_secret_kv1_fallback(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    # First call (v2) returns 404
    mock_resp_v2 = MagicMock()
    mock_resp_v2.status_code = 404

    # Second call (v1) returns 200
    mock_resp_v1 = MagicMock()
    mock_resp_v1.status_code = 200
    mock_resp_v1.json.return_value = {
        "data": {
            "foo_v1": "bar_v1"
        }
    }

    mock_client = AsyncMock()
    mock_client.get.side_effect = [mock_resp_v2, mock_resp_v1]

    mock_async_client_cm = MagicMock()
    mock_async_client_cm.__aenter__.return_value = mock_client
    mock_async_client_cm.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_async_client_cm):
        res = await get_vault_secret("secret/my-secret")
        assert res == {"foo_v1": "bar_v1"}
        assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_get_vault_secret_exception_handling(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    mock_client = AsyncMock()
    mock_client.get.side_effect = RuntimeError("Connection dropped")

    mock_async_client_cm = MagicMock()
    mock_async_client_cm.__aenter__.return_value = mock_client
    mock_async_client_cm.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_async_client_cm):
        res = await get_vault_secret("secret/my-secret")
        assert res == {}
