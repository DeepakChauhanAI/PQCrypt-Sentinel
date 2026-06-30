import logging
import os
import httpx
from typing import Optional, Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)

# Set of environment variable names that contain sensitive data
SENSITIVE_ENV_KEYS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "GCP_CREDENTIALS_JSON",
    "VAULT_TOKEN",
    "VAULT_PASSWORD",
    "SECRET_KEY",
    "DATABASE_PASSWORD",
    "REDIS_PASSWORD",
}


def _redact_sensitive(value: Optional[str]) -> str:
    """Redact sensitive values for safe logging."""
    if not value:
        return "<empty>"
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _get_env_fallback() -> Dict[str, Any]:
    """Get credentials from environment variables.

    IMPORTANT: This function is only called when the caller has explicitly
    opted in via ``ALLOW_ENV_FALLBACK=1``. Reading cloud credentials from
    ``os.environ`` is otherwise a credential-leakage path and is denied
    by default. The returned dict has no logging; presence is never logged.
    """
    fallback = {
        "aws_access_key_id": os.environ.get("AWS_ACCESS_KEY_ID")
        or os.environ.get("AWS_ACCESS_KEY"),
        "aws_secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY")
        or os.environ.get("AWS_SECRET_KEY"),
        "client_id": os.environ.get("AZURE_CLIENT_ID"),
        "client_secret": os.environ.get("AZURE_CLIENT_SECRET"),
        "tenant_id": os.environ.get("AZURE_TENANT_ID"),
        "credentials_json": os.environ.get("GCP_CREDENTIALS_JSON"),
    }
    return fallback


async def get_vault_secret(
    vault_path: str, version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve a secret from HashiCorp Vault using KV engine.
    Supports KV v2 (try first) and KV v1 (fallback).

    Security: environment-variable fallback requires an explicit
    ``ALLOW_ENV_FALLBACK=1`` opt-in (see _get_env_fallback). When Vault
    is unconfigured AND the opt-in is missing, this returns an empty
    dict — never silently reads AWS/Azure/GCP credentials from the
    process environment.
    """
    vault_url = os.environ.get("VAULT_URL") or settings.VAULT_URL
    vault_token = os.environ.get("VAULT_TOKEN") or settings.VAULT_TOKEN
    namespace = os.environ.get("VAULT_NAMESPACE") or settings.VAULT_NAMESPACE

    if not vault_url or not vault_token:
        if os.environ.get("ALLOW_ENV_FALLBACK") != "1":
            logger.warning(
                "Vault is not configured (VAULT_URL/VAULT_TOKEN not set) and "
                "ALLOW_ENV_FALLBACK is not enabled. Returning empty secret. "
                "Set VAULT_URL/VAULT_TOKEN, or ALLOW_ENV_FALLBACK=1 to opt in "
                "to env-var fallback."
            )
            return {}
        return _get_env_fallback()

    headers = {"X-Vault-Token": vault_token}
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    parts = [p for p in vault_path.strip("/").split("/") if p]
    if not parts:
        return {}

    mount = parts[0]
    subpath = "/".join(parts[1:])

    # Try KV v2
    v2_url = f"{vault_url.rstrip('/')}/v1/{mount}/data/{subpath}"
    params = {}
    if version:
        params["version"] = version

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(v2_url, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    inner_data = data.get("data")
                    if isinstance(inner_data, dict):
                        secret_data = inner_data.get("data")
                        if isinstance(secret_data, dict):
                            return secret_data
                        return inner_data

            # Try KV v1
            v1_url = f"{vault_url.rstrip('/')}/v1/{vault_path.lstrip('/')}"
            resp = await client.get(v1_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    return data.get("data", {})
    except Exception as e:
        logger.error(
            f"Error fetching secret from Vault path {vault_path}: {_redact_sensitive(str(e))}"
        )

    return {}
