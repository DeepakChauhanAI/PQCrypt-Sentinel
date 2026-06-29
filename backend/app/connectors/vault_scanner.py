import asyncio
import logging
from typing import Any, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.models.models import Asset

logger = logging.getLogger(__name__)


class VaultScannerConnector(BaseConnector):
    """Scan HashiCorp Vault for cryptographic material in secrets."""

    def __init__(self, vault_url: str, token: str, mount_point: str = "secret", path: str = ""):
        super().__init__(f"Vault Scanner ({vault_url})")
        self.vault_url = vault_url.rstrip("/")
        self.token = token
        self.mount_point = mount_point.strip("/")
        self.path = path.strip("/")

    async def _vault_request(self, method: str, vpath: str) -> Dict[str, Any]:
        import httpx
        url = f"{self.vault_url}/v1/{vpath}"
        headers = {"X-Vault-Token": self.token}
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.request(method, url, headers=headers)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            if resp.status_code == 204:
                return {}
            try:
                return resp.json()
            except Exception:
                return {}

    async def _list_kv_paths(self, full_path: str) -> List[str]:
        target = f"{self.mount_point}/metadata/{full_path or ''}"
        try:
            data = await self._vault_request("GET", f"{target}?list=true")
            return data.get("data", {}).get("keys", []) or []
        except Exception as e:
            logger.warning(f"Cannot list Vault path {target}: {e}")
            return []

    async def _read_kv_entry(self, full_path: str) -> Dict[str, Any]:
        target = f"{self.mount_point}/data/{full_path}"
        try:
            data = await self._vault_request("GET", target)
            return data.get("data", {}).get("data", {}) or {}
        except Exception as e:
            logger.debug(f"Cannot read Vault entry {target}: {e}")
            return {}

    async def _upsert_secret(self, session: AsyncSession, secret_path: str) -> str:
        secret_data = await self._read_kv_entry(secret_path)
        has_cert = any(k in secret_data for k in ("cert", "certificate", "tls_cert", "ca_cert"))
        has_key = any(k in secret_data for k in ("private_key", "key", "tls_key"))

        asset_name = f"vault:{self.mount_point}:{secret_path}"
        stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        metadata = {
            "provider": "hashicorp_vault",
            "mount_point": self.mount_point,
            "path": secret_path,
            "has_certificate": has_cert,
            "has_private_key": has_key,
            "keys": list(secret_data.keys()),
        }

        if existing:
            existing.asset_type = "saas"
            existing.asset_metadata = metadata
            await session.flush()
            return "updated"

        asset = Asset(
            name=asset_name,
            asset_type="saas",
            environment="cloud",
            discovery_source="vault_secrets",
            asset_metadata=metadata,
        )
        session.add(asset)
        await session.flush()
        return "imported"

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        imported = 0
        updated = 0
        errors: List[str] = []

        base_path = self.path
        keys = await self._list_kv_paths(base_path)

        for key in keys:
            if key.endswith("/"):
                sub = f"{base_path}/{key}" if base_path else key
                sub_keys = await self._list_kv_paths(sub.rstrip("/"))
                for sk in sub_keys:
                    if sk.endswith("/"):
                        continue
                    full = f"{sub.rstrip('/')}/{sk}"
                    try:
                        status = await self._upsert_secret(session, full)
                        if status == "imported":
                            imported += 1
                        else:
                            updated += 1
                    except Exception as exc:
                        errors.append(f"Vault secret {full}: {exc}")
            else:
                full = f"{base_path}/{key}" if base_path else key
                try:
                    status = await self._upsert_secret(session, full)
                    if status == "imported":
                        imported += 1
                    else:
                        updated += 1
                except Exception as exc:
                    errors.append(f"Vault secret {full}: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }
