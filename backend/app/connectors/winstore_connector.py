"""
Windows Certificate Store (L7 Endpoint layer) connector.

This is a *passive* inventory connector: it parses a `certutil -store -user`
(or `-store -enterprise`) dump produced elsewhere on the system, and
persists the certificates it finds as Assets with `asset_type=
windows_cert_store`.

We deliberately avoid any direct Win32 API calls (pywin32, ctypes) so
that the connector is safe to import on Linux build agents and CI.
The calling code (a separate Win32 service or scheduled task) is
expected to write the dump to a file path and pass it to `sync()`.
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import BaseConnector
from app.models.models import Asset
from app.services.layer_service import layer_for_asset

logger = logging.getLogger(__name__)


# Lines emitted by `certutil -store -user` / `-store -enterprise` look like:
#   ============== Certificate 0 ==============
#   Serial Number: 33...
#   Issuer: CN=Test CA, O=Example
#   Subject: CN=host.example.com
#   NotBefore: 1/1/2024 12:00 AM
#   NotAfter:  1/1/2025 12:00 AM
#   Signature matches Public Key
#   Root Certificate: Subject matches Issuer
#   Cert Hash(sha1): aa bb cc ...
_CERT_HEADER_RE = re.compile(r"^={2,}\s*Certificate\s+(\d+)\s*={2,}$", re.IGNORECASE)
_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _\-]+?):\s*(.+)$")


class WindowsCertStoreConnector(BaseConnector):
    """
    Parser for `certutil -store` output.

    Parameters
    ----------
    store_name:
        The Windows store name (e.g. "My", "Root", "CA"). Captured in
        the asset metadata for downstream filtering.
    store_kind:
        Either "user" or "enterprise" (machine-level). Default: "user".
    """

    def __init__(self, store_name: str = "My", store_kind: str = "user"):
        if store_kind not in {"user", "enterprise"}:
            raise ValueError("store_kind must be 'user' or 'enterprise'")
        super().__init__(f"Windows Cert Store ({store_name}/{store_kind})")
        self.store_name = store_name
        self.store_kind = store_kind

    async def sync(
        self,
        session: AsyncSession,
        dump_path: Optional[str] = None,
        dump_text: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Parse a `certutil -store` dump and persist each certificate.

        Provide one of `dump_path` (path to a text file produced by
        certutil) or `dump_text` (the raw output as a string).
        """
        if not dump_path and not dump_text:
            return {
                "status": "error",
                "error": "must supply dump_path or dump_text",
                "imported": 0,
                "updated": 0,
                "skipped": 0,
                "errors": [],
            }

        try:
            text = dump_text if dump_text is not None else Path(dump_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {
                "status": "error",
                "error": f"could not read dump: {exc}",
                "imported": 0,
                "updated": 0,
                "skipped": 0,
                "errors": [],
            }

        blocks = self._parse_blocks(text)
        imported = 0
        updated = 0
        errors: List[str] = []
        for idx, block in enumerate(blocks):
            if not block.get("subject"):
                errors.append(f"block {idx}: no subject")
                continue
            digest = hashlib.sha256(
                f"{block.get('subject')}|{block.get('issuer')}|{block.get('serial_number')}".encode("utf-8")
            ).hexdigest()[:32]
            asset_name = f"winstore:{self.store_name}:{digest}"
            metadata = {
                "provider": "windows_cert_store",
                "store_name": self.store_name,
                "store_kind": self.store_kind,
                "subject": block.get("subject"),
                "issuer": block.get("issuer"),
                "serial_number": block.get("serial_number"),
                "not_before": block.get("not_before"),
                "not_after": block.get("not_after"),
                "sha1_fingerprint": block.get("sha1"),
                "raw_dump_keys": sorted(k for k in block.keys() if k not in {"subject", "issuer", "serial_number", "not_before", "not_after", "sha1"}),
            }
            stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()
            layer = layer_for_asset(_FakeAsset("windows_cert_store"))
            metadata["layer"] = layer
            if existing:
                existing.asset_metadata = metadata
                existing.asset_type = "windows_cert_store"
                existing.discovery_source = "windows_cert_store"
                updated += 1
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="windows_cert_store",
                    environment="endpoint",
                    discovery_source="windows_cert_store",
                    asset_metadata=metadata,
                )
                session.add(asset)
                imported += 1

        try:
            await session.flush()
        except Exception as exc:
            await session.rollback()
            return {
                "status": "error",
                "error": f"flush failed: {exc}",
                "imported": 0,
                "updated": 0,
                "skipped": len(errors),
                "errors": errors,
            }

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "skipped": len(errors),
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_blocks(text: str) -> List[Dict[str, str]]:
        """Split the certutil output into one dict per certificate."""
        blocks: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for line in text.splitlines():
            header = _CERT_HEADER_RE.match(line.strip())
            if header:
                if current:
                    blocks.append(current)
                current = {}
                continue
            field = _FIELD_RE.match(line.rstrip())
            if field and current is not None:
                key = field.group(1).strip().lower().replace(" ", "_")
                value = field.group(2).strip()
                current[key] = value
        if current:
            blocks.append(current)
        return blocks


class _FakeAsset:
    def __init__(self, asset_type: str):
        self.asset_type = asset_type
        self.discovery_source = asset_type
        self.asset_metadata: Dict[str, Any] = {}


__all__ = ["WindowsCertStoreConnector"]
