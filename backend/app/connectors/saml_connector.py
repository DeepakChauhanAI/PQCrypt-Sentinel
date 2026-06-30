import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.models.models import Asset
from app.scanners.cert_parser import parse_certificate

logger = logging.getLogger(__name__)


class SAMLMetadataConnector(BaseConnector):
    """
    SAML metadata scanner connector.
    Accepts a metadata URL or XML blob and extracts public keys / certificates.
    """

    def __init__(
        self,
        metadata_url: Optional[str] = None,
        xml_blob: Optional[str] = None,
        credentials_ref: Any = None,
    ):
        super().__init__("SAML Metadata Connector")
        self.metadata_url = metadata_url
        self.xml_blob = xml_blob
        self.credentials_ref = credentials_ref

    async def _get_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference if any."""
        if not self.credentials_ref:
            return {}
        from app.connectors.vault_helper import get_vault_secret

        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)

        return await get_vault_secret(vault_path, version)

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        import httpx

        imported = 0
        updated = 0
        errors: List[str] = []

        xml_content = self.xml_blob

        if not xml_content and self.metadata_url:
            try:
                from urllib.parse import urlparse
                from app.scanners.safe_target import resolve_safely

                parsed = urlparse(self.metadata_url)
                if not parsed.hostname:
                    raise ValueError("SAML metadata URL must have a hostname")

                # Verify that the URL hostname is SSRF safe
                await resolve_safely(parsed.hostname)

                creds = await self._get_credentials()
                headers = {}
                token = creds.get("token") or creds.get("api_key")
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
                    resp = await client.get(self.metadata_url, headers=headers)
                    if resp.status_code != 200:
                        raise RuntimeError(f"HTTP error: {resp.status_code}")
                    xml_content = resp.text
            except Exception as exc:
                errors.append(f"Failed to fetch SAML metadata URL: {exc}")

        if not xml_content:
            return {
                "status": "error",
                "imported": 0,
                "updated": 0,
                "errors": errors or ["No XML content or metadata URL provided."],
            }

        def parse_xml() -> Dict[str, List[str]]:
            root = ET.fromstring(  # nosec B314
                xml_content.encode("utf-8")
                if isinstance(xml_content, str)
                else xml_content
            )

            certificates = []
            name_id_formats = []
            bindings = []

            for elem in root.iter():
                # Extract certificate
                if elem.tag.endswith("X509Certificate"):
                    if elem.text:
                        cert_text = (
                            elem.text.strip()
                            .replace(" ", "")
                            .replace("\n", "")
                            .replace("\r", "")
                        )
                        if cert_text:
                            # Format as PEM
                            pem = f"-----BEGIN CERTIFICATE-----\n{cert_text}\n-----END CERTIFICATE-----"
                            certificates.append(pem)
                # Extract NameIDFormat
                elif elem.tag.endswith("NameIDFormat"):
                    if elem.text:
                        name_id_formats.append(elem.text.strip())
                # Extract Binding type
                elif (
                    elem.tag.endswith("SingleSignOnService")
                    or elem.tag.endswith("SingleLogoutService")
                    or elem.tag.endswith("AssertionConsumerService")
                ):
                    binding = elem.attrib.get("Binding")
                    if binding:
                        bindings.append(binding)

            return {
                "certificates": list(set(certificates)),
                "name_id_formats": list(set(name_id_formats)),
                "bindings": list(set(bindings)),
            }

        try:
            xml_parsed: Dict[str, List[str]] = await asyncio.to_thread(parse_xml)
        except Exception as exc:
            return {
                "status": "error",
                "imported": 0,
                "updated": 0,
                "errors": [f"XML parsing failed: {exc}"],
            }

        for pem in xml_parsed["certificates"]:
            try:
                cert_meta = parse_certificate(pem)
                thumbprint = cert_meta["thumbprint"]

                asset_name = f"saml-cert:{thumbprint[:16]}"
                stmt = select(Asset).where(
                    Asset.name == asset_name, Asset.deleted_at.is_(None)
                )
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                metadata = {
                    "provider": "saml",
                    "discovery_source": "saml_metadata",
                    "subject": cert_meta["subject"],
                    "issuer": cert_meta["issuer"],
                    "sig_algorithm": cert_meta["sig_algorithm"],
                    "pub_key_algorithm": cert_meta["pub_key_algorithm"],
                    "pub_key_size": cert_meta["pub_key_size"],
                    "curve_name": cert_meta["curve_name"],
                    "not_before": cert_meta["not_before"].isoformat(),
                    "not_after": cert_meta["not_after"].isoformat(),
                    "pqc_capable": cert_meta["pqc_capable"],
                    "pqc_status": cert_meta["pqc_details"]["pqc_status"],
                    "name_id_formats": xml_parsed["name_id_formats"],
                    "bindings": xml_parsed["bindings"],
                    "metadata_url": self.metadata_url,
                }

                if existing:
                    existing.asset_type = "saml_metadata"
                    existing.asset_metadata = metadata
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="saml_metadata",
                        environment="onprem" if not self.metadata_url else "cloud",
                        discovery_source="saml_metadata",
                        asset_metadata=metadata,
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"Failed to process certificate: {exc}")

        return {
            "status": "success" if not errors else "partial",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }
