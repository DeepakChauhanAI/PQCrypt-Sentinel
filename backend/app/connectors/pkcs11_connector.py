import asyncio
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.models.models import Asset

logger = logging.getLogger(__name__)


class PKCS11Connector(BaseConnector):
    """
    PKCS#11 HSM enumeration connector.
    Uses the python-pkcs11 library to enumerate HSM objects.
    """

    def __init__(
        self,
        library_path: str,
        credentials_ref: Any,
        slot_id: Optional[int] = None,
        token_label: Optional[str] = None,
    ):
        super().__init__(f"PKCS#11 HSM ({library_path})")
        self.library_path = library_path
        self.credentials_ref = credentials_ref
        self.slot_id = slot_id
        self.token_label = token_label

    async def _get_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference."""
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "pin" in self.credentials_ref
            or "user_pin" in self.credentials_ref
        ):
            return self.credentials_ref

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
        try:
            import pkcs11
        except ImportError as exc:
            raise RuntimeError("python-pkcs11 is required for PKCS#11 connector") from exc

        creds = await self._get_credentials()
        user_pin = creds.get("user_pin") or creds.get("pin")
        so_pin = creds.get("so_pin")

        if not user_pin:
            raise RuntimeError("PKCS#11 connector requires user_pin from vault")

        imported = 0
        updated = 0
        errors: List[str] = []

        def get_hsm_objects():
            lib = pkcs11.lib(self.library_path)
            slots = lib.get_slots(token_present=True)
            results = []
            for slot in slots:
                if self.slot_id is not None and slot.slot_id != self.slot_id:
                    continue
                try:
                    token = slot.get_token()
                    if self.token_label and token.label != self.token_label:
                        continue
                    with token.open(user_pin=user_pin, rw=False) as session_pkcs11:
                        for obj in session_pkcs11.get_objects():
                            try:
                                obj_class = obj.get_attribute(pkcs11.Attribute.CLASS)
                                obj_label = obj.get_attribute(pkcs11.Attribute.LABEL, "")
                                obj_id = obj.get_attribute(pkcs11.Attribute.ID, b"")
                                key_type = obj.get_attribute(pkcs11.Attribute.KEY_TYPE, None)
                                key_size = None
                                if obj_class in (pkcs11.ObjectClass.PUBLIC_KEY, pkcs11.ObjectClass.PRIVATE_KEY, pkcs11.ObjectClass.SECRET_KEY):
                                    if hasattr(pkcs11.Attribute, "MODULUS_BITS"):
                                        try:
                                            key_size = obj.get_attribute(pkcs11.Attribute.MODULUS_BITS)
                                        except Exception:
                                            pass
                                    if key_size is None and hasattr(pkcs11.Attribute, "VALUE_BITS"):
                                        try:
                                            key_size = obj.get_attribute(pkcs11.Attribute.VALUE_BITS)
                                        except Exception:
                                            pass
                                key_type_str = str(key_type) if key_type else "UNKNOWN"
                                results.append({
                                    "token_label": token.label,
                                    "slot_id": slot.slot_id,
                                    "object_label": obj_label,
                                    "object_id": obj_id.hex() if isinstance(obj_id, bytes) else str(obj_id),
                                    "object_class": str(obj_class) if obj_class else "UNKNOWN",
                                    "key_type": key_type_str,
                                    "key_size": key_size,
                                })
                            except Exception as exc:
                                errors.append(f"Object {getattr(obj, 'label', 'unknown')}: {exc}")
                except Exception as exc:
                    errors.append(f"Slot {slot.slot_id}: {exc}")
            return results

        try:
            hsm_objects = await asyncio.to_thread(get_hsm_objects)
        except Exception as exc:
            errors.append(f"HSM connection failed: {exc}")
            hsm_objects = []

        for obj in hsm_objects:
            try:
                asset_name = f"pkcs11:{obj['token_label']}:{obj['object_label'] or obj['object_id']}"
                stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                metadata = {
                    "provider": "pkcs11",
                    "library": self.library_path,
                    "slot_id": obj["slot_id"],
                    "token_label": obj["token_label"],
                    "object_label": obj["object_label"],
                    "object_id": obj["object_id"],
                    "object_class": obj["object_class"],
                    "key_type": obj["key_type"],
                    "key_size": obj["key_size"],
                }

                if existing:
                    existing.asset_type = "hsm_key"
                    existing.asset_metadata = metadata
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="hsm_key",
                        environment="onprem",
                        discovery_source="pkcs11",
                        asset_metadata=metadata,
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"Database error for asset {obj.get('object_label')}: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }


class KMIPConnector(BaseConnector):
    """
    KMIP KMS scan connector.
    Connects to a KMIP server over TLS and performs Locate/GetAttributes operations.
    """

    def __init__(
        self,
        host: str,
        port: int,
        credentials_ref: Any,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
    ):
        super().__init__(f"KMIP KMS ({host}:{port})")
        self.host = host
        self.port = port
        self.credentials_ref = credentials_ref
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.ca_cert_path = ca_cert_path

    async def _get_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference."""
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref
            or "client_cert" in self.credentials_ref
            or "client_key" in self.credentials_ref
        ):
            return self.credentials_ref

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
        try:
            from kmip import client as kmip_client
            from kmip.core import enums as kmip_enums
            from kmip.pie import objects as kmip_objects
        except ImportError as exc:
            raise RuntimeError("python-kmip is required for KMIP connector") from exc

        creds = await self._get_credentials()
        
        imported = 0
        updated = 0
        errors: List[str] = []

        def get_kmip_objects():
            import ssl as _ssl
            client = kmip_client.KMIPClient(
                hostname=self.host,
                port=self.port,
                cert=self.client_cert_path or creds.get("client_cert"),
                key=self.client_key_path or creds.get("client_key"),
                ca=self.ca_cert_path or creds.get("ca_cert"),
                username=creds.get("username"),
                password=creds.get("password"),
                ssl_version=_ssl.PROTOCOL_TLSv1_2,
            )
            client.open()
            try:
                uuids = client.locate()
                results = []
                for uuid in uuids:
                    try:
                        obj = client.get(uuid)
                        name = getattr(obj, 'name', uuid)
                        obj_type = getattr(obj, 'object_type', 'UNKNOWN')
                        crypto_alg = getattr(obj, 'cryptographic_algorithm', 'UNKNOWN')
                        key_length = getattr(obj, 'cryptographic_length', None)
                        state = getattr(obj, 'state', 'UNKNOWN')
                        usage_mask = getattr(obj, 'usage_mask', None)
                        activation_date = getattr(obj, 'activation_date', None)
                        deactivation_date = getattr(obj, 'deactivation_date', None)
                        
                        results.append({
                            "uuid": uuid,
                            "name": name,
                            "object_type": str(obj_type),
                            "crypto_algorithm": str(crypto_alg),
                            "key_length": key_length,
                            "state": str(state),
                            "usage_mask": str(usage_mask) if usage_mask else None,
                            "activation_date": str(activation_date) if activation_date else None,
                            "deactivation_date": str(deactivation_date) if deactivation_date else None,
                        })
                    except Exception as exc:
                        errors.append(f"KMIP object {uuid}: {exc}")
                return results
            finally:
                client.close()

        try:
            kmip_objects_list = await asyncio.to_thread(get_kmip_objects)
        except Exception as exc:
            errors.append(f"KMIP connection failed: {exc}")
            kmip_objects_list = []

        for obj in kmip_objects_list:
            try:
                uuid = obj["uuid"]
                asset_name = f"kmip:{self.host}:{uuid}"
                stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                
                metadata = {
                    "provider": "kmip",
                    "host": self.host,
                    "port": self.port,
                    "uuid": uuid,
                    "name": obj["name"],
                    "object_type": obj["object_type"],
                    "crypto_algorithm": obj["crypto_algorithm"],
                    "key_length": obj["key_length"],
                    "state": obj["state"],
                    "usage_mask": obj["usage_mask"],
                    "activation_date": obj["activation_date"],
                    "deactivation_date": obj["deactivation_date"],
                }
                
                if existing:
                    existing.asset_type = "kms_key"
                    existing.asset_metadata = metadata
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="kms_key",
                        environment="onprem",
                        discovery_source="kmip",
                        asset_metadata=metadata,
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"Database error for KMIP object {obj.get('uuid')}: {exc}")

        return {
            "status": "success" if not errors else "partial",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }


class ADCSConnector(BaseConnector):
    """
    ADCS/LDAP certificate enumeration connector.
    Queries Active Directory Certificate Services via LDAP.
    """

    def __init__(
        self,
        domain_controller: str,
        credentials_ref: Any,
        base_dn: Optional[str] = None,
        use_ldaps: bool = True,
    ):
        super().__init__(f"ADCS/LDAP ({domain_controller})")
        self.domain_controller = domain_controller
        self.credentials_ref = credentials_ref
        self.base_dn = base_dn
        self.use_ldaps = use_ldaps

    async def _get_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference."""
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref
            or "password" in self.credentials_ref
        ):
            return self.credentials_ref

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
        try:
            import ldap3
        except ImportError as exc:
            raise RuntimeError("ldap3 is required for ADCS connector") from exc

        creds = await self._get_credentials()
        username = creds.get("username") or creds.get("bind_dn")
        password = creds.get("password") or creds.get("bind_password")

        if not username or not password:
            raise RuntimeError("ADCS connector requires username/password from vault")

        imported = 0
        updated = 0
        errors: List[str] = []

        def get_adcs_entries():
            port = 636 if self.use_ldaps else 389
            server = ldap3.Server(
                self.domain_controller,
                port=port,
                use_ssl=self.use_ldaps,
                get_info=ldap3.ALL,
            )
            conn = ldap3.Connection(
                server,
                user=username,
                password=password,
                authentication=ldap3.SIMPLE,
                auto_bind=True,
            )
            # Base DN for ADCS - typically CN=Configuration,DC=domain,DC=com
            search_base = self.base_dn or f"CN=Configuration,{username.split('@')[1]}"
            conn.search(
                search_base=search_base,
                search_filter="(objectClass=pKIEnrollmentService)",
                attributes=[
                    "cn",
                    "dNSHostName",
                    "cACertificateDN",
                    "certificateTemplates",
                    "flags",
                ],
            )
            results = []
            for entry in conn.entries:
                ca_name = str(entry.cn) if entry.cn else "unknown"
                dns_host = str(entry.dNSHostName) if entry.dNSHostName else ""
                results.append({
                    "ca_name": ca_name,
                    "dns_host": dns_host,
                    "ca_certificate_dn": str(entry.cACertificateDN) if entry.cACertificateDN else "",
                    "certificate_templates": [str(t) for t in entry.certificateTemplates] if entry.certificateTemplates else [],
                    "flags": str(entry.flags) if entry.flags else "",
                })
            return results

        try:
            adcs_entries = await asyncio.to_thread(get_adcs_entries)
        except Exception as exc:
            errors.append(f"ADCS connection failed: {exc}")
            adcs_entries = []

        for entry in adcs_entries:
            try:
                ca_name = entry["ca_name"]
                asset_name = f"adcs:{ca_name}"
                stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                metadata = {
                    "provider": "adcs",
                    "domain_controller": self.domain_controller,
                    "ca_name": ca_name,
                    "dns_host": entry["dns_host"],
                    "ca_certificate_dn": entry["ca_certificate_dn"],
                    "certificate_templates": entry["certificate_templates"],
                    "flags": entry["flags"],
                }

                if existing:
                    existing.asset_type = "certificate_authority"
                    existing.asset_metadata = metadata
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="certificate_authority",
                        environment="onprem",
                        discovery_source="adcs",
                        asset_metadata=metadata,
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"Database error for CA entry {entry.get('ca_name')}: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }