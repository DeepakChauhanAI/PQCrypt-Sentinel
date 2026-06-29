import asyncio
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.connectors.base import BaseConnector
from app.models.models import Asset

logger = logging.getLogger(__name__)


class AWSKMSConnector(BaseConnector):
    def __init__(self, credentials_ref: Any, region: str = "us-east-1"):
        super().__init__(f"AWS KMS ({region})")
        self.credentials_ref = credentials_ref
        self.region = region

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS KMS connector") from exc

        # Resolve Vault credential reference
        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)

        from app.connectors.vault_helper import get_vault_secret
        secret = await get_vault_secret(vault_path, version)

        aws_access_key_id = secret.get("aws_access_key_id") or secret.get("access_key_id")
        aws_secret_access_key = secret.get("aws_secret_access_key") or secret.get("secret_access_key")

        client_kwargs = {"region_name": self.region}
        if aws_access_key_id:
            client_kwargs["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            client_kwargs["aws_secret_access_key"] = aws_secret_access_key

        kms = await asyncio.to_thread(boto3.client, "kms", **client_kwargs)

        imported = 0
        updated = 0
        errors: List[str] = []

        def get_all_keys():
            paginator = kms.get_paginator("list_keys")
            keys = []
            for page in paginator.paginate():
                keys.extend(page.get("Keys", []))
            return keys

        keys = await asyncio.to_thread(get_all_keys)
        for key in keys:
            key_id = key.get("KeyId")
            try:
                def describe_and_policy():
                    desc = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    try:
                        policy = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "{}")
                    except Exception:
                        policy = "{}"
                    return desc, policy

                desc, policy = await asyncio.to_thread(describe_and_policy)
                key_spec = desc.get("KeySpec", "UNKNOWN")
                key_usage = desc.get("KeyUsage", "UNKNOWN")
                origin = desc.get("Origin", "UNKNOWN")

                asset_name = f"aws-kms:{key_id}"
                stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                if existing:
                    existing.asset_type = "kms"
                    existing.asset_metadata = {
                        "provider": "aws",
                        "key_id": key_id,
                        "key_spec": key_spec,
                        "key_usage": key_usage,
                        "origin": origin,
                        "arn": desc.get("Arn", ""),
                    }
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="kms",
                        environment="cloud",
                        discovery_source="aws_kms",
                        asset_metadata={
                            "provider": "aws",
                            "key_id": key_id,
                            "key_spec": key_spec,
                            "key_usage": key_usage,
                            "origin": origin,
                            "arn": desc.get("Arn", ""),
                        },
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"AWS KMS key {key_id}: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }


class AzureKeyVaultConnector(BaseConnector):
    def __init__(self, credentials_ref: Any, tenant_id: str, vault_url: str):
        super().__init__(f"Azure Key Vault ({vault_url})")
        self.credentials_ref = credentials_ref
        self.tenant_id = tenant_id
        self.vault_url = vault_url

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            from azure.identity import ClientSecretCredential
            from azure.keyvault.keys import KeyClient
        except ImportError as exc:
            raise RuntimeError("azure-identity and azure-keyvault-keys are required") from exc

        if isinstance(self.credentials_ref, dict) and (
            "client_id" in self.credentials_ref or "client_secret" in self.credentials_ref
        ):
            secret = self.credentials_ref
        else:
            vault_path = ""
            version = None
            if isinstance(self.credentials_ref, dict):
                vault_path = self.credentials_ref.get("vault_path", "")
                version = self.credentials_ref.get("version")
            elif hasattr(self.credentials_ref, "vault_path"):
                vault_path = getattr(self.credentials_ref, "vault_path", "")
                version = getattr(self.credentials_ref, "version", None)

            from app.connectors.vault_helper import get_vault_secret
            secret = await get_vault_secret(vault_path, version)

        client_id = secret.get("client_id") if isinstance(secret, dict) else None
        client_secret = secret.get("client_secret") if isinstance(secret, dict) else None
        tenant_id = (self.tenant_id or (secret.get("tenant_id") if isinstance(secret, dict) else None))

        if client_id and client_secret and tenant_id:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()

        key_client = KeyClient(vault_url=self.vault_url, credential=credential)

        imported = 0
        updated = 0
        errors: List[str] = []

        def get_all_key_properties():
            return list(key_client.list_properties_of_keys())

        key_properties = await asyncio.to_thread(get_all_key_properties)

        for key in key_properties:
            try:
                key_name = key.name
                asset_name = f"azure-kv:{key_name}"

                stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                vault_key = await asyncio.to_thread(key_client.get_key, key_name)
                key_type = getattr(vault_key, "key_type", "UNKNOWN")

                if existing:
                    existing.asset_type = "kms"
                    existing.asset_metadata = {
                        "provider": "azure",
                        "vault": self.vault_url,
                        "key_name": key_name,
                        "key_type": key_type,
                        "version": vault_key.properties.version,
                    }
                    updated += 1
                else:
                    asset = Asset(
                        name=asset_name,
                        asset_type="kms",
                        environment="cloud",
                        discovery_source="azure_key_vault",
                        asset_metadata={
                            "provider": "azure",
                            "vault": self.vault_url,
                            "key_name": key_name,
                            "key_type": key_type,
                            "version": vault_key.properties.version,
                        },
                    )
                    session.add(asset)
                    imported += 1
            except Exception as exc:
                errors.append(f"Azure KV key {key.name}: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }


class GCPKMSConnector(BaseConnector):
    def __init__(self, project_id: str, credentials_ref: Any):
        super().__init__(f"GCP KMS ({project_id})")
        self.project_id = project_id
        self.credentials_ref = credentials_ref

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            from google.cloud import kms_v1
        except ImportError as exc:
            raise RuntimeError("google-cloud-kms is required") from exc

        if isinstance(self.credentials_ref, dict) and (
            "credentials_json" in self.credentials_ref or "private_key" in self.credentials_ref
        ):
            secret = self.credentials_ref
        else:
            vault_path = ""
            version = None
            if isinstance(self.credentials_ref, dict):
                vault_path = self.credentials_ref.get("vault_path", "")
                version = self.credentials_ref.get("version")
            elif hasattr(self.credentials_ref, "vault_path"):
                vault_path = getattr(self.credentials_ref, "vault_path", "")
                version = getattr(self.credentials_ref, "version", None)

            from app.connectors.vault_helper import get_vault_secret
            secret = await get_vault_secret(vault_path, version)

        # Allow direct credentials_json passed from API payload kwargs (frontend path)
        if not secret and kwargs.get("credentials_json"):
            secret = {"credentials_json": kwargs["credentials_json"]}

        import json
        client = None
        credentials_info = None

        if isinstance(secret, dict) and "credentials_json" in secret and secret["credentials_json"]:
            try:
                credentials_info = json.loads(secret["credentials_json"])
            except Exception:
                pass
        elif isinstance(secret, dict) and "private_key" in secret and "client_email" in secret:
            credentials_info = secret

        if credentials_info:
            from google.oauth2 import service_account
            credentials = service_account.Credentials.from_service_account_info(credentials_info)
            client = kms_v1.KeyManagementServiceClient(credentials=credentials)
        else:
            client = kms_v1.KeyManagementServiceClient()

        parent = f"projects/{self.project_id}/locations/global"
        imported = 0
        updated = 0
        errors: List[str] = []

        def get_all_gcp_keys():
            return list(client.list_crypto_keys(request={"parent": parent}))

        try:
            gcp_keys = await asyncio.to_thread(get_all_gcp_keys)
            for key in gcp_keys:
                try:
                    key_name = key.name
                    asset_name = f"gcp-kms:{key_name.split('/')[-1]}"

                    stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
                    res = await session.execute(stmt)
                    existing = res.scalar_one_or_none()

                    algorithm = key.primary.algorithm.name if key.primary else "UNKNOWN"
                    purpose = key.purpose.name if key.purpose else "UNKNOWN"

                    if existing:
                        existing.asset_type = "kms"
                        existing.asset_metadata = {
                            "provider": "gcp",
                            "key_name": key_name,
                            "algorithm": algorithm,
                            "purpose": purpose,
                            "protection_level": key.primary.protection_level.name if key.primary else "UNKNOWN",
                        }
                        updated += 1
                    else:
                        asset = Asset(
                            name=asset_name,
                            asset_type="kms",
                            environment="cloud",
                            discovery_source="gcp_kms",
                            asset_metadata={
                                "provider": "gcp",
                                "key_name": key_name,
                                "algorithm": algorithm,
                                "purpose": purpose,
                                "protection_level": key.primary.protection_level.name if key.primary else "UNKNOWN",
                            },
                        )
                        session.add(asset)
                        imported += 1
                except Exception as exc:
                    errors.append(f"GCP KMS key {key.name}: {exc}")
        except Exception as exc:
            errors.append(f"GCP KMS list failed: {exc}")

        return {
            "status": "success",
            "imported": imported,
            "updated": updated,
            "errors": errors[:50],
            "total_processed": imported + updated,
        }
