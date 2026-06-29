import logging
import os
from datetime import datetime, timezone
from typing import Optional, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import User, Scan, Finding
from app.utils.target_classifier import classify_target
from app.connectors.csv_connector import CSVCMDBConnector
from app.connectors.cloud_kms_connector import AWSKMSConnector, AzureKeyVaultConnector, GCPKMSConnector
from app.connectors.aws_pqc_scanner import AWSPQCScanner
from app.connectors.pkcs11_connector import PKCS11Connector, KMIPConnector, ADCSConnector
from app.connectors.ssh_connector import SSHConnector
from app.connectors.winrm_connector import WinRMConnector
from app.connectors.tde_connector import OracleTDEConnector, SQLServerTDEConnector
from app.connectors.k8s_connector import KubernetesConnector
from app.connectors.sast_connector import SASTConnector
from app.connectors.jwt_connector import JWTConnector
from app.connectors.winstore_connector import WindowsCertStoreConnector
from app.connectors.saml_connector import SAMLMetadataConnector
from app.connectors.vault_scanner import VaultScannerConnector
from app.connectors.git_secrets_connector import GitSecretsConnector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


def _apply_target_classification(scan: Scan) -> None:
    """Populate ``target_kind`` / ``target_label`` from the scan's target
    string. Connector targets are always single-endpoint
    (``ssh:host:22``, ``aws:region``, ``pkcs11:...``), so the classifier
    returns ``("host", target, False)`` and no ScanGroup is created.

    Kept as a tiny module-level helper (rather than duplicated at each
    of the 12 call sites) so the 12 endpoints stay readable and the
    classification logic has one source of truth.
    """
    classification = classify_target(scan.target)
    scan.target_kind = classification.kind
    scan.target_label = classification.label


class VaultCredentialRef(BaseModel):
    vault_path: str = Field(..., min_length=1, description="Vault credential path, e.g. secret/pqc/aws/kms")
    version: Optional[str] = Field(None, description="Optional Vault version/version_id")


class AWSKMSSyncRequest(BaseModel):
    provider: str = "aws_kms"
    credentials: Optional[VaultCredentialRef] = None
    region: str = Field(default="us-east-1", min_length=1)
    access_key_id: Optional[str] = Field(None, min_length=1)
    secret_access_key: Optional[str] = Field(None, min_length=1)


class AzureKeyVaultSyncRequest(BaseModel):
    provider: str = "azure_key_vault"
    credentials: Optional[VaultCredentialRef] = None
    tenant_id: str = Field(min_length=1)
    vault_url: str = Field(min_length=1)
    client_id: Optional[str] = Field(None, min_length=1)
    client_secret: Optional[str] = Field(None, min_length=1)


class GCPKMSSyncRequest(BaseModel):
    provider: str = "gcp_kms"
    project_id: str = Field(min_length=1)
    credentials: Optional[VaultCredentialRef] = None
    credentials_path: Optional[str] = Field(None, min_length=1)
    credentials_json: Optional[str] = Field(None, min_length=1)


class PKCS11SyncRequest(BaseModel):
    provider: str = "pkcs11_hsm"
    library_path: str = Field(min_length=1)
    credentials: VaultCredentialRef
    slot_id: Optional[int] = Field(None, ge=0)
    token_label: Optional[str] = None


class KMIPSyncRequest(BaseModel):
    provider: str = "kmip_kms"
    host: str = Field(min_length=1)
    port: int = Field(default=5696, ge=1, le=65535)
    credentials: VaultCredentialRef
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None


class ADCSSyncRequest(BaseModel):
    provider: str = "adcs_ldap"
    domain_controller: str = Field(min_length=1)
    credentials: VaultCredentialRef
    base_dn: Optional[str] = None
    use_ldaps: bool = True


class SSHSyncRequest(BaseModel):
    provider: str = "ssh_agentless"
    host: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    credentials: VaultCredentialRef
    sudo: bool = False
    sudo_password_ref: Optional[VaultCredentialRef] = None


class WinRMSyncRequest(BaseModel):
    provider: str = "winrm_agentless"
    host: str = Field(min_length=1)
    port: int = Field(default=5985, ge=1, le=65535)
    credentials: VaultCredentialRef
    transport: str = Field(default="ntlm", pattern="^(ntlm|kerberos|credssp)$")
    use_https: bool = False
    verify_ssl: bool = True


class OracleTDESyncRequest(BaseModel):
    provider: str = "oracle_tde"
    host: str = Field(min_length=1)
    port: int = Field(default=1521, ge=1, le=65535)
    service_name: str = Field(default="ORCL", min_length=1)
    credentials: VaultCredentialRef
    use_wallet: bool = True


class SQLServerTDESyncRequest(BaseModel):
    provider: str = "sqlserver_tde"
    host: str = Field(min_length=1)
    port: int = Field(default=1433, ge=1, le=65535)
    database: str = Field(default="master", min_length=1)
    credentials: VaultCredentialRef
    domain: Optional[str] = None


class KubernetesSyncRequest(BaseModel):
    provider: str = "kubernetes"
    credentials: VaultCredentialRef
    context: Optional[str] = None
    kubeconfig_path: Optional[str] = None


class SASTSyncRequest(BaseModel):
    provider: str = "sast_native"
    target_path: str = Field(min_length=1, description="Path to source code directory")
    credentials: Optional[VaultCredentialRef] = None


class JWTSyncRequest(BaseModel):
    provider: str = "jwt_audit"
    tokens: Optional[list[str]] = Field(
        None, description="JWT strings to analyze (offline mode)."
    )
    endpoint: Optional[str] = Field(
        None, description="HTTPS endpoint returning a JSON list of JWTs."
    )
    credentials: Optional[VaultCredentialRef] = None


class WindowsCertStoreSyncRequest(BaseModel):
    provider: str = "windows_cert_store"
    store_name: str = Field("My", description='Windows store name, e.g. "My", "Root", "CA".')
    store_kind: str = Field("user", description='"user" or "enterprise".')
    dump: Optional[str] = Field(
        None, description="Raw text of a `certutil -store` dump."
    )


class VaultScannerSyncRequest(BaseModel):
    provider: str = "vault_secrets"
    vault_url: str = Field(min_length=1, description="HashiCorp Vault URL, e.g. https://vault.internal:8200")
    token: str = Field(min_length=1, description="Vault token with read permissions")
    mount_point: str = Field(default="secret", description="KV secrets engine mount point")
    path: str = Field(default="", description="Optional sub-path within the mount point")


class GitSecretsSyncRequest(BaseModel):
    provider: str = "git_secrets"
    repo_path: str = Field(min_length=1, description="Local path to a git repository")
    scan_history: bool = Field(default=True, description="Scan recent commit history for secrets")


class AWSPQCScanRequest(BaseModel):
    """Direct AWS credentials for comprehensive PQC scanning."""
    access_key_id: str = Field(min_length=1, description="AWS Access Key ID")
    secret_access_key: str = Field(min_length=1, description="AWS Secret Access Key")
    region: str = Field(default="ap-south-1", min_length=1, description="AWS region")
    session_token: Optional[str] = Field(None, description="Optional STS session token")


class SSHDirectScanRequest(BaseModel):
    host: str = Field(..., min_length=1, description="SSH Host IP or FQDN")
    port: int = Field(default=22, ge=1, le=65535, description="SSH Port")
    username: str = Field(..., min_length=1, description="SSH Username")
    password: Optional[str] = Field(None, description="SSH Password")
    private_key: Optional[str] = Field(None, description="PEM-formatted private key")
    key_passphrase: Optional[str] = Field(None, description="Passphrase for the private key")
    sudo: bool = Field(default=False, description="Enable privilege escalation via sudo")
    sudo_password: Optional[str] = Field(None, description="Password for sudo escalation")


class SASTDirectScanRequest(BaseModel):
    target_path: str = Field(..., min_length=1, description="Absolute target directory path to scan")


class WinRMDirectScanRequest(BaseModel):
    host: str = Field(..., min_length=1, description="WinRM Host IP or FQDN")
    port: int = Field(default=5985, ge=1, le=65535, description="WinRM Port")
    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")
    transport: str = Field(default="ntlm", pattern="^(ntlm|kerberos|credssp)$")
    use_https: bool = Field(default=False)
    verify_ssl: bool = Field(default=True)


class KubernetesDirectScanRequest(BaseModel):
    context: Optional[str] = Field(None, description="Kubeconfig context name")
    kubeconfig: Optional[str] = Field(None, description="Kubeconfig file content as a string")
    host: Optional[str] = Field(None, description="Kubernetes API server host")
    token: Optional[str] = Field(None, description="Bearer token")
    verify_ssl: bool = Field(default=False)
    ca_cert: Optional[str] = Field(None, description="CA Certificate PEM string")


class OracleTDEDirectScanRequest(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(default=1521, ge=1, le=65535)
    service_name: str = Field(default="ORCL", min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    use_wallet: bool = Field(default=True)
    wallet_location: Optional[str] = None


class SQLServerTDEDirectScanRequest(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(default=1433, ge=1, le=65535)
    database: str = Field(default="master", min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    domain: Optional[str] = None


class PKCS11DirectScanRequest(BaseModel):
    library_path: str = Field(..., min_length=1)
    pin: str = Field(..., min_length=1, description="HSM user pin")
    so_pin: Optional[str] = Field(None, description="Security Officer PIN")
    slot_id: Optional[int] = Field(None, ge=0)
    token_label: Optional[str] = None


class KMIPDirectScanRequest(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(default=5696, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    ca_cert: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None


class ADCSDirectScanRequest(BaseModel):
    domain_controller: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    base_dn: Optional[str] = None
    use_ldaps: bool = Field(default=True)


class JWTDirectScanRequest(BaseModel):
    tokens: Optional[list[str]] = Field(None, description="Offline list of JWTs")
    endpoint: Optional[str] = Field(None, description="HTTPS endpoint returning JWT list")
    token: Optional[str] = Field(None, description="Bearer token auth for endpoint")


class WindowsCertStoreDirectScanRequest(BaseModel):
    store_name: str = Field("My")
    store_kind: str = Field("user", pattern="^(user|enterprise|machine)$")
    dump: str = Field(..., min_length=1, description="Raw certutil store text dump")


class SAMLSyncRequest(BaseModel):
    provider: str = "saml_metadata"
    metadata_url: Optional[str] = Field(None, description="URL of SAML metadata XML")
    credentials: Optional[VaultCredentialRef] = None


class SAMLDirectScanRequest(BaseModel):
    metadata_url: Optional[str] = Field(None, description="SAML metadata URL to fetch and parse")
    xml_blob: Optional[str] = Field(None, description="Raw SAML metadata XML string")
    token: Optional[str] = Field(None, description="Bearer token for authenticated metadata URLs")


@router.get("")
async def list_connectors(
    current_user: User = Depends(get_current_user),
):
    """
    Return available connectors list (including active CSV and mock connectors for other systems).
    """
    return [
        {
            "id": "csv_cmdb",
            "name": "CSV CMDB Import",
            "type": "cmdb",
            "status": "configured",
            "last_sync": None,
            "description": "Upload a CSV file to bulk import or update assets."
        },
        {
            "id": "servicenow",
            "name": "ServiceNow CMDB Integration",
            "type": "cmdb",
            "status": "inactive",
            "last_sync": None,
            "description": "Sync servers and business service mapping from ServiceNow CIs."
        },
        {
            "id": "aws_discovery",
            "name": "AWS Cryptographic Resource Discovery",
            "type": "cloud",
            "status": "configured",
            "last_sync": None,
            "description": "Automatically inventory AWS KMS, ACM certificates, and ALBs."
        },
        {
            "id": "pkcs11_hsm",
            "name": "PKCS#11 HSM Enumeration",
            "type": "hsm",
            "status": "configured",
            "last_sync": None,
            "description": "Enumerate HSM objects via PKCS#11 (key types, sizes, labels)."
        },
        {
            "id": "kmip_kms",
            "name": "KMIP KMS Scan",
            "type": "hsm",
            "status": "configured",
            "last_sync": None,
            "description": "Query KMIP server for managed objects via Locate/GetAttributes."
        },
        {
            "id": "adcs_ldap",
            "name": "ADCS/LDAP Scanner",
            "type": "pki",
            "status": "configured",
            "last_sync": None,
            "description": "Discover CAs and certificates from Active Directory Certificate Services."
        },
        {
            "id": "ssh_agentless",
            "name": "SSH Linux Scanner",
            "type": "host",
            "status": "configured",
            "last_sync": None,
            "description": "SSH agentless scan of certificate stores, OpenSSL, SSH config, and ciphers."
        },
        {
            "id": "winrm_agentless",
            "name": "WinRM Windows Scanner",
            "type": "host",
            "status": "configured",
            "last_sync": None,
            "description": "Audit Windows hosts for certificate stores, Schannel TLS, and IIS."
        },
        {
            "id": "oracle_tde",
            "name": "Oracle TDE Scanner",
            "type": "database",
            "status": "configured",
            "last_sync": None,
            "description": "Enumerate Oracle tablespace encryption and TDE wallet master keys."
        },
        {
            "id": "sqlserver_tde",
            "name": "SQL Server TDE",
            "type": "database",
            "status": "configured",
            "last_sync": None,
            "description": "Audit SQL Server database encryption (TDE) keys and certificates."
        },
        {
            "id": "kubernetes",
            "name": "Kubernetes Scanner",
            "type": "container",
            "status": "configured",
            "last_sync": None,
            "description": "Scan ingress TLS, secrets, etcd encryption, and cluster components."
        },
        {
            "id": "sast_native",
            "name": "Native SAST Scanner",
            "type": "sast",
            "status": "configured",
            "last_sync": None,
            "description": "Scan codebases (Python/Java/Go/NodeJS) for crypto usage and lockfiles."
        },
        {
            "id": "windows_cert_store",
            "name": "Windows Cert Store",
            "type": "endpoint",
            "status": "configured",
            "last_sync": None,
            "description": "Enumerate local Windows certificate stores via certutil dump."
        },
        {
            "id": "jwt_audit",
            "name": "JWT Token Auditor",
            "type": "app",
            "status": "configured",
            "last_sync": None,
            "description": "Audit JWT signing algorithms and keys offline or via JWKS endpoints."
        },
        {
            "id": "azure_key_vault",
            "name": "Azure Key Vault Sync",
            "type": "cloud",
            "status": "configured",
            "last_sync": None,
            "description": "Sync keys and configuration from Azure Key Vault."
        },
        {
            "id": "gcp_kms",
            "name": "GCP KMS Sync",
            "type": "cloud",
            "status": "configured",
            "last_sync": None,
            "description": "Sync keys and keyring algorithms from GCP KMS."
        },
        {
            "id": "vault_scanner",
            "name": "HashiCorp Vault Secrets Scanner",
            "type": "secrets",
            "status": "configured",
            "last_sync": None,
            "description": "Discover cryptographic material (PKI certs, transit keys) in HashiCorp Vault secrets."
        },
        {
            "id": "git_secrets",
            "name": "Git Repository Secrets Scanner",
            "type": "sast",
            "status": "configured",
            "last_sync": None,
            "description": "Scan git repositories for exposed private keys, certificates, and credentials in history."
        },
        {
            "id": "saml_metadata",
            "name": "SAML Metadata Certificate Scanner",
            "type": "pki",
            "status": "configured",
            "last_sync": None,
            "description": "Parse SAML metadata XML or URLs to inventory signing/encryption certificates for PQC readiness."
        }
    ]


@router.post("/import/csv", status_code=status.HTTP_200_OK)
async def import_csv(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Upload a CSV file to import assets in bulk.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators and analysts can import asset data."
        )

    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must be a CSV file."
        )

    try:
        content = await file.read()
        csv_content = content.decode("utf-8")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not parse file content as UTF-8 text: {e}"
        )

    connector = CSVCMDBConnector()
    result = await connector.sync(csv_content, session)

    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "Unknown error parsing CSV")
        )

    return result


@router.post("/sync/aws-kms", status_code=status.HTTP_200_OK)
async def sync_aws_kms(
    payload: AWSKMSSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    credentials_ref: Any = payload.credentials
    if payload.access_key_id or payload.secret_access_key:
        credentials_ref = {
            "aws_access_key_id": payload.access_key_id,
            "aws_secret_access_key": payload.secret_access_key,
        }
    connector = AWSKMSConnector(credentials_ref=credentials_ref, region=payload.region)
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/azure-key-vault", status_code=status.HTTP_200_OK)
async def sync_azure_key_vault(
    payload: AzureKeyVaultSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    creds_ref: Any = payload.credentials
    if payload.client_id or payload.client_secret:
        creds_ref = {
            "client_id": payload.client_id,
            "client_secret": payload.client_secret,
            "tenant_id": payload.tenant_id,
        }
    connector = AzureKeyVaultConnector(credentials_ref=creds_ref, tenant_id=payload.tenant_id, vault_url=payload.vault_url)
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/gcp-kms", status_code=status.HTTP_200_OK)
async def sync_gcp_kms(
    payload: GCPKMSSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    credentials_json = payload.credentials_json
    if not credentials_json and payload.credentials_path:
        import pathlib
        try:
            credentials_json = pathlib.Path(payload.credentials_path).read_text(encoding="utf-8")
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Could not read credentials_path: {exc}")
    credentials_ref: Any = payload.credentials
    if credentials_json:
        credentials_ref = {"credentials_json": credentials_json}
    connector = GCPKMSConnector(project_id=payload.project_id, credentials_ref=credentials_ref)
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/pkcs11-hsm", status_code=status.HTTP_200_OK)
async def sync_pkcs11_hsm(
    payload: PKCS11SyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = PKCS11Connector(
        library_path=payload.library_path,
        credentials_ref=payload.credentials,
        slot_id=payload.slot_id,
        token_label=payload.token_label,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/kmip-kms", status_code=status.HTTP_200_OK)
async def sync_kmip_kms(
    payload: KMIPSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = KMIPConnector(
        host=payload.host,
        port=payload.port,
        credentials_ref=payload.credentials,
        client_cert_path=payload.client_cert_path,
        client_key_path=payload.client_key_path,
        ca_cert_path=payload.ca_cert_path,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/adcs-ldap", status_code=status.HTTP_200_OK)
async def sync_adcs_ldap(
    payload: ADCSSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = ADCSConnector(
        domain_controller=payload.domain_controller,
        credentials_ref=payload.credentials,
        base_dn=payload.base_dn,
        use_ldaps=payload.use_ldaps,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/ssh-agentless", status_code=status.HTTP_200_OK)
async def sync_ssh_agentless(
    payload: SSHSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = SSHConnector(
        credentials_ref=payload.credentials,
        host=payload.host,
        port=payload.port,
        sudo=payload.sudo,
        sudo_password_ref=payload.sudo_password_ref,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/winrm-agentless", status_code=status.HTTP_200_OK)
async def sync_winrm_agentless(
    payload: WinRMSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = WinRMConnector(
        credentials_ref=payload.credentials,
        host=payload.host,
        port=payload.port,
        transport=payload.transport,
        use_https=payload.use_https,
        verify_ssl=payload.verify_ssl,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/oracle-tde", status_code=status.HTTP_200_OK)
async def sync_oracle_tde(
    payload: OracleTDESyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = OracleTDEConnector(
        credentials_ref=payload.credentials,
        host=payload.host,
        port=payload.port,
        service_name=payload.service_name,
        use_wallet=payload.use_wallet,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/sqlserver-tde", status_code=status.HTTP_200_OK)
async def sync_sqlserver_tde(
    payload: SQLServerTDESyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = SQLServerTDEConnector(
        credentials_ref=payload.credentials,
        host=payload.host,
        port=payload.port,
        database=payload.database,
        domain=payload.domain,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/kubernetes", status_code=status.HTTP_200_OK)
async def sync_kubernetes(
    payload: KubernetesSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = KubernetesConnector(
        credentials_ref=payload.credentials,
        context=payload.context,
        kubeconfig_path=payload.kubeconfig_path,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/sast", status_code=status.HTTP_200_OK)
async def sync_sast(
    payload: SASTSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = SASTConnector(
        target_path=payload.target_path,
        credentials_ref=payload.credentials,
    )
    result = await connector.sync(session)
    return result


@router.post("/sync/jwt", status_code=status.HTTP_200_OK)
async def sync_jwt(
    payload: JWTSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    from app.connectors.jwt_connector import JWTConnector
    connector = JWTConnector(
        tokens=payload.tokens,
        endpoint=payload.endpoint,
        credentials_ref=payload.credentials,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/windows-cert-store", status_code=status.HTTP_200_OK)
async def sync_windows_cert_store(
    payload: WindowsCertStoreSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    from app.connectors.winstore_connector import WindowsCertStoreConnector
    normalized_kind = "enterprise" if payload.store_kind == "machine" else payload.store_kind
    if normalized_kind not in {"user", "enterprise"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="store_kind must be 'user' or 'enterprise'")
    connector = WindowsCertStoreConnector(
        store_name=payload.store_name,
        store_kind=normalized_kind,
    )
    result = await connector.sync(session, dump_text=payload.dump)
    await session.commit()
    return result


@router.post("/sync/saml", status_code=status.HTTP_200_OK)
async def sync_saml(
    payload: SAMLSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = SAMLMetadataConnector(
        metadata_url=payload.metadata_url,
        credentials_ref=payload.credentials,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/scan/saml-direct", status_code=status.HTTP_200_OK)
async def scan_saml_direct(
    payload: SAMLDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="saml_metadata",
        target=f"saml:{payload.metadata_url or 'offline'}",
        status="running",
        config="saml_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        connector = SAMLMetadataConnector(
            metadata_url=payload.metadata_url,
            xml_blob=payload.xml_blob,
            credentials_ref={"token": payload.token} if payload.token else None,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown SAML error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"SAML direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"SAML direct scan failed: {exc}")


@router.post("/sync/vault-scanner", status_code=status.HTTP_200_OK)
async def sync_vault_scanner(
    payload: VaultScannerSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = VaultScannerConnector(
        vault_url=payload.vault_url,
        token=payload.token,
        mount_point=payload.mount_point,
        path=payload.path,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/sync/git-secrets", status_code=status.HTTP_200_OK)
async def sync_git_secrets(
    payload: GitSecretsSyncRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    connector = GitSecretsConnector(
        repo_path=payload.repo_path,
        scan_history=payload.scan_history,
    )
    result = await connector.sync(session)
    await session.commit()
    return result


@router.post("/scan/aws-pqc", status_code=status.HTTP_200_OK)
async def scan_aws_pqc(
    payload: AWSPQCScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Comprehensive AWS PQC scan: discovers cryptographic material across
    KMS, ACM, ELB/ALB, CloudFront, S3, and IAM, then classifies each
    algorithm for quantum vulnerability and generates findings.

    Accepts direct AWS credentials (Access Key + Secret Key). Creates a
    Scan record to track the operation.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    # Create a Scan record so results are tracked like any other scan
    scan = Scan(
        scan_type="cloud_sync",
        target=f"aws:{payload.region}",
        status="running",
        config="aws_pqc_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)

    try:
        scanner = AWSPQCScanner(
            access_key_id=payload.access_key_id,
            secret_access_key=payload.secret_access_key,
            region=payload.region,
            session_token=payload.session_token,
        )
        result = await scanner.scan(session, scan_id)

        # Update the Scan record with results
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("assets_created", 0) + result.get("assets_updated", 0)
        scan.findings_created = result.get("findings_created", 0)
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()

        return {
            "status": "success",
            "scan_id": scan_id,
            "region": payload.region,
            "services_scanned": result.get("services_scanned", []),
            "assets_discovered": result.get("assets_created", 0),
            "assets_updated": result.get("assets_updated", 0),
            "algorithms_recorded": result.get("algorithms_recorded", 0),
            "findings_created": result.get("findings_created", 0),
            "certificates_recorded": result.get("certificates_recorded", 0),
            "errors": result.get("errors", [])[:20],
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()
        logger.exception(f"AWS PQC scan failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AWS PQC scan failed: {exc}",
        )


@router.post("/scan/ssh-direct", status_code=status.HTTP_200_OK)
async def scan_ssh_direct(
    payload: SSHDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Direct credentials SSH scan for remote servers.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    if not payload.password and not payload.private_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either password or private_key must be provided for SSH authentication.",
        )

    scan = Scan(
        scan_type="ssh_only",
        target=f"ssh:{payload.host}:{payload.port}",
        status="running",
        config="ssh_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)

    try:
        credentials = {
            "username": payload.username,
            "password": payload.password,
            "private_key": payload.private_key,
            "key_passphrase": payload.key_passphrase,
            "sudo_password": payload.sudo_password,
        }
        
        connector = SSHConnector(
            credentials_ref=credentials,
            host=payload.host,
            port=payload.port,
            sudo=payload.sudo,
            sudo_password_ref=credentials if payload.sudo_password else None,
        )
        
        result = await connector.sync(session)

        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = result.get("error", "Unknown SSH error")
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )
            await session.commit()
            return {
                "status": "error",
                "scan_id": scan_id,
                "error": result.get("error"),
            }

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        
        # Count findings created for this scan
        findings_res = await session.execute(
            select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
        )
        scan.findings_created = findings_res.scalar_one() or 0
        
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()

        return {
            "status": "success",
            "scan_id": scan_id,
            "host": payload.host,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()
        logger.exception(f"SSH PQC scan failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSH PQC scan failed: {exc}",
        )


@router.post("/scan/sast-direct", status_code=status.HTTP_200_OK)
async def scan_sast_direct(
    payload: SASTDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Direct path SAST codebase scan.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    scan = Scan(
        scan_type="targeted",
        target=f"sast:{payload.target_path}",
        status="running",
        config="sast_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)

    try:
        # Check if directory exists
        if not os.path.exists(payload.target_path):
            raise ValueError(f"Target path does not exist: {payload.target_path}")

        connector = SASTConnector(
            target_path=payload.target_path,
        )
        result = await connector.sync(session, scan_id=scan.id)

        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown SAST error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )
            await session.commit()
            return {
                "status": "error",
                "scan_id": scan_id,
                "errors": result.get("errors", []),
            }

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        scan.findings_created = result.get("findings_created", 0)
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()

        return {
            "status": "success",
            "scan_id": scan_id,
            "target_path": payload.target_path,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        await session.commit()
        logger.exception(f"SAST PQC scan failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SAST PQC scan failed: {exc}",
        )


@router.post("/scan/winrm-direct", status_code=status.HTTP_200_OK)
async def scan_winrm_direct(
    payload: WinRMDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="winrm",
        target=f"winrm:{payload.host}:{payload.port}",
        status="running",
        config="winrm_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        connector = WinRMConnector(
            credentials_ref={"username": payload.username, "password": payload.password},
            host=payload.host,
            port=payload.port,
            transport=payload.transport,
            use_https=payload.use_https,
            verify_ssl=payload.verify_ssl,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = result.get("error", "Unknown WinRM error")
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "error": result.get("error")}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "host": payload.host,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"WinRM direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"WinRM direct scan failed: {exc}")


@router.post("/scan/kubernetes-direct", status_code=status.HTTP_200_OK)
async def scan_kubernetes_direct(
    payload: KubernetesDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="kubernetes",
        target=f"kubernetes:{payload.context or 'default'}",
        status="running",
        config="kubernetes_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {}
        if payload.kubeconfig:
            credentials_ref["kubeconfig"] = payload.kubeconfig
        elif payload.token and payload.host:
            credentials_ref["token"] = payload.token
            credentials_ref["host"] = payload.host
            credentials_ref["verify_ssl"] = payload.verify_ssl
            credentials_ref["ca_cert"] = payload.ca_cert
        connector = KubernetesConnector(
            credentials_ref=credentials_ref,
            context=payload.context,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown Kubernetes error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"Kubernetes direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Kubernetes direct scan failed: {exc}")


@router.post("/scan/oracle-tde-direct", status_code=status.HTTP_200_OK)
async def scan_oracle_tde_direct(
    payload: OracleTDEDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="oracle_tde",
        target=f"oracle-tde:{payload.host}:{payload.port}/{payload.service_name}",
        status="running",
        config="oracle_tde_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {
            "username": payload.username,
            "password": payload.password,
            "wallet_location": payload.wallet_location,
        }
        connector = OracleTDEConnector(
            credentials_ref=credentials_ref,
            host=payload.host,
            port=payload.port,
            service_name=payload.service_name,
            use_wallet=payload.use_wallet,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown Oracle error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"Oracle TDE direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Oracle TDE direct scan failed: {exc}")


@router.post("/scan/sqlserver-tde-direct", status_code=status.HTTP_200_OK)
async def scan_sqlserver_tde_direct(
    payload: SQLServerTDEDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="sqlserver_tde",
        target=f"sqlserver-tde:{payload.host}:{payload.port}",
        status="running",
        config="sqlserver_tde_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {
            "username": payload.username,
            "password": payload.password,
        }
        connector = SQLServerTDEConnector(
            credentials_ref=credentials_ref,
            host=payload.host,
            port=payload.port,
            database=payload.database,
            domain=payload.domain,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown SQL Server error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"SQL Server TDE direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"SQL Server TDE direct scan failed: {exc}")


@router.post("/scan/pkcs11-hsm-direct", status_code=status.HTTP_200_OK)
async def scan_pkcs11_hsm_direct(
    payload: PKCS11DirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="pkcs11_hsm",
        target=f"pkcs11:{payload.library_path}",
        status="running",
        config="pkcs11_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {
            "pin": payload.pin,
            "so_pin": payload.so_pin,
        }
        connector = PKCS11Connector(
            library_path=payload.library_path,
            credentials_ref=credentials_ref,
            slot_id=payload.slot_id,
            token_label=payload.token_label,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown PKCS11 error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"PKCS11 direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"PKCS11 direct scan failed: {exc}")


@router.post("/scan/kmip-kms-direct", status_code=status.HTTP_200_OK)
async def scan_kmip_kms_direct(
    payload: KMIPDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="kmip_kms",
        target=f"kmip:{payload.host}:{payload.port}",
        status="running",
        config="kmip_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {
            "username": payload.username,
            "password": payload.password,
            "client_cert": payload.client_cert,
            "client_key": payload.client_key,
            "ca_cert": payload.ca_cert,
        }
        connector = KMIPConnector(
            host=payload.host,
            port=payload.port,
            credentials_ref=credentials_ref,
            client_cert_path=payload.client_cert_path,
            client_key_path=payload.client_key_path,
            ca_cert_path=payload.ca_cert_path,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown KMIP error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"KMIP direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"KMIP direct scan failed: {exc}")


@router.post("/scan/adcs-ldap-direct", status_code=status.HTTP_200_OK)
async def scan_adcs_ldap_direct(
    payload: ADCSDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="adcs_ldap",
        target=f"adcs:{payload.domain_controller}",
        status="running",
        config="adcs_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        credentials_ref = {
            "username": payload.username,
            "password": payload.password,
        }
        connector = ADCSConnector(
            domain_controller=payload.domain_controller,
            credentials_ref=credentials_ref,
            base_dn=payload.base_dn,
            use_ldaps=payload.use_ldaps,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown ADCS error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"ADCS direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"ADCS direct scan failed: {exc}")


@router.post("/scan/jwt-direct", status_code=status.HTTP_200_OK)
async def scan_jwt_direct(
    payload: JWTDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="jwt_audit",
        target=f"jwt:{payload.endpoint or 'offline'}",
        status="running",
        config="jwt_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        from app.connectors.jwt_connector import JWTConnector
        credentials_ref = {}
        if payload.token:
            credentials_ref["token"] = payload.token
        connector = JWTConnector(
            tokens=payload.tokens,
            endpoint=payload.endpoint,
            credentials_ref=credentials_ref if credentials_ref else None,
        )
        result = await connector.sync(session)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown JWT error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"JWT direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"JWT direct scan failed: {exc}")


@router.post("/scan/windows-cert-store-direct", status_code=status.HTTP_200_OK)
async def scan_windows_cert_store_direct(
    payload: WindowsCertStoreDirectScanRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    scan = Scan(
        scan_type="windows_cert_store",
        target=f"winstore:{payload.store_name}:{payload.store_kind}",
        status="running",
        config="winstore_direct_scan",
        created_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    _apply_target_classification(scan)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    scan_id = str(scan.id)
    try:
        from app.connectors.winstore_connector import WindowsCertStoreConnector
        connector = WindowsCertStoreConnector(
            store_name=payload.store_name,
            store_kind=payload.store_kind,
        )
        result = await connector.sync(session, dump_text=payload.dump)
        if result.get("status") == "error":
            scan.status = "failed"
            scan.error_message = ", ".join(result.get("errors", ["Unknown Windows Cert Store error"]))
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
            await session.commit()
            return {"status": "error", "scan_id": scan_id, "errors": result.get("errors", [])}
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.assets_found = result.get("imported", 0) + result.get("updated", 0)
        findings_res = await session.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        scan.findings_created = findings_res.scalar_one() or 0
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        return {
            "status": "success",
            "scan_id": scan_id,
            "assets_found": scan.assets_found,
            "findings_created": scan.findings_created,
            "errors": result.get("errors", []),
        }
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = str(exc)[:500]
        if scan.started_at:
            scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        await session.commit()
        logger.exception(f"Windows Cert Store direct scan failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Windows Cert Store direct scan failed: {exc}")
