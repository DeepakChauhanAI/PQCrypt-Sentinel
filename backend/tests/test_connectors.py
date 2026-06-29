import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from app.main import create_app
from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import User
from app.connectors.csv_connector import CSVCMDBConnector

# Create test app
app = create_app()

# Admin user context for connectors APIs
mock_user = User(
    id="12345678-1234-1234-1234-123456789012",
    email="admin@pqc.local",
    full_name="Test Admin",
    role="admin",
    is_active=True
)

app.dependency_overrides[get_current_user] = lambda: mock_user

@pytest.fixture
def mock_db():
    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)

client = TestClient(app)

def test_list_connectors():
    response = client.get("/api/v1/connectors")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 14
    assert data[0]["id"] == "csv_cmdb"
    assert data[1]["id"] == "servicenow"
    assert data[2]["id"] == "aws_discovery"
    assert data[3]["id"] == "pkcs11_hsm"
    assert data[4]["id"] == "kmip_kms"
    assert data[5]["id"] == "adcs_ldap"
    assert data[6]["id"] == "ssh_agentless"
    assert data[7]["id"] == "winrm_agentless"
    assert data[8]["id"] == "oracle_tde"
    assert data[9]["id"] == "sqlserver_tde"
    assert data[10]["id"] == "kubernetes"
    assert data[11]["id"] == "sast_native"

@pytest.mark.asyncio
async def test_csv_connector_sync():
    session = AsyncMock()
    
    # Mock no existing asset found (creates new one)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result
    
    csv_content = "name,asset_type,environment,ip_address,port\nserver-a,server,production,10.0.0.1,443"
    connector = CSVCMDBConnector()
    result = await connector.sync(csv_content, session)
    
    assert result["status"] == "success"
    assert result["imported"] == 1
    assert result["updated"] == 0
    assert result["skipped"] == 0
    assert len(result["errors"]) == 0
    
    assert session.add.call_count == 1
    added_asset = session.add.call_args[0][0]
    assert added_asset.name == "server-a"
    assert added_asset.asset_type == "server"
    assert added_asset.environment == "production"
    assert added_asset.ip_address == "10.0.0.1"
    assert added_asset.port == 443
    assert added_asset.discovery_source == "csv_cmdb"

def test_import_csv_endpoint(mock_db):
    mock_sync_result = {
        "status": "success",
        "imported": 3,
        "updated": 0,
        "skipped": 1,
        "errors": ["Row 2: Missing 'name' field"]
    }
    
    with patch("app.api.connectors.CSVCMDBConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        
        csv_data = b"name,asset_type,environment\nserver1,server,production\n"
        response = client.post(
            "/api/v1/connectors/import/csv",
            files={"file": ("cmdb.csv", csv_data, "text/csv")}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["imported"] == 3
        assert data["skipped"] == 1
        assert len(data["errors"]) == 1


def test_scan_ssh_direct_success(mock_db):
    payload = {
        "host": "192.168.1.100",
        "port": 22,
        "username": "ubuntu",
        "password": "mypassword",
        "sudo": True,
        "sudo_password": "mypassword"
    }
    
    mock_sync_result = {
        "status": "success",
        "imported": 1,
        "updated": 0,
        "errors": []
    }
    
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 2
    mock_db.execute.return_value = mock_count_result
    
    with patch("app.api.connectors.SSHConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        
        response = client.post("/api/v1/connectors/scan/ssh-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["host"] == "192.168.1.100"
        assert data["assets_found"] == 1
        assert data["findings_created"] == 2


def test_scan_ssh_direct_missing_auth(mock_db):
    payload = {
        "host": "192.168.1.100",
        "port": 22,
        "username": "ubuntu",
    }
    response = client.post("/api/v1/connectors/scan/ssh-direct", json=payload)
    assert response.status_code == 400
    assert "Either password or private_key must be provided" in response.json()["detail"]


def test_scan_ssh_direct_failure(mock_db):
    payload = {
        "host": "192.168.1.100",
        "port": 22,
        "username": "ubuntu",
        "password": "wrongpassword"
    }
    
    mock_sync_result = {
        "status": "error",
        "error": "Authentication failed.",
        "imported": 0,
        "updated": 0
    }
    
    with patch("app.api.connectors.SSHConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        
        response = client.post("/api/v1/connectors/scan/ssh-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert data["error"] == "Authentication failed."


def test_scan_sast_direct_success(mock_db):
    payload = {
        "target_path": "d:/project-files/my-api"
    }
    
    mock_sync_result = {
        "status": "success",
        "imported": 1,
        "updated": 0,
        "findings_created": 5,
        "errors": []
    }
    
    with patch("os.path.exists", return_value=True), \
         patch("app.api.connectors.SASTConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        
        response = client.post("/api/v1/connectors/scan/sast-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["target_path"] == "d:/project-files/my-api"
        assert data["assets_found"] == 1
        assert data["findings_created"] == 5


def test_scan_sast_direct_path_not_exists(mock_db):
    payload = {
        "target_path": "d:/non-existent-path"
    }
    
    with patch("os.path.exists", return_value=False):
        response = client.post("/api/v1/connectors/scan/sast-direct", json=payload)
        assert response.status_code == 500
        assert "Target path does not exist" in response.json()["detail"]


def test_sync_aws_kms(mock_db):
    payload = {
        "provider": "aws_kms",
        "credentials": {"vault_path": "secret/aws"},
        "region": "us-east-1"
    }
    with patch("app.api.connectors.AWSKMSConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success", "imported": 1, "updated": 0, "total_processed": 1}
        response = client.post("/api/v1/connectors/sync/aws-kms", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "success"


def test_sync_azure_key_vault(mock_db):
    payload = {
        "provider": "azure_key_vault",
        "credentials": {"vault_path": "secret/azure"},
        "tenant_id": "mytenant",
        "vault_url": "https://myvault.vault.azure.net"
    }
    with patch("app.api.connectors.AzureKeyVaultConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/azure-key-vault", json=payload)
        assert response.status_code == 200


def test_sync_gcp_kms(mock_db):
    payload = {
        "provider": "gcp_kms",
        "project_id": "myproject",
        "credentials": {"vault_path": "secret/gcp"}
    }
    with patch("app.api.connectors.GCPKMSConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/gcp-kms", json=payload)
        assert response.status_code == 200


def test_sync_pkcs11_hsm(mock_db):
    payload = {
        "provider": "pkcs11_hsm",
        "library_path": "/usr/lib/libsofthsm2.so",
        "credentials": {"vault_path": "secret/softhsm"}
    }
    with patch("app.api.connectors.PKCS11Connector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/pkcs11-hsm", json=payload)
        assert response.status_code == 200


def test_sync_kmip_kms(mock_db):
    payload = {
        "provider": "kmip_kms",
        "host": "kmip.local",
        "port": 5696,
        "credentials": {"vault_path": "secret/kmip"}
    }
    with patch("app.api.connectors.KMIPConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/kmip-kms", json=payload)
        assert response.status_code == 200


def test_sync_adcs_ldap(mock_db):
    payload = {
        "provider": "adcs_ldap",
        "domain_controller": "dc.local",
        "credentials": {"vault_path": "secret/ldap"}
    }
    with patch("app.api.connectors.ADCSConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/adcs-ldap", json=payload)
        assert response.status_code == 200


def test_sync_ssh_agentless(mock_db):
    payload = {
        "provider": "ssh_agentless",
        "host": "192.168.1.100",
        "credentials": {"vault_path": "secret/ssh"}
    }
    with patch("app.api.connectors.SSHConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/ssh-agentless", json=payload)
        assert response.status_code == 200


def test_sync_winrm_agentless(mock_db):
    payload = {
        "provider": "winrm_agentless",
        "host": "192.168.1.101",
        "credentials": {"vault_path": "secret/winrm"}
    }
    with patch("app.api.connectors.WinRMConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/winrm-agentless", json=payload)
        assert response.status_code == 200


def test_sync_oracle_tde(mock_db):
    payload = {
        "provider": "oracle_tde",
        "host": "db.local",
        "credentials": {"vault_path": "secret/db"}
    }
    with patch("app.api.connectors.OracleTDEConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/oracle-tde", json=payload)
        assert response.status_code == 200


def test_sync_sqlserver_tde(mock_db):
    payload = {
        "provider": "sqlserver_tde",
        "host": "db.local",
        "credentials": {"vault_path": "secret/db"}
    }
    with patch("app.api.connectors.SQLServerTDEConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/sqlserver-tde", json=payload)
        assert response.status_code == 200


def test_sync_kubernetes(mock_db):
    payload = {
        "provider": "kubernetes",
        "credentials": {"vault_path": "secret/k8s"}
    }
    with patch("app.api.connectors.KubernetesConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/kubernetes", json=payload)
        assert response.status_code == 200


def test_sync_sast(mock_db):
    payload = {
        "provider": "sast_native",
        "target_path": "/src"
    }
    with patch("app.api.connectors.SASTConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/sast", json=payload)
        assert response.status_code == 200


def test_sync_jwt(mock_db):
    payload = {
        "provider": "jwt_audit",
        "endpoint": "https://api.local/jwts"
    }
    with patch("app.connectors.jwt_connector.JWTConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/jwt", json=payload)
        assert response.status_code == 200


def test_sync_windows_cert_store(mock_db):
    payload = {
        "provider": "windows_cert_store",
        "store_name": "My",
        "store_kind": "user"
    }
    with patch("app.connectors.winstore_connector.WindowsCertStoreConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "success"}
        response = client.post("/api/v1/connectors/sync/windows-cert-store", json=payload)
        assert response.status_code == 200


def test_scan_winrm_direct_success(mock_db):
    payload = {
        "host": "192.168.1.101",
        "port": 5985,
        "username": "administrator",
        "password": "Password123",
        "transport": "ntlm",
        "use_https": False,
        "verify_ssl": True
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 1
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.WinRMConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/winrm-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["host"] == "192.168.1.101"
        assert data["assets_found"] == 1
        assert data["findings_created"] == 1


def test_scan_kubernetes_direct_success(mock_db):
    payload = {
        "context": "minikube",
        "kubeconfig": "apiVersion: v1..."
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.KubernetesConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/kubernetes-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["assets_found"] == 1


def test_scan_oracle_tde_direct_success(mock_db):
    payload = {
        "host": "oracle.local",
        "port": 1521,
        "service_name": "ORCL",
        "username": "sys",
        "password": "password",
        "use_wallet": False
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.OracleTDEConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/oracle-tde-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_sqlserver_tde_direct_success(mock_db):
    payload = {
        "host": "sql.local",
        "port": 1433,
        "database": "master",
        "username": "sa",
        "password": "password"
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.SQLServerTDEConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/sqlserver-tde-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_pkcs11_hsm_direct_success(mock_db):
    payload = {
        "library_path": "/usr/lib/libsofthsm2.so",
        "pin": "1234",
        "slot_id": 1
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.PKCS11Connector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/pkcs11-hsm-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_kmip_kms_direct_success(mock_db):
    payload = {
        "host": "kmip.local",
        "port": 5696,
        "username": "user",
        "password": "pwd"
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.KMIPConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/kmip-kms-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_adcs_ldap_direct_success(mock_db):
    payload = {
        "domain_controller": "dc.local",
        "username": "user",
        "password": "pwd"
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.api.connectors.ADCSConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/adcs-ldap-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_jwt_direct_success(mock_db):
    payload = {
        "tokens": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-zISoiuTaZeaRy7AlV0596rZ75D94iaKsVI4CoWy48"]
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.connectors.jwt_connector.JWTConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/jwt-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_windows_cert_store_direct_success(mock_db):
    payload = {
        "store_name": "My",
        "store_kind": "user",
        "dump": "certutil dump text"
    }
    mock_sync_result = {"status": "success", "imported": 1, "updated": 0, "errors": []}
    mock_count_result = MagicMock()
    mock_count_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_count_result
    with patch("app.connectors.winstore_connector.WindowsCertStoreConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/windows-cert-store-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


def test_scan_direct_forbidden(mock_db):
    non_admin_user = User(
        id="98765432-1234-1234-1234-123456789012",
        email="user@pqc.local",
        full_name="Regular User",
        role="user",
        is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: non_admin_user
    try:
        payload = {
            "host": "192.168.1.101",
            "port": 5985,
            "username": "administrator",
            "password": "Password123"
        }
        response = client.post("/api/v1/connectors/scan/winrm-direct", json=payload)
        assert response.status_code == 403
    finally:
        app.dependency_overrides[get_current_user] = lambda: mock_user



def test_scan_winrm_direct_error(mock_db):
    payload = {
        "host": "192.168.1.101",
        "port": 5985,
        "username": "administrator",
        "password": "Password123"
    }
    mock_sync_result = {"status": "error", "error": "Connection timed out"}
    with patch("app.api.connectors.WinRMConnector.sync", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = mock_sync_result
        response = client.post("/api/v1/connectors/scan/winrm-direct", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "Connection timed out" in data["error"]


def test_scan_winrm_direct_exception(mock_db):
    payload = {
        "host": "192.168.1.101",
        "port": 5985,
        "username": "administrator",
        "password": "Password123"
    }
    with patch("app.api.connectors.WinRMConnector.sync", side_effect=Exception("Critical WinRM connection failure")):
        response = client.post("/api/v1/connectors/scan/winrm-direct", json=payload)
        assert response.status_code == 500
        assert "Critical WinRM connection failure" in response.json()["detail"]


