import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from app.main import create_app
from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import User

app = create_app()

mock_admin = User(
    id="12345678-1234-1234-1234-123456789012",
    email="admin@pqc.local",
    full_name="Test Admin",
    role="admin",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_admin


@pytest.fixture
def mock_db():
    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


client = TestClient(app)


class TestScanDirectExceptionPaths:
    """Test exception paths for all remaining /scan/*-direct endpoints.
    Each follows the same pattern: connector.sync raises -> 500 response.
    """

    def test_scan_ssh_direct_exception(self, mock_db):
        with patch(
            "app.api.connectors.SSHConnector.sync", side_effect=Exception("SSH boom")
        ):
            resp = client.post(
                "/api/v1/connectors/scan/ssh-direct",
                json={"host": "10.0.0.1", "port": 22, "username": "u", "password": "p"},
            )
        assert resp.status_code == 500
        assert "SSH boom" in resp.json()["detail"]

    def test_scan_sast_direct_exception(self, mock_db):
        with patch("os.path.exists", return_value=True), patch(
            "app.api.connectors.SASTConnector.sync", side_effect=Exception("SAST boom")
        ):
            resp = client.post(
                "/api/v1/connectors/scan/sast-direct", json={"target_path": "/src"}
            )
        assert resp.status_code == 500
        assert "SAST boom" in resp.json()["detail"]

    def test_scan_sast_direct_error_status(self, mock_db):
        with patch("os.path.exists", return_value=True), patch(
            "app.api.connectors.SASTConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["No source found"]}
            resp = client.post(
                "/api/v1/connectors/scan/sast-direct", json={"target_path": "/src"}
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_oracle_tde_direct_success(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.OracleTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/oracle-tde-direct",
                json={
                    "host": "oracle.local",
                    "port": 1521,
                    "service_name": "ORCL",
                    "username": "sys",
                    "password": "pwd",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_scan_oracle_tde_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.OracleTDEConnector.sync",
            side_effect=Exception("ORA-01017"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/oracle-tde-direct",
                json={
                    "host": "oracle.local",
                    "port": 1521,
                    "service_name": "ORCL",
                    "username": "sys",
                    "password": "bad",
                },
            )
        assert resp.status_code == 500
        assert "ORA-01017" in resp.json()["detail"]

    def test_scan_sqlserver_tde_direct_success(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.SQLServerTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/sqlserver-tde-direct",
                json={
                    "host": "sql.local",
                    "port": 1433,
                    "database": "master",
                    "username": "sa",
                    "password": "pwd",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_scan_sqlserver_tde_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.SQLServerTDEConnector.sync",
            side_effect=Exception("Login failed"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/sqlserver-tde-direct",
                json={
                    "host": "sql.local",
                    "port": 1433,
                    "database": "master",
                    "username": "sa",
                    "password": "bad",
                },
            )
        assert resp.status_code == 500

    def test_scan_pkcs11_hsm_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.PKCS11Connector.sync",
            side_effect=Exception("HSM unavailable"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/pkcs11-hsm-direct",
                json={"library_path": "/usr/lib/libsofthsm2.so", "pin": "1234"},
            )
        assert resp.status_code == 500
        assert "HSM unavailable" in resp.json()["detail"]

    def test_scan_kmip_kms_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.KMIPConnector.sync",
            side_effect=Exception("KMIP timeout"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/kmip-kms-direct",
                json={"host": "kmip.local", "port": 5696},
            )
        assert resp.status_code == 500
        assert "KMIP timeout" in resp.json()["detail"]

    def test_scan_adcs_ldap_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.ADCSConnector.sync",
            side_effect=Exception("LDAP bind failed"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/adcs-ldap-direct",
                json={
                    "domain_controller": "dc.local",
                    "username": "u",
                    "password": "p",
                },
            )
        assert resp.status_code == 500
        assert "LDAP bind failed" in resp.json()["detail"]

    def test_scan_jwt_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.connectors.jwt_connector.JWTConnector.sync",
            side_effect=Exception("JWT parse error"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/jwt-direct",
                json={"tokens": ["eyJhbGciOiJIUzI1NiJ9.e30.abc"]},
            )
        assert resp.status_code == 500
        assert "JWT parse error" in resp.json()["detail"]

    def test_scan_jwt_direct_error_status(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.connectors.jwt_connector.JWTConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "error",
                "errors": ["Invalid token format"],
            }
            resp = client.post(
                "/api/v1/connectors/scan/jwt-direct", json={"tokens": ["bad-token"]}
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_windows_cert_store_direct_success(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.connectors.winstore_connector.WindowsCertStoreConnector.sync",
            new_callable=AsyncMock,
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/windows-cert-store-direct",
                json={
                    "store_name": "My",
                    "store_kind": "user",
                    "dump": "certutil dump text",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_scan_windows_cert_store_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.connectors.winstore_connector.WindowsCertStoreConnector.sync",
            side_effect=Exception("WinStore error"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/windows-cert-store-direct",
                json={"store_name": "My", "store_kind": "user", "dump": "text"},
            )
        assert resp.status_code == 500
        assert "WinStore error" in resp.json()["detail"]

    def test_scan_kubernetes_direct_with_token_and_host(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.KubernetesConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/kubernetes-direct",
                json={
                    "host": "https://k8s.local:6443",
                    "token": "bearer-token",
                    "verify_ssl": False,
                },
            )
        assert resp.status_code == 200

    def test_scan_kubernetes_direct_with_kubeconfig(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.KubernetesConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/kubernetes-direct",
                json={"context": "minikube", "kubeconfig": "apiVersion: v1..."},
            )
        assert resp.status_code == 200

    def test_scan_kubernetes_direct_exception(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.KubernetesConnector.sync",
            side_effect=Exception("K8s unreachable"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/kubernetes-direct",
                json={"context": "minikube"},
            )
        assert resp.status_code == 500
        assert "K8s unreachable" in resp.json()["detail"]

    def test_scan_oracle_tde_direct_with_wallet(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.OracleTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/oracle-tde-direct",
                json={
                    "host": "oracle.local",
                    "port": 1521,
                    "service_name": "ORCL",
                    "username": "sys",
                    "password": "pwd",
                    "use_wallet": True,
                    "wallet_location": "/opt/oracle/wallet",
                },
            )
        assert resp.status_code == 200

    def test_scan_sqlserver_tde_direct_with_domain(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count
        with patch(
            "app.api.connectors.SQLServerTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/sqlserver-tde-direct",
                json={
                    "host": "sql.local",
                    "port": 1433,
                    "database": "master",
                    "username": "sa",
                    "password": "pwd",
                    "domain": "CONTOSO",
                },
            )
        assert resp.status_code == 200


class TestCSVUpload:
    """Error paths for the CSV import endpoint."""

    def test_csv_upload_non_csv_extension(self, mock_db):
        resp = client.post(
            "/api/v1/connectors/import/csv",
            files={"file": ("cmdb.txt", b"name,asset_type\ns1,server", "text/plain")},
        )
        assert resp.status_code == 400
        assert "CSV file" in resp.json()["detail"]

    def test_csv_upload_utf8_decode_error(self, mock_db):
        bad_bytes = b"\xff\xfe\x00\x01"
        resp = client.post(
            "/api/v1/connectors/import/csv",
            files={"file": ("cmdb.csv", bad_bytes, "text/csv")},
        )
        assert resp.status_code == 400
        assert "UTF-8" in resp.json()["detail"]

    def test_csv_upload_connector_error(self, mock_db):
        with patch(
            "app.api.connectors.CSVCMDBConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "error": "bad csv"}
            resp = client.post(
                "/api/v1/connectors/import/csv",
                files={"file": ("cmdb.csv", b"name\ns1", "text/csv")},
            )
        assert resp.status_code == 400
        assert "bad csv" in resp.json()["detail"]


class TestPermissionDenied:
    """Viewer role should be denied on all scan/sync endpoints."""

    @pytest.fixture
    def viewer_client(self):
        from app.api.auth import get_current_user

        viewer = User(
            id="22222222-2222-2222-2222-222222222222",
            email="viewer@pqc.local",
            full_name="Viewer",
            role="viewer",
            is_active=True,
        )
        app.dependency_overrides[get_current_user] = lambda: viewer
        yield
        app.dependency_overrides[get_current_user] = lambda: mock_admin

    def test_scan_ssh_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/ssh-direct",
            json={"host": "10.0.0.1", "port": 22, "username": "u", "password": "p"},
        )
        assert resp.status_code == 403

    def test_scan_sast_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/sast-direct", json={"target_path": "/src"}
        )
        assert resp.status_code == 403

    def test_scan_kubernetes_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/kubernetes-direct", json={"context": "x"}
        )
        assert resp.status_code == 403

    def test_scan_oracle_tde_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/oracle-tde-direct",
            json={
                "host": "o",
                "port": 1521,
                "service_name": "ORCL",
                "username": "u",
                "password": "p",
            },
        )
        assert resp.status_code == 403

    def test_scan_sqlserver_tde_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/sqlserver-tde-direct",
            json={
                "host": "s",
                "port": 1433,
                "database": "m",
                "username": "u",
                "password": "p",
            },
        )
        assert resp.status_code == 403

    def test_scan_pkcs11_hsm_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/pkcs11-hsm-direct",
            json={"library_path": "/lib.so", "pin": "1234"},
        )
        assert resp.status_code == 403

    def test_scan_kmip_kms_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/kmip-kms-direct", json={"host": "k", "port": 5696}
        )
        assert resp.status_code == 403

    def test_scan_adcs_ldap_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/adcs-ldap-direct",
            json={"domain_controller": "dc", "username": "u", "password": "p"},
        )
        assert resp.status_code == 403

    def test_scan_jwt_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/jwt-direct", json={"tokens": ["a.b.c"]}
        )
        assert resp.status_code == 403

    def test_scan_windows_cert_store_direct_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/scan/windows-cert-store-direct",
            json={"store_name": "My", "store_kind": "user", "dump": "x"},
        )
        assert resp.status_code == 403

    def test_sync_pkcs11_hsm_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/sync/pkcs11-hsm",
            json={
                "library_path": "/lib.so",
                "credentials": {"vault_path": "sec/pkcs11"},
            },
        )
        assert resp.status_code == 403

    def test_sync_kmip_kms_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/sync/kmip-kms",
            json={"host": "k", "port": 5696, "credentials": {"vault_path": "sec/kmip"}},
        )
        assert resp.status_code == 403

    def test_sync_adcs_ldap_forbidden(self, viewer_client, mock_db):
        resp = client.post(
            "/api/v1/connectors/sync/adcs-ldap",
            json={"domain_controller": "dc", "credentials": {"vault_path": "sec/adcs"}},
        )
        assert resp.status_code == 403


class TestScanDirectErrorStatuses:
    """Test the 'status': 'error' return branch for direct scan endpoints."""

    @pytest.fixture
    def zero_findings_db(self, mock_db):
        mock_count = MagicMock()
        mock_count.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count

    def test_scan_kubernetes_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.KubernetesConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["K8s err"]}
            resp = client.post(
                "/api/v1/connectors/scan/kubernetes-direct", json={"context": "x"}
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_oracle_tde_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.OracleTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["ORA err"]}
            resp = client.post(
                "/api/v1/connectors/scan/oracle-tde-direct",
                json={
                    "host": "o",
                    "port": 1521,
                    "service_name": "ORCL",
                    "username": "u",
                    "password": "p",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_sqlserver_tde_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.SQLServerTDEConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["SQL err"]}
            resp = client.post(
                "/api/v1/connectors/scan/sqlserver-tde-direct",
                json={
                    "host": "s",
                    "port": 1433,
                    "database": "m",
                    "username": "u",
                    "password": "p",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_pkcs11_hsm_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.PKCS11Connector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["HSM err"]}
            resp = client.post(
                "/api/v1/connectors/scan/pkcs11-hsm-direct",
                json={"library_path": "/lib.so", "pin": "1234"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_kmip_kms_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.KMIPConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["KMIP err"]}
            resp = client.post(
                "/api/v1/connectors/scan/kmip-kms-direct",
                json={"host": "k", "port": 5696},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_adcs_ldap_direct_error_status(self, zero_findings_db, mock_db):
        with patch(
            "app.api.connectors.ADCSConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["LDAP err"]}
            resp = client.post(
                "/api/v1/connectors/scan/adcs-ldap-direct",
                json={"domain_controller": "dc", "username": "u", "password": "p"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

    def test_scan_windows_cert_store_direct_error_status(
        self, zero_findings_db, mock_db
    ):
        with patch(
            "app.connectors.winstore_connector.WindowsCertStoreConnector.sync",
            new_callable=AsyncMock,
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["Win err"]}
            resp = client.post(
                "/api/v1/connectors/scan/windows-cert-store-direct",
                json={"store_name": "My", "store_kind": "user", "dump": "x"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"
