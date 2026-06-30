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


class TestConnectorSyncPermissionDenied:
    def _set_viewer_role(self):
        viewer = User(
            id="99999999-9999-9999-9999-999999999999",
            email="viewer@pqc.local",
            full_name="Viewer",
            role="viewer",
            is_active=True,
        )
        app.dependency_overrides[get_current_user] = lambda: viewer

    def _restore_admin(self):
        app.dependency_overrides[get_current_user] = lambda: mock_admin

    def test_sync_aws_kms_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/aws-kms",
                json={
                    "provider": "aws_kms",
                    "region": "us-east-1",
                    "credentials": {"vault_path": "secret/aws"},
                },
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_azure_kv_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/azure-key-vault",
                json={
                    "provider": "azure_key_vault",
                    "tenant_id": "t",
                    "vault_url": "https://v",
                    "credentials": {"vault_path": "secret/az"},
                },
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_gcp_kms_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/gcp-kms",
                json={
                    "provider": "gcp_kms",
                    "project_id": "p",
                    "credentials": {"vault_path": "secret/gcp"},
                },
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_vault_scanner_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/vault-scanner",
                json={
                    "provider": "vault_secrets",
                    "vault_url": "https://v:8200",
                    "token": "s.tok",
                },
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_git_secrets_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/git-secrets",
                json={"provider": "git_secrets", "repo_path": "/tmp/repo"},
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_import_csv_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            csv_data = b"name,asset_type\nserver1,server"
            resp = client.post(
                "/api/v1/connectors/import/csv",
                files={"file": ("cmdb.csv", csv_data, "text/csv")},
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_sast_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/sast",
                json={"provider": "sast_native", "target_path": "/src"},
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_jwt_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/jwt",
                json={"provider": "jwt_audit", "endpoint": "https://api.local/jwts"},
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_saml_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/saml",
                json={"metadata_url": "https://idp.example.com/metadata"},
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()

    def test_sync_windows_cert_store_forbidden_for_viewer(self, mock_db):
        self._set_viewer_role()
        try:
            resp = client.post(
                "/api/v1/connectors/sync/windows-cert-store",
                json={
                    "provider": "windows_cert_store",
                    "store_name": "My",
                    "store_kind": "user",
                },
            )
            assert resp.status_code == 403
        finally:
            self._restore_admin()


class TestConnectorSyncWithDirectCredentials:
    def test_sync_aws_kms_with_direct_credentials(self, mock_db):
        with patch(
            "app.api.connectors.AWSKMSConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "success", "imported": 1, "updated": 0}
            resp = client.post(
                "/api/v1/connectors/sync/aws-kms",
                json={
                    "provider": "aws_kms",
                    "region": "eu-west-1",
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "secret123",
                },
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "success"

    def test_sync_azure_with_direct_credentials(self, mock_db):
        with patch(
            "app.api.connectors.AzureKeyVaultConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "success", "imported": 1}
            resp = client.post(
                "/api/v1/connectors/sync/azure-key-vault",
                json={
                    "provider": "azure_key_vault",
                    "tenant_id": "tenant-123",
                    "vault_url": "https://myvault.vault.azure.net",
                    "client_id": "client-123",
                    "client_secret": "secret-123",
                },
            )
            assert resp.status_code == 200

    def test_sync_gcp_kms_with_credentials_json(self, mock_db):
        with patch(
            "app.api.connectors.GCPKMSConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {"status": "success", "imported": 1}
            resp = client.post(
                "/api/v1/connectors/sync/gcp-kms",
                json={
                    "provider": "gcp_kms",
                    "project_id": "my-project",
                    "credentials_json": '{"type": "service_account"}',
                },
            )
            assert resp.status_code == 200

    def test_sync_gcp_kms_with_credentials_path_not_found(self, mock_db):
        resp = client.post(
            "/api/v1/connectors/sync/gcp-kms",
            json={
                "provider": "gcp_kms",
                "project_id": "my-project",
                "credentials_path": "/nonexistent/path.json",
            },
        )
        assert resp.status_code == 400
        assert "Could not read credentials_path" in resp.json()["detail"]


class TestImportCSVEdgeCases:
    def test_import_csv_non_csv_file(self, mock_db):
        resp = client.post(
            "/api/v1/connectors/import/csv",
            files={"file": ("data.txt", b"hello", "text/plain")},
        )
        assert resp.status_code == 400
        assert "CSV file" in resp.json()["detail"]

    def test_import_csv_error_result(self, mock_db):
        with patch(
            "app.api.connectors.CSVCMDBConnector.sync", new_callable=AsyncMock
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "error",
                "error": "CSV is empty or missing headers",
            }
            csv_data = b"   "
            resp = client.post(
                "/api/v1/connectors/import/csv",
                files={"file": ("cmdb.csv", csv_data, "text/csv")},
            )
            assert resp.status_code == 400


class TestConnectorScanEndpoints:
    def test_scan_aws_pqc_success(self, mock_db):
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count_result

        with patch("app.api.connectors.AWSPQCScanner") as MockScanner:
            mock_instance = MockScanner.return_value
            mock_instance.scan = AsyncMock(
                return_value={
                    "assets_created": 5,
                    "assets_updated": 2,
                    "findings_created": 3,
                    "services_scanned": ["kms", "acm"],
                    "algorithms_recorded": 10,
                    "certificates_recorded": 4,
                    "errors": [],
                }
            )
            resp = client.post(
                "/api/v1/connectors/scan/aws-pqc",
                json={
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "secret123",
                    "region": "us-east-1",
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["assets_discovered"] == 5
        assert data["findings_created"] == 3

    def test_scan_aws_pqc_failure(self, mock_db):
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count_result

        with patch("app.api.connectors.AWSPQCScanner") as MockScanner:
            mock_instance = MockScanner.return_value
            mock_instance.scan = AsyncMock(side_effect=Exception("AWS access denied"))
            resp = client.post(
                "/api/v1/connectors/scan/aws-pqc",
                json={
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "wrong",
                    "region": "us-east-1",
                },
            )
        assert resp.status_code == 500
        assert "AWS access denied" in resp.json()["detail"]

    def test_scan_aws_pqc_forbidden_for_viewer(self, mock_db):
        viewer = User(
            id="99999999-9999-9999-9999-999999999999",
            email="viewer@pqc.local",
            full_name="Viewer",
            role="viewer",
            is_active=True,
        )
        app.dependency_overrides[get_current_user] = lambda: viewer
        try:
            resp = client.post(
                "/api/v1/connectors/scan/aws-pqc",
                json={
                    "access_key_id": "AKIATEST",
                    "secret_access_key": "secret123",
                    "region": "us-east-1",
                },
            )
            assert resp.status_code == 403
        finally:
            app.dependency_overrides[get_current_user] = lambda: mock_admin


class TestWindowsCertStoreSyncEdgeCases:
    def test_sync_windows_cert_store_machine_kind(self, mock_db):
        with patch(
            "app.connectors.winstore_connector.WindowsCertStoreConnector.sync",
            new_callable=AsyncMock,
        ) as mock_sync:
            mock_sync.return_value = {"status": "success"}
            resp = client.post(
                "/api/v1/connectors/sync/windows-cert-store",
                json={
                    "provider": "windows_cert_store",
                    "store_name": "My",
                    "store_kind": "machine",
                },
            )
            assert resp.status_code == 200

    def test_sync_windows_cert_store_invalid_kind(self, mock_db):
        resp = client.post(
            "/api/v1/connectors/sync/windows-cert-store",
            json={
                "provider": "windows_cert_store",
                "store_name": "My",
                "store_kind": "invalid_kind",
            },
        )
        assert resp.status_code == 400
        assert "store_kind" in resp.json()["detail"]


class TestSAMLScanEndpoints:
    def test_scan_saml_direct_error_result(self, mock_db):
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count_result

        with patch(
            "app.connectors.saml_connector.SAMLMetadataConnector.sync",
            new_callable=AsyncMock,
        ) as mock_sync:
            mock_sync.return_value = {"status": "error", "errors": ["Invalid XML"]}
            resp = client.post(
                "/api/v1/connectors/scan/saml-direct", json={"xml_blob": "not-xml"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "error"

    def test_scan_saml_direct_exception(self, mock_db):
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count_result

        with patch(
            "app.connectors.saml_connector.SAMLMetadataConnector.sync",
            new_callable=AsyncMock,
            side_effect=Exception("Parse error"),
        ):
            resp = client.post(
                "/api/v1/connectors/scan/saml-direct", json={"xml_blob": "<invalid/>"}
            )
        assert resp.status_code == 500
        assert "Parse error" in resp.json()["detail"]

    def test_scan_saml_direct_with_token(self, mock_db):
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_db.execute.return_value = mock_count_result

        with patch(
            "app.connectors.saml_connector.SAMLMetadataConnector.sync",
            new_callable=AsyncMock,
        ) as mock_sync:
            mock_sync.return_value = {
                "status": "success",
                "imported": 1,
                "updated": 0,
                "errors": [],
            }
            resp = client.post(
                "/api/v1/connectors/scan/saml-direct",
                json={
                    "metadata_url": "https://idp.example.com/metadata",
                    "token": "bearer-token-123",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"
