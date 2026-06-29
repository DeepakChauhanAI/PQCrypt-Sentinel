import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import base64

# Setup mock modules for kubernetes
mock_k8s = MagicMock()
mock_k8s_client = MagicMock()
mock_k8s_config = MagicMock()
mock_k8s.client = mock_k8s_client
mock_k8s.config = mock_k8s_config
sys.modules["kubernetes"] = mock_k8s
sys.modules["kubernetes.client"] = mock_k8s_client
sys.modules["kubernetes.config"] = mock_k8s_config

from app.models.models import Asset
from app.connectors.k8s_connector import KubernetesConnector


@pytest.fixture(autouse=True)
def reset_k8s_mocks():
    mock_k8s.reset_mock()
    mock_k8s_client.reset_mock()
    mock_k8s_config.reset_mock()


@pytest.mark.asyncio
async def test_k8s_get_credentials_dict():
    connector = KubernetesConnector(
        credentials_ref={"vault_path": "secret/pqc/k8s", "version": 1},
    )
    with patch("app.connectors.k8s_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"token": "my-token"}
        creds = await connector._get_credentials()
        mock_get.assert_called_once_with("secret/pqc/k8s", 1)
        assert creds == {"token": "my-token"}


@pytest.mark.asyncio
async def test_k8s_get_credentials_obj():
    class FakeRef:
        def __init__(self):
            self.vault_path = "secret/pqc/k8s-obj"
            self.version = 2

    connector = KubernetesConnector(credentials_ref=FakeRef())
    with patch("app.connectors.k8s_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"token": "my-token-obj"}
        creds = await connector._get_credentials()
        mock_get.assert_called_once_with("secret/pqc/k8s-obj", 2)
        assert creds == {"token": "my-token-obj"}


@pytest.mark.asyncio
async def test_k8s_create_client_missing_library():
    connector = KubernetesConnector(credentials_ref={})
    # Hide kubernetes package
    orig = sys.modules.get("kubernetes")
    sys.modules["kubernetes"] = None
    try:
        with pytest.raises(RuntimeError) as exc:
            await connector._create_k8s_client()
        assert "kubernetes client is required" in str(exc.value)
    finally:
        sys.modules["kubernetes"] = orig


@pytest.mark.asyncio
async def test_k8s_create_client_kubeconfig_tempfile():
    connector = KubernetesConnector(credentials_ref={}, context="prod-context")
    creds = {"kubeconfig": "apiVersion: v1\nclusters: []"}

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds), \
         patch("os.path.exists", return_value=True) as mock_exists, \
         patch("os.unlink") as mock_unlink:
             
        await connector._create_k8s_client()
        
        mock_k8s_config.load_kube_config.assert_called_once()
        call_kwargs = mock_k8s_config.load_kube_config.call_args[1]
        assert "config_file" in call_kwargs
        assert call_kwargs["context"] == "prod-context"
        mock_unlink.assert_called_once_with(call_kwargs["config_file"])


@pytest.mark.asyncio
async def test_k8s_create_client_token_auth():
    connector = KubernetesConnector(credentials_ref={})
    creds = {
        "token": "secret-token",
        "host": "https://api.k8s.local",
        "verify_ssl": True,
        "ca_cert": "---BEGIN CERTIFICATE---\n..."
    }

    mock_configuration = MagicMock()
    mock_k8s_client.Configuration.return_value = mock_configuration
    
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds):
        await connector._create_k8s_client()
        
        assert mock_configuration.host == "https://api.k8s.local"
        assert mock_configuration.api_key == {"authorization": "Bearer secret-token"}
        assert mock_configuration.verify_ssl is True
        assert mock_configuration.ssl_ca_cert == "---BEGIN CERTIFICATE---\n..."
        mock_k8s_client.ApiClient.assert_called_once_with(mock_configuration)
        assert connector.api_client == mock_k8s_client.ApiClient.return_value


@pytest.mark.asyncio
async def test_k8s_create_client_kubeconfig_path():
    connector = KubernetesConnector(credentials_ref={}, context="dev-ctx", kubeconfig_path="/path/kube.yaml")
    
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        await connector._create_k8s_client()
        
        mock_k8s_config.load_kube_config.assert_called_once_with(
            config_file="/path/kube.yaml",
            context="dev-ctx"
        )


@pytest.mark.asyncio
async def test_k8s_create_client_fallback_incluster_success():
    connector = KubernetesConnector(credentials_ref={})
    
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        await connector._create_k8s_client()
        
        mock_k8s_config.load_incluster_config.assert_called_once()
        mock_k8s_config.load_kube_config.assert_not_called()


@pytest.mark.asyncio
async def test_k8s_create_client_fallback_incluster_failure():
    connector = KubernetesConnector(credentials_ref={}, context="fallback-context")
    mock_k8s_config.load_incluster_config.side_effect = Exception("Not in cluster")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        await connector._create_k8s_client()
        
        mock_k8s_config.load_incluster_config.assert_called_once()
        mock_k8s_config.load_kube_config.assert_called_once_with(context="fallback-context")


@pytest.mark.asyncio
async def test_k8s_get_secrets():
    connector = KubernetesConnector(credentials_ref={})
    
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    
    # Secret 1: TLS type with valid cert encoding
    secret1 = MagicMock()
    secret1.type = "kubernetes.io/tls"
    secret1.metadata.namespace = "default"
    secret1.metadata.name = "secret-1"
    secret1.metadata.creation_timestamp = "2026-01-01T00:00:00Z"
    encoded_cert = base64.b64encode(b"my-cert-content").decode("utf-8")
    secret1.data = {"tls.crt": encoded_cert, "tls.key": "encodedkey"}
    
    # Secret 2: normal type but has custom crt keys
    secret2 = MagicMock()
    secret2.type = "Opaque"
    secret2.metadata.namespace = "kube-system"
    secret2.metadata.name = "secret-2"
    secret2.metadata.creation_timestamp = None
    secret2.data = {"app.crt": "content"}
    
    # Secret 3: does not match TLS
    secret3 = MagicMock()
    secret3.type = "Opaque"
    secret3.metadata.namespace = "default"
    secret3.metadata.name = "secret-3"
    secret3.data = {"config.yaml": "something"}

    mock_v1.list_secret_for_all_namespaces.return_value.items = [secret1, secret2, secret3]
    
    secrets = await connector._get_secrets()
    assert len(secrets) == 2
    
    assert secrets[0]["name"] == "secret-1"
    assert secrets[0]["namespace"] == "default"
    assert secrets[0]["type"] == "kubernetes.io/tls"
    assert secrets[0]["creation_timestamp"] == "2026-01-01T00:00:00Z"
    assert secrets[0]["keys"] == ["tls.crt", "tls.key"]
    assert secrets[0]["has_cert"] is True
    assert secrets[0]["has_key"] is True
    assert secrets[0]["cert_pem"] == "my-cert-content"

    assert secrets[1]["name"] == "secret-2"
    assert secrets[1]["has_cert"] is True
    assert secrets[1]["has_key"] is False


@pytest.mark.asyncio
async def test_k8s_get_secrets_decoding_exception():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1

    secret1 = MagicMock()
    secret1.type = "tls"
    secret1.metadata.namespace = "default"
    secret1.metadata.name = "secret-1"
    secret1.metadata.creation_timestamp = None
    # Bad base64 string
    secret1.data = {"tls.crt": "bad-b64-value@@@@", "tls.key": "key"}

    mock_v1.list_secret_for_all_namespaces.return_value.items = [secret1]
    
    secrets = await connector._get_secrets()
    assert len(secrets) == 1
    assert "cert_pem" not in secrets[0]


@pytest.mark.asyncio
async def test_k8s_get_secrets_error():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    mock_v1.list_secret_for_all_namespaces.side_effect = Exception("API Server down")

    secrets = await connector._get_secrets()
    assert secrets == []


@pytest.mark.asyncio
async def test_k8s_get_certificates():
    connector = KubernetesConnector(credentials_ref={})
    
    # 1. CustomObjectsApi success
    mock_custom = MagicMock()
    mock_k8s_client.CustomObjectsApi.return_value = mock_custom
    mock_custom.list_cluster_custom_object.return_value = {
        "items": [
            {
                "metadata": {"namespace": "default", "name": "cert-1"},
                "spec": {"commonName": "example.com"},
                "status": {"conditions": []}
            }
        ]
    }
    
    # 2. CertificatesV1Api success
    mock_certs_v1 = MagicMock()
    mock_k8s_client.CertificatesV1Api.return_value = mock_certs_v1
    
    csr1 = MagicMock()
    csr1.metadata.name = "csr-1"
    csr1.spec.username = "system:node:node1"
    csr1.spec.groups = ["system:nodes"]
    csr1.spec.usages = ["client auth"]
    
    cond1 = MagicMock()
    cond1.type = "Approved"
    cond1.status = "True"
    cond1.reason = "NodeRestriction"
    cond1.message = "Approved by node restriction"
    csr1.status.conditions = [cond1]
    
    mock_certs_v1.list_certificate_signing_request.return_value.items = [csr1]
    
    certs = await connector._get_certificates()
    assert len(certs) == 2
    
    assert certs[0]["name"] == "cert-1"
    assert certs[0]["namespace"] == "default"
    assert certs[0]["spec"] == {"commonName": "example.com"}
    
    assert certs[1]["name"] == "csr-1"
    assert certs[1]["username"] == "system:node:node1"
    assert certs[1]["groups"] == ["system:nodes"]
    assert certs[1]["usages"] == ["client auth"]
    assert certs[1]["status"]["conditions"] == [{
        "type": "Approved",
        "status": "True",
        "reason": "NodeRestriction",
        "message": "Approved by node restriction"
    }]


@pytest.mark.asyncio
async def test_k8s_get_certificates_crd_missing_but_csr_succeeds():
    connector = KubernetesConnector(credentials_ref={})
    
    mock_custom = MagicMock()
    mock_k8s_client.CustomObjectsApi.return_value = mock_custom
    # cert-manager CRD is missing
    mock_custom.list_cluster_custom_object.side_effect = Exception("CRD not found")
    
    mock_certs_v1 = MagicMock()
    mock_k8s_client.CertificatesV1Api.return_value = mock_certs_v1
    
    csr1 = MagicMock()
    csr1.metadata.name = "csr-only"
    csr1.spec.username = "user"
    csr1.spec.groups = []
    csr1.spec.usages = []
    csr1.status = None # Status is None
    mock_certs_v1.list_certificate_signing_request.return_value.items = [csr1]

    certs = await connector._get_certificates()
    assert len(certs) == 1
    assert certs[0]["name"] == "csr-only"
    assert certs[0]["status"] == {}


@pytest.mark.asyncio
async def test_k8s_get_certificates_api_error():
    connector = KubernetesConnector(credentials_ref={})
    mock_custom = MagicMock()
    mock_k8s_client.CustomObjectsApi.return_value = mock_custom
    mock_custom.list_cluster_custom_object.side_effect = Exception("API Server error")
    
    mock_certs_v1 = MagicMock()
    mock_k8s_client.CertificatesV1Api.return_value = mock_certs_v1
    mock_certs_v1.list_certificate_signing_request.side_effect = Exception("CSR API error")

    certs = await connector._get_certificates()
    assert certs == []


@pytest.mark.asyncio
async def test_k8s_get_etcd_encryption():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    
    # Mock api-server pod
    pod = MagicMock()
    pod.spec.containers = []
    
    c1 = MagicMock()
    c1.command = [
        "kube-apiserver",
        "--encryption-provider-config=/etc/kubernetes/enc.yaml",
        "--some-other-arg"
    ]
    pod.spec.containers = [c1]
    
    mock_v1.list_namespaced_pod.return_value.items = [pod]
    
    res = await connector._get_etcd_encryption()
    assert res["encryption_enabled"] is True
    assert res["config_path"] == "/etc/kubernetes/enc.yaml"


@pytest.mark.asyncio
async def test_k8s_get_etcd_encryption_no_equals():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1

    # Mock api-server pod with arg containing key but no "="
    pod = MagicMock()
    pod.spec.containers = []
    
    c = MagicMock()
    c.command = [
        "kube-apiserver",
        "--encryption-provider-config",
        "--another-arg"
    ]
    pod.spec.containers = [c]
    
    mock_v1.list_namespaced_pod.return_value.items = [pod]
    
    res = await connector._get_etcd_encryption()
    assert res["encryption_enabled"] is True
    assert res["config_path"] == "--encryption-provider-config"


@pytest.mark.asyncio
async def test_k8s_get_etcd_encryption_failures():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    mock_v1.list_namespaced_pod.side_effect = Exception("Pod check failed")

    res = await connector._get_etcd_encryption()
    assert res == {"encryption_enabled": False, "config": None}


@pytest.mark.asyncio
async def test_k8s_get_apiserver_cert():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1

    pod = MagicMock()
    c = MagicMock()
    c.command = [
        "kube-apiserver",
        "--tls-cert-file=/etc/kubernetes/cert.pem",
        "--tls-private-key-file=/etc/kubernetes/key.pem"
    ]
    pod.spec.containers = [c]
    mock_v1.list_namespaced_pod.return_value.items = [pod]

    res = await connector._get_apiserver_cert()
    assert res == {
        "tls_cert_file": "/etc/kubernetes/cert.pem",
        "tls_key_file": "/etc/kubernetes/key.pem",
    }


@pytest.mark.asyncio
async def test_k8s_get_apiserver_cert_no_equals():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1

    pod = MagicMock()
    c = MagicMock()
    c.command = [
        "kube-apiserver",
        "--tls-cert-file",
        "--tls-private-key-file"
    ]
    pod.spec.containers = [c]
    mock_v1.list_namespaced_pod.return_value.items = [pod]

    res = await connector._get_apiserver_cert()
    assert res == {
        "tls_cert_file": "--tls-cert-file",
        "tls_key_file": "--tls-private-key-file",
    }


@pytest.mark.asyncio
async def test_k8s_get_apiserver_cert_error():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    mock_v1.list_namespaced_pod.side_effect = Exception("Kube API down")

    res = await connector._get_apiserver_cert()
    assert res == {}


@pytest.mark.asyncio
async def test_k8s_get_kubelet_certs():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1

    # Node 1: has status addresses
    n1 = MagicMock()
    n1.metadata.name = "node-1"
    a1 = MagicMock()
    a1.address = "192.168.1.10"
    n1.status.addresses = [a1]

    # Node 2: status addresses is None
    n2 = MagicMock()
    n2.metadata.name = "node-2"
    n2.status.addresses = None

    mock_v1.list_node.return_value.items = [n1, n2]

    res = await connector._get_kubelet_certs()
    assert len(res) == 2
    assert res[0] == {"node": "node-1", "addresses": ["192.168.1.10"]}
    assert res[1] == {"node": "node-2", "addresses": []}


@pytest.mark.asyncio
async def test_k8s_get_kubelet_certs_error():
    connector = KubernetesConnector(credentials_ref={})
    mock_v1 = MagicMock()
    mock_k8s_client.CoreV1Api.return_value = mock_v1
    mock_v1.list_node.side_effect = Exception("Node listing error")

    res = await connector._get_kubelet_certs()
    assert res == []


@pytest.mark.asyncio
async def test_k8s_connector_sync_new_asset(mock_db):
    connector = KubernetesConnector(credentials_ref={}, context="prod-cluster")
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    # Mock parallel functions
    fake_secrets = [
        {"name": "sec-1", "namespace": "ns-1", "type": "tls", "has_cert": True, "has_key": True, "cert_pem": "pem-content"}
    ]
    fake_certs = [{"name": "c-1"}]
    fake_etcd = {"encryption_enabled": True}
    fake_api_cert = {"tls_cert_file": "cert.pem"}
    fake_kubelets = [{"node": "n-1"}]

    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock) as mock_create, \
         patch.object(connector, "_get_secrets", new_callable=AsyncMock, return_value=fake_secrets), \
         patch.object(connector, "_get_certificates", new_callable=AsyncMock, return_value=fake_certs), \
         patch.object(connector, "_get_etcd_encryption", new_callable=AsyncMock, return_value=fake_etcd), \
         patch.object(connector, "_get_apiserver_cert", new_callable=AsyncMock, return_value=fake_api_cert), \
         patch.object(connector, "_get_kubelet_certs", new_callable=AsyncMock, return_value=fake_kubelets), \
         patch("app.scanners.cert_parser.parse_certificate") as mock_parse:
             
        mock_parse.return_value = {"subject": "CN=me"}
        
        res = await connector.sync(mock_db)
        
        mock_create.assert_called_once()
        mock_parse.assert_called_once_with("pem-content")
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 0
        assert len(res["errors"]) == 0
        
        mock_db.add.assert_called_once()
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.name == "k8s:prod-cluster"
        assert added_asset.asset_type == "kubernetes"
        assert added_asset.asset_metadata["total_secrets"] == 1
        assert added_asset.asset_metadata["tls_secrets_count"] == 1
        assert added_asset.asset_metadata["cert_details"] == [{"subject": "CN=me", "namespace": "ns-1", "secret_name": "sec-1"}]


@pytest.mark.asyncio
async def test_k8s_connector_sync_existing_asset(mock_db):
    connector = KubernetesConnector(credentials_ref={}, context="prod-cluster")
    
    existing_asset = Asset(
        name="k8s:prod-cluster",
        asset_type="kubernetes",
        asset_metadata={}
    )
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = existing_asset
    mock_db.execute.return_value = mock_db_result

    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock), \
         patch.object(connector, "_get_secrets", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_certificates", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_etcd_encryption", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_apiserver_cert", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kubelet_certs", new_callable=AsyncMock, return_value=[]):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 1
        assert existing_asset.asset_metadata["cluster_name"] == "prod-cluster"


@pytest.mark.asyncio
async def test_k8s_connector_sync_parse_certificate_exception(mock_db):
    connector = KubernetesConnector(credentials_ref={})
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    fake_secrets = [
        {"name": "sec-1", "namespace": "ns-1", "type": "tls", "has_cert": True, "has_key": True, "cert_pem": "pem-content"}
    ]

    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock), \
         patch.object(connector, "_get_secrets", new_callable=AsyncMock, return_value=fake_secrets), \
         patch.object(connector, "_get_certificates", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_etcd_encryption", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_apiserver_cert", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kubelet_certs", new_callable=AsyncMock, return_value=[]), \
         patch("app.scanners.cert_parser.parse_certificate", side_effect=Exception("Parsing crash")):
             
        res = await connector.sync(mock_db)
        assert res["status"] == "success"
        
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.asset_metadata["cert_details"] == []


@pytest.mark.asyncio
async def test_k8s_connector_sync_client_creation_error():
    connector = KubernetesConnector(credentials_ref={})
    with patch.object(connector, "_create_k8s_client", side_effect=Exception("Failed to resolve host")):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "Failed to create Kubernetes client" in str(exc.value)


@pytest.mark.asyncio
async def test_k8s_connector_sync_parallel_exceptions(mock_db):
    connector = KubernetesConnector(credentials_ref={})
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    # Raise exceptions in all gather tasks
    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock), \
         patch.object(connector, "_get_secrets", side_effect=Exception("sec error")), \
         patch.object(connector, "_get_certificates", side_effect=Exception("cert error")), \
         patch.object(connector, "_get_etcd_encryption", side_effect=Exception("etcd error")), \
         patch.object(connector, "_get_apiserver_cert", side_effect=Exception("api error")), \
         patch.object(connector, "_get_kubelet_certs", side_effect=Exception("kubelet error")):
             
        res = await connector.sync(mock_db)
        assert res["status"] == "success"
        assert len(res["errors"]) == 5
        assert "secrets: sec error" in res["errors"]
        
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.asset_metadata["total_secrets"] == 0
        assert added_asset.asset_metadata["certificates"] == []
        assert added_asset.asset_metadata["etcd_encryption"] == {}
        assert added_asset.asset_metadata["apiserver_cert"] == {}
        assert added_asset.asset_metadata["kubelets"] == []


@pytest.mark.asyncio
async def test_k8s_connector_sync_outer_exception(mock_db):
    connector = KubernetesConnector(credentials_ref={})
    
    # DB execute raises exception to trigger the outer sync except block
    mock_db.execute.side_effect = Exception("DB connection aborted")

    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock), \
         patch.object(connector, "_get_secrets", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_certificates", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_etcd_encryption", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_apiserver_cert", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kubelet_certs", new_callable=AsyncMock, return_value=[]):
             
        res = await connector.sync(mock_db)
        assert res["status"] == "error"
        assert "Kubernetes sync failed: DB connection aborted" in res["errors"][0]
