import sys
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
import pytest
from types import SimpleNamespace
from app.models.models import Asset

# ==================== Setup Mock Modules for sys.modules ====================


def mock_module(name):
    mock = MagicMock()
    sys.modules[name] = mock
    return mock


# Setup boto3
mock_boto3 = mock_module("boto3")

# Setup Azure
mock_azure = mock_module("azure")
mock_azure_identity = mock_module("azure.identity")
mock_azure.identity = mock_azure_identity
mock_azure_kv = mock_module("azure.keyvault")
mock_azure.keyvault = mock_azure_kv
mock_azure_kv_keys = mock_module("azure.keyvault.keys")
mock_azure_kv.keys = mock_azure_kv_keys

# Setup Google
mock_google = mock_module("google")
mock_google_cloud = mock_module("google.cloud")
mock_google.cloud = mock_google_cloud
mock_google_cloud_kms = mock_module("google.cloud.kms_v1")
mock_google_cloud.kms_v1 = mock_google_cloud_kms
mock_google_oauth = mock_module("google.oauth2")
mock_google.oauth2 = mock_google_oauth
mock_google_oauth_sa = mock_module("google.oauth2.service_account")
mock_google_oauth.service_account = mock_google_oauth_sa

# Now import the connector classes after mock modules are in sys.modules
from app.connectors.cloud_kms_connector import (
    AWSKMSConnector,
    AzureKeyVaultConnector,
    GCPKMSConnector,
)


@pytest.fixture(autouse=True)
def reset_shared_mocks():
    """Autouse fixture to reset all shared system module mocks between test cases."""
    mock_boto3.reset_mock()
    mock_azure_identity.reset_mock()
    mock_azure_kv_keys.reset_mock()
    mock_google_cloud_kms.reset_mock()
    mock_google_oauth_sa.reset_mock()
    mock_google_oauth_sa.Credentials.reset_mock()
    mock_google_oauth_sa.Credentials.from_service_account_info.reset_mock()


# ==================== AWS KMS Connector Tests ====================


@pytest.mark.asyncio
async def test_aws_kms_connector_import_error():
    # Hide boto3 to trigger ImportError
    orig = sys.modules.get("boto3")
    sys.modules["boto3"] = None
    try:
        connector = AWSKMSConnector(credentials_ref={})
        mock_session = AsyncMock()
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(mock_session)
        assert "boto3 is required" in str(exc.value)
    finally:
        sys.modules["boto3"] = orig


@pytest.mark.asyncio
async def test_aws_kms_connector_sync_new_and_existing_keys(mock_db):
    # Mock Vault credentials retrieval
    mock_credentials = {"vault_path": "secret/aws", "version": "1"}

    mock_secret = {
        "aws_access_key_id": "fake_aws_key_id",
        "aws_secret_access_key": "fake_aws_secret",
    }

    # Mock KMS client list/describe/policy calls
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Keys": [{"KeyId": "key-new"}, {"KeyId": "key-existing"}]}
    ]

    mock_desc_new = {
        "KeyMetadata": {
            "KeyId": "key-new",
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-new",
        }
    }

    mock_desc_existing = {
        "KeyMetadata": {
            "KeyId": "key-existing",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-existing",
        }
    }

    mock_kms_client = MagicMock()
    mock_kms_client.get_paginator.return_value = mock_paginator

    # describe_key side effect to return description depending on KeyId
    def mock_describe_key(KeyId):
        if KeyId == "key-new":
            return mock_desc_new
        return mock_desc_existing

    mock_kms_client.describe_key.side_effect = mock_describe_key

    # policy check triggers exception on key-new to test lines 67-68
    def mock_get_key_policy(KeyId, PolicyName):
        if KeyId == "key-new":
            raise Exception("Policy fetch failed")
        return {"Policy": '{"Version": "2012-10-17"}'}

    mock_kms_client.get_key_policy.side_effect = mock_get_key_policy

    # Mock DB returns: none for new key (first in loop), existing Asset for existing key (second)
    existing_asset = Asset(
        name="aws-kms:key-existing",
        asset_type="kms",
        asset_metadata={"provider": "aws", "key_id": "key-existing"},
    )

    mock_db_result_new = MagicMock()
    mock_db_result_new.scalar_one_or_none.return_value = None

    mock_db_result_existing = MagicMock()
    mock_db_result_existing.scalar_one_or_none.return_value = existing_asset

    # DB execute side effect to return None (for key-new) then existing asset (for key-existing)
    mock_db.execute.side_effect = [mock_db_result_new, mock_db_result_existing]

    # Run tests using patch of boto3 and get_vault_secret
    mock_boto3.client.return_value = mock_kms_client
    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ):
        connector = AWSKMSConnector(credentials_ref=mock_credentials)
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 1
        assert len(res["errors"]) == 0

        # Verify db add was called for new asset
        assert mock_db.add.call_count == 1
        added = mock_db.add.call_args[0][0]
        assert added.name == "aws-kms:key-new"
        assert added.asset_metadata["key_spec"] == "ECC_NIST_P256"

        # Verify existing asset updated metadata
        assert existing_asset.asset_metadata["key_spec"] == "RSA_2048"


@pytest.mark.asyncio
async def test_aws_kms_connector_error_handling(mock_db):
    class CredsObj:
        def __init__(self):
            self.vault_path = "secret/aws"
            self.version = "1"

    # describe_key will throw exception to test key individual error handling
    mock_kms_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-crashed"}]}]
    mock_kms_client.get_paginator.return_value = mock_paginator
    mock_kms_client.describe_key.side_effect = Exception("Describe failed")

    mock_boto3.client.return_value = mock_kms_client
    with patch(
        "app.connectors.vault_helper.get_vault_secret", new=AsyncMock(return_value={})
    ):
        connector = AWSKMSConnector(credentials_ref=CredsObj())
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 0
        assert len(res["errors"]) == 1
        assert "Describe failed" in res["errors"][0]


# ==================== Azure Key Vault Connector Tests ====================


@pytest.mark.asyncio
async def test_azure_kms_connector_import_error():
    orig_identity = sys.modules.get("azure.identity")
    orig_keys = sys.modules.get("azure.keyvault.keys")
    sys.modules["azure.identity"] = None
    sys.modules["azure.keyvault.keys"] = None
    try:
        connector = AzureKeyVaultConnector(
            credentials_ref={}, tenant_id="tenant", vault_url="http://vault"
        )
        mock_session = AsyncMock()
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(mock_session)
        assert "azure-identity and azure-keyvault-keys are required" in str(exc.value)
    finally:
        sys.modules["azure.identity"] = orig_identity
        sys.modules["azure.keyvault.keys"] = orig_keys


@pytest.mark.asyncio
async def test_azure_kms_connector_sync_secret_credential(mock_db):
    mock_secret = {
        "client_id": "client-id",
        "client_secret": "client-secret",
        "tenant_id": "tenant-id",
    }

    mock_key_properties1 = MagicMock()
    mock_key_properties1.name = "key1"

    mock_key_properties2 = MagicMock()
    mock_key_properties2.name = "key2"

    mock_key1 = MagicMock()
    mock_key1.key_type = "RSA"
    mock_key1.properties.version = "v1"

    mock_key2 = MagicMock()
    mock_key2.key_type = "EC"
    mock_key2.properties.version = "v2"

    mock_key_client = MagicMock()
    mock_key_client.list_properties_of_keys.return_value = [
        mock_key_properties1,
        mock_key_properties2,
    ]

    # get_key side effect
    def mock_get_key(name):
        if name == "key1":
            return mock_key1
        return mock_key2

    mock_key_client.get_key.side_effect = mock_get_key

    # DB setup
    existing_asset = Asset(
        name="azure-kv:key1",
        asset_type="kms",
        asset_metadata={"provider": "azure", "key_name": "key1"},
    )
    mock_db_result1 = MagicMock()
    mock_db_result1.scalar_one_or_none.return_value = existing_asset

    mock_db_result2 = MagicMock()
    mock_db_result2.scalar_one_or_none.return_value = None

    mock_db.execute.side_effect = [mock_db_result1, mock_db_result2]

    # Configure azure mocks
    mock_azure_identity.ClientSecretCredential.return_value = "secret-credential-obj"
    mock_azure_kv_keys.KeyClient.return_value = mock_key_client

    # Pass object as credentials_ref to test lines 141-143
    mock_credentials = SimpleNamespace(vault_path="secret/azure", version="2")

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ) as mock_vault:
        connector = AzureKeyVaultConnector(
            credentials_ref=mock_credentials,
            tenant_id="",
            vault_url="https://test.vault.azure.net/",
        )
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 1
        assert len(res["errors"]) == 0
        mock_vault.assert_called_once_with("secret/azure", "2")

        # Verify credential initialized correctly
        mock_azure_identity.ClientSecretCredential.assert_called_once_with(
            tenant_id="tenant-id", client_id="client-id", client_secret="client-secret"
        )
        mock_azure_kv_keys.KeyClient.assert_called_once_with(
            vault_url="https://test.vault.azure.net/",
            credential="secret-credential-obj",
        )


@pytest.mark.asyncio
async def test_azure_kms_connector_sync_default_credential_and_key_error(mock_db):
    # Vault secret lacks full oauth credentials -> DefaultAzureCredential fallback
    mock_secret = {}

    mock_key_properties = MagicMock()
    mock_key_properties.name = "crashed-key"
    mock_key_client = MagicMock()
    mock_key_client.list_properties_of_keys.return_value = [mock_key_properties]
    # get_key throws error to test individual key failure logging
    mock_key_client.get_key.side_effect = Exception("Get Key Failed")

    # DB execute mock
    mock_db.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )

    mock_azure_identity.DefaultAzureCredential.return_value = "default-credential-obj"
    mock_azure_kv_keys.KeyClient.return_value = mock_key_client

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ):
        connector = AzureKeyVaultConnector(
            credentials_ref={},
            tenant_id="t-id",
            vault_url="https://test.vault.azure.net/",
        )
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 0
        assert len(res["errors"]) == 1
        assert "Get Key Failed" in res["errors"][0]
        mock_azure_identity.DefaultAzureCredential.assert_called_once()


# ==================== GCP KMS Connector Tests ====================


@pytest.mark.asyncio
async def test_gcp_kms_connector_import_error():
    orig_google = sys.modules.get("google.cloud")
    sys.modules["google.cloud"] = None
    try:
        connector = GCPKMSConnector(project_id="proj", credentials_ref={})
        mock_session = AsyncMock()
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(mock_session)
        assert "google-cloud-kms is required" in str(exc.value)
    finally:
        sys.modules["google.cloud"] = orig_google


@pytest.mark.asyncio
async def test_gcp_kms_connector_sync_json_credentials(mock_db):
    mock_secret = {
        "credentials_json": '{"private_key": "fake_pk", "client_email": "fake@email.com"}'
    }

    mock_key1 = MagicMock()
    mock_key1.name = "projects/proj/locations/global/keyRings/ring/cryptoKeys/key-new"
    mock_key1.primary.algorithm.name = "RSA_SIGN_PSS_2048_SHA256"
    mock_key1.primary.protection_level.name = "SOFTWARE"
    mock_key1.purpose.name = "ASYMMETRIC_SIGN"

    mock_key2 = MagicMock()
    mock_key2.name = (
        "projects/proj/locations/global/keyRings/ring/cryptoKeys/key-existing"
    )
    mock_key2.primary.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_key2.primary.protection_level.name = "HSM"
    mock_key2.purpose.name = "ASYMMETRIC_SIGN"

    mock_gcp_client = MagicMock()
    mock_gcp_client.list_crypto_keys.return_value = [mock_key1, mock_key2]

    # DB mocks
    existing_asset = Asset(
        name="gcp-kms:key-existing",
        asset_type="kms",
        asset_metadata={
            "provider": "gcp",
            "key_name": "projects/proj/locations/global/keyRings/ring/cryptoKeys/key-existing",
        },
    )
    mock_db.execute.side_effect = [
        MagicMock(scalar_one_or_none=MagicMock(return_value=None)),  # new key
        MagicMock(
            scalar_one_or_none=MagicMock(return_value=existing_asset)
        ),  # existing key
    ]

    mock_google_oauth_sa.Credentials.from_service_account_info.return_value = (
        "fake-gcp-creds"
    )
    mock_google_cloud_kms.KeyManagementServiceClient.return_value = mock_gcp_client

    # Pass object as credentials_ref to test lines 241-243
    mock_credentials = SimpleNamespace(vault_path="secret/gcp", version="3")

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ) as mock_vault:
        connector = GCPKMSConnector(project_id="proj", credentials_ref=mock_credentials)
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 1
        assert len(res["errors"]) == 0
        mock_vault.assert_called_once_with("secret/gcp", "3")
        mock_google_oauth_sa.Credentials.from_service_account_info.assert_called_once()
        mock_google_cloud_kms.KeyManagementServiceClient.assert_called_once_with(
            credentials="fake-gcp-creds"
        )


@pytest.mark.asyncio
async def test_gcp_kms_connector_sync_direct_private_key_credentials(mock_db):
    mock_secret = {
        "private_key": "fake_pk_direct",
        "client_email": "fake_direct@email.com",
    }

    mock_gcp_client = MagicMock()
    mock_gcp_client.list_crypto_keys.return_value = []

    mock_google_oauth_sa.Credentials.from_service_account_info.return_value = (
        "fake-gcp-creds-direct"
    )
    mock_google_cloud_kms.KeyManagementServiceClient.return_value = mock_gcp_client

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ):
        connector = GCPKMSConnector(project_id="proj", credentials_ref={})
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 0
        mock_google_oauth_sa.Credentials.from_service_account_info.assert_called_once_with(
            mock_secret
        )


@pytest.mark.asyncio
async def test_gcp_kms_connector_sync_default_credentials_and_errors(mock_db):
    # Secret lacks credentials -> Client initialized with default credentials
    # Return bad json to trigger json loads exception at lines 255-256
    mock_secret = {"credentials_json": "invalid-json-{"}

    mock_gcp_client = MagicMock()
    mock_gcp_client.list_crypto_keys.side_effect = Exception("List keys crashed")

    mock_google_cloud_kms.KeyManagementServiceClient.return_value = mock_gcp_client

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ):
        connector = GCPKMSConnector(project_id="proj", credentials_ref={})
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert len(res["errors"]) == 1
        assert "List keys crashed" in res["errors"][0]


@pytest.mark.asyncio
async def test_gcp_kms_connector_sync_individual_key_error(mock_db):
    mock_secret = {}
    mock_key = MagicMock()
    mock_key.name = "projects/proj/locations/global/keyRings/ring/cryptoKeys/key-err"
    # Primary check crashes key metadata access
    type(mock_key).primary = PropertyMock(side_effect=Exception("Key primary error"))

    mock_gcp_client = MagicMock()
    mock_gcp_client.list_crypto_keys.return_value = [mock_key]

    mock_google_cloud_kms.KeyManagementServiceClient.return_value = mock_gcp_client

    with patch(
        "app.connectors.vault_helper.get_vault_secret",
        new=AsyncMock(return_value=mock_secret),
    ):
        connector = GCPKMSConnector(project_id="proj", credentials_ref={})
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert len(res["errors"]) == 1
        assert "Key primary error" in res["errors"][0]
