import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

# Mock modules for sys.modules
mock_pkcs11 = MagicMock()
mock_pkcs11.Attribute = MagicMock()
mock_pkcs11.Attribute.CLASS = "CLASS"
mock_pkcs11.Attribute.LABEL = "LABEL"
mock_pkcs11.Attribute.ID = "ID"
mock_pkcs11.Attribute.KEY_TYPE = "KEY_TYPE"
mock_pkcs11.Attribute.MODULUS_BITS = "MODULUS_BITS"
mock_pkcs11.Attribute.VALUE_BITS = "VALUE_BITS"

mock_pkcs11.ObjectClass = MagicMock()
mock_pkcs11.ObjectClass.PUBLIC_KEY = "PUBLIC_KEY"
mock_pkcs11.ObjectClass.PRIVATE_KEY = "PRIVATE_KEY"
mock_pkcs11.ObjectClass.SECRET_KEY = "SECRET_KEY"

sys.modules["pkcs11"] = mock_pkcs11

# Mock kmip
mock_kmip = MagicMock()
mock_kmip_client = MagicMock()
mock_kmip_enums = MagicMock()
mock_kmip_objects = MagicMock()
mock_kmip.client = mock_kmip_client
mock_kmip.core.enums = mock_kmip_enums
mock_kmip.pie.objects = mock_kmip_objects
sys.modules["kmip"] = mock_kmip
sys.modules["kmip.client"] = mock_kmip_client
sys.modules["kmip.core"] = MagicMock()
sys.modules["kmip.core.enums"] = mock_kmip_enums
sys.modules["kmip.pie"] = MagicMock()
sys.modules["kmip.pie.objects"] = mock_kmip_objects

# Mock ldap3
mock_ldap3 = MagicMock()
mock_ldap3.ALL = "ALL"
mock_ldap3.SIMPLE = "SIMPLE"
sys.modules["ldap3"] = mock_ldap3

from app.models.models import Asset
from app.connectors.pkcs11_connector import PKCS11Connector, KMIPConnector, ADCSConnector


@pytest.fixture(autouse=True)
def reset_pkcs11_mocks():
    mock_pkcs11.reset_mock()
    mock_pkcs11.lib.side_effect = None
    mock_kmip.reset_mock()
    mock_kmip_client.KMIPClient.side_effect = None
    mock_kmip_client.KMIPClient.return_value = MagicMock()
    mock_ldap3.reset_mock()
    mock_ldap3.Connection.side_effect = None
    mock_ldap3.Connection.return_value = MagicMock()
    mock_ldap3.Server.side_effect = None
    mock_ldap3.Server.return_value = MagicMock()


# ==================== PKCS11Connector Tests ====================

@pytest.mark.asyncio
async def test_pkcs11_get_credentials():
    connector = PKCS11Connector("lib.so", credentials_ref={"vault_path": "sec", "version": 1})
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"pin": "123"}
        creds = await connector._get_credentials()
        assert creds == {"pin": "123"}

    class ObjRef:
        vault_path = "sec2"
        version = None
    connector2 = PKCS11Connector("lib.so", credentials_ref=ObjRef())
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"pin": "456"}
        creds = await connector2._get_credentials()
        assert creds == {"pin": "456"}


@pytest.mark.asyncio
async def test_pkcs11_sync_missing_import():
    orig = sys.modules.get("pkcs11")
    sys.modules["pkcs11"] = None
    try:
        connector = PKCS11Connector("lib.so", {})
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "python-pkcs11 is required" in str(exc.value)
    finally:
        sys.modules["pkcs11"] = orig


@pytest.mark.asyncio
async def test_pkcs11_sync_missing_pin():
    connector = PKCS11Connector("lib.so", {})
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "requires user_pin" in str(exc.value)


@pytest.mark.asyncio
async def test_pkcs11_sync_success_new_and_existing_assets(mock_db):
    connector = PKCS11Connector(
        library_path="lib.so",
        credentials_ref={"vault_path": "sec"},
        slot_id=1,
        token_label="token1"
    )

    creds = {"user_pin": "pin123"}
    
    mock_lib = MagicMock()
    mock_pkcs11.lib.return_value = mock_lib
    
    # Slot 1: Matches slot_id=1
    slot1 = MagicMock()
    slot1.slot_id = 1
    token1 = MagicMock()
    token1.label = "token1"
    slot1.get_token.return_value = token1
    
    # Slot 2: Doesn't match slot_id=1
    slot2 = MagicMock()
    slot2.slot_id = 2
    
    # Slot 3: Matches slot_id=1, but token label doesn't match
    slot3 = MagicMock()
    slot3.slot_id = 1
    token3 = MagicMock()
    token3.label = "other-token"
    slot3.get_token.return_value = token3

    # Slot 4: Matches slot_id=1, but get_token raises exception to cover line 106-107
    slot4 = MagicMock()
    slot4.slot_id = 1
    slot4.get_token.side_effect = Exception("Failed to get token metadata")

    mock_lib.get_slots.return_value = [slot1, slot2, slot3, slot4]

    mock_session = MagicMock()
    
    class DummyContext:
        def __enter__(self):
            return mock_session
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    token1.open.return_value = DummyContext()

    # Object 1: Public Key, has Modulus bits
    obj1 = MagicMock()
    obj1.label = "obj1-label"
    
    # Object 2: Secret Key, has Value bits
    obj2 = MagicMock()
    obj2.label = "obj2-label"
    
    # Object 3: Triggers exception on label fetch to test exception path
    obj3 = MagicMock()
    obj3.get_attribute.side_effect = Exception("Attribute read failure")

    # Object 4: Secret Key, has NO MODULUS_BITS and value bits fetch crashes to cover lines 92-93
    obj4 = MagicMock()
    obj4.label = "obj4-label"

    mock_session.get_objects.return_value = [obj1, obj2, obj3, obj4]

    def mock_get_attribute(attr, default=None):
        if attr == "CLASS":
            if mock_get_attribute.curr_obj == obj1:
                return "PUBLIC_KEY"
            return "SECRET_KEY"
        if attr == "LABEL":
            if mock_get_attribute.curr_obj == obj1:
                return "obj1-label"
            if mock_get_attribute.curr_obj == obj2:
                return "obj2-label"
            return "obj4-label"
        if attr == "ID":
            return b"\x01\x02\x03"
        if attr == "KEY_TYPE":
            return "RSA"
        if attr == "MODULUS_BITS":
            if mock_get_attribute.curr_obj == obj1:
                return 2048
            raise Exception("No modulus bits")
        if attr == "VALUE_BITS":
            if mock_get_attribute.curr_obj == obj2:
                return 256
            raise Exception("No value bits")
        return None

    # Track which object is currently queried
    def wrap_side_effect(obj):
        def effect(attr, default=None):
            mock_get_attribute.curr_obj = obj
            return mock_get_attribute(attr, default)
        return effect
    obj1.get_attribute.side_effect = wrap_side_effect(obj1)
    obj2.get_attribute.side_effect = wrap_side_effect(obj2)
    obj4.get_attribute.side_effect = wrap_side_effect(obj4)

    # Database returns None for obj1, obj4, and returns existing asset for obj2
    mock_db_result_new1 = MagicMock()
    mock_db_result_new1.scalar_one_or_none.return_value = None

    existing_asset = Asset(
        name="pkcs11:token1:obj2-label",
        asset_type="hsm_key",
        asset_metadata={}
    )
    mock_db_result_existing = MagicMock()
    mock_db_result_existing.scalar_one_or_none.return_value = existing_asset
    
    mock_db_result_new2 = MagicMock()
    mock_db_result_new2.scalar_one_or_none.return_value = None

    mock_db.execute.side_effect = [mock_db_result_new1, mock_db_result_existing, mock_db_result_new2]

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds):
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 2
        assert res["updated"] == 1
        assert len(res["errors"]) == 2  # obj3 failed + slot4 failed
        
        # Verify imported asset details
        assert mock_db.add.call_count == 2
        added_asset = mock_db.add.call_args_list[0][0][0]
        assert added_asset.name == "pkcs11:token1:obj1-label"
        assert added_asset.asset_metadata["key_size"] == 2048
        
        # Verify updated asset details
        assert existing_asset.asset_metadata["key_size"] == 256


@pytest.mark.asyncio
async def test_pkcs11_sync_hsm_connection_failed(mock_db):
    connector = PKCS11Connector("lib.so", {"vault_path": "sec"})
    mock_pkcs11.lib.side_effect = Exception("HSM Driver initialization failed")
    
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"user_pin": "123"}):
        res = await connector.sync(mock_db)
        assert res["status"] == "success"
        assert res["imported"] == 0
        assert "HSM connection failed: HSM Driver initialization failed" in res["errors"][0]


@pytest.mark.asyncio
async def test_pkcs11_sync_database_exception(mock_db):
    connector = PKCS11Connector("lib.so", {"vault_path": "sec"})
    
    mock_lib = MagicMock()
    mock_pkcs11.lib.return_value = mock_lib
    slot = MagicMock()
    slot.slot_id = 0
    token = MagicMock()
    token.label = "tok"
    slot.get_token.return_value = token
    mock_lib.get_slots.return_value = [slot]
    
    mock_session = MagicMock()
    class DummyContext:
        def __enter__(self):
            return mock_session
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    token.open.return_value = DummyContext()
    
    obj = MagicMock()
    obj.label = "k"
    mock_session.get_objects.return_value = [obj]
    obj.get_attribute.side_effect = lambda attr, d=None: "CLASS" if attr == "CLASS" else ("k" if attr == "LABEL" else b"\x01")

    # DB execute crashes to trigger database exception block at line 149-150
    mock_db.execute.side_effect = Exception("DB Connection timeout")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"user_pin": "123"}):
        res = await connector.sync(mock_db)
        assert res["imported"] == 0
        assert "Database error for asset k: DB Connection timeout" in res["errors"][0]


# ==================== KMIPConnector Tests ====================

@pytest.mark.asyncio
async def test_kmip_sync_missing_import():
    orig = sys.modules.get("kmip")
    sys.modules["kmip"] = None
    try:
        connector = KMIPConnector("127.0.0.1", 5696, {})
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "python-kmip is required" in str(exc.value)
    finally:
        sys.modules["kmip"] = orig


@pytest.mark.asyncio
async def test_kmip_get_credentials_variants():
    class ObjRef:
        vault_path = "sec-kmip"
        version = 2
    connector = KMIPConnector("127.0.0.1", 5696, ObjRef())
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"username": "admin"}
        creds = await connector._get_credentials()
        mock_vault.assert_called_once_with("sec-kmip", 2)
        assert creds == {"username": "admin"}

    connector_dict = KMIPConnector("127.0.0.1", 5696, {"vault_path": "sec-dict", "version": 5})
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"username": "dict-user"}
        creds = await connector_dict._get_credentials()
        mock_vault.assert_called_once_with("sec-dict", 5)
        assert creds == {"username": "dict-user"}


@pytest.mark.asyncio
async def test_kmip_sync_success(mock_db):
    connector = KMIPConnector(
        host="hsm.local",
        port=5696,
        credentials_ref={"vault_path": "sec"},
        client_cert_path="/cert.pem",
        client_key_path="/key.pem",
        ca_cert_path="/ca.pem"
    )

    creds = {"username": "admin", "password": "pwd"}

    mock_client_instance = MagicMock()
    mock_kmip_client.KMIPClient.return_value = mock_client_instance
    
    mock_client_instance.locate.return_value = ["uuid-new", "uuid-existing", "uuid-bad"]
    
    obj_new = MagicMock()
    obj_new.name = "key-new"
    obj_new.object_type = "SYMMETRIC_KEY"
    obj_new.cryptographic_algorithm = "AES"
    obj_new.cryptographic_length = 256
    obj_new.state = "ACTIVE"
    obj_new.usage_mask = "ENCRYPT"
    obj_new.activation_date = "2026-01-01"
    obj_new.deactivation_date = "2027-01-01"

    obj_existing = MagicMock()
    obj_existing.name = "key-exist"
    obj_existing.object_type = "SYMMETRIC_KEY"
    obj_existing.cryptographic_algorithm = "AES"
    obj_existing.cryptographic_length = 128
    
    # Mock client.get side effects
    def mock_get(uuid):
        if uuid == "uuid-new":
            return obj_new
        if uuid == "uuid-existing":
            return obj_existing
        raise Exception("KMIP fetch error")
    mock_client_instance.get.side_effect = mock_get

    # DB mocks
    mock_db_result_new = MagicMock()
    mock_db_result_new.scalar_one_or_none.return_value = None

    existing_asset = Asset(
        name="kmip:hsm.local:uuid-existing",
        asset_type="kms_key",
        asset_metadata={}
    )
    mock_db_result_existing = MagicMock()
    mock_db_result_existing.scalar_one_or_none.return_value = existing_asset
    
    mock_db.execute.side_effect = [mock_db_result_new, mock_db_result_existing]

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds):
        res = await connector.sync(mock_db)
        
        assert res["status"] == "partial"
        assert res["imported"] == 1
        assert res["updated"] == 1
        assert "KMIP fetch error" in res["errors"][0]
        
        # Verify parameters passed to KMIPClient
        mock_kmip_client.KMIPClient.assert_called_once()
        kwargs = mock_kmip_client.KMIPClient.call_args[1]
        assert kwargs["hostname"] == "hsm.local"
        assert kwargs["port"] == 5696
        assert kwargs["cert"] == "/cert.pem"
        assert kwargs["username"] == "admin"

        mock_client_instance.open.assert_called_once()
        mock_client_instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_kmip_sync_connection_failed(mock_db):
    connector = KMIPConnector("127.0.0.1", 5696, {})
    
    mock_client_instance = MagicMock()
    mock_kmip_client.KMIPClient.return_value = mock_client_instance
    mock_client_instance.open.side_effect = Exception("SSL Handshake failed")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        res = await connector.sync(mock_db)
        assert res["status"] == "partial"
        assert "KMIP connection failed: SSL Handshake failed" in res["errors"][0]


@pytest.mark.asyncio
async def test_kmip_sync_database_exception(mock_db):
    connector = KMIPConnector("127.0.0.1", 5696, {})
    mock_client_instance = MagicMock()
    mock_kmip_client.KMIPClient.return_value = mock_client_instance
    mock_client_instance.locate.return_value = ["u1"]
    
    obj = MagicMock()
    obj.name = "k"
    mock_client_instance.get.return_value = obj

    # DB execute crashes to cover database error handling inside loop
    mock_db.execute.side_effect = Exception("Database error")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        res = await connector.sync(mock_db)
        assert "Database error for KMIP object u1: Database error" in res["errors"][0]


# ==================== ADCSConnector Tests ====================

@pytest.mark.asyncio
async def test_adcs_sync_missing_import():
    orig = sys.modules.get("ldap3")
    sys.modules["ldap3"] = None
    try:
        connector = ADCSConnector("dc.local", {})
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "ldap3 is required" in str(exc.value)
    finally:
        sys.modules["ldap3"] = orig


@pytest.mark.asyncio
async def test_adcs_get_credentials_variants():
    class ObjRef:
        vault_path = "sec-adcs"
        version = 3
    connector = ADCSConnector("dc.local", ObjRef())
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"username": "admin"}
        creds = await connector._get_credentials()
        mock_vault.assert_called_once_with("sec-adcs", 3)
        assert creds == {"username": "admin"}

    connector_dict = ADCSConnector("dc.local", {"vault_path": "sec-adcs-dict", "version": 7})
    with patch("app.connectors.vault_helper.get_vault_secret", new_callable=AsyncMock) as mock_vault:
        mock_vault.return_value = {"username": "adcs-user"}
        creds = await connector_dict._get_credentials()
        mock_vault.assert_called_once_with("sec-adcs-dict", 7)
        assert creds == {"username": "adcs-user"}


@pytest.mark.asyncio
async def test_adcs_sync_missing_credentials():
    connector = ADCSConnector("dc.local", {})
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "requires username/password" in str(exc.value)


@pytest.mark.asyncio
async def test_adcs_sync_success(mock_db):
    connector = ADCSConnector(
        domain_controller="dc.local",
        credentials_ref={"vault_path": "sec"},
        base_dn="CN=Configuration,DC=pqc,DC=local",
        use_ldaps=True
    )

    creds = {"username": "admin@pqc.local", "password": "pwd"}

    mock_connection_instance = MagicMock()
    mock_ldap3.Connection.return_value = mock_connection_instance
    
    # Setup entries returned from search
    entry1 = MagicMock()
    entry1.cn = "RootCA"
    entry1.dNSHostName = "ca1.pqc.local"
    entry1.cACertificateDN = "CN=RootCA,DC=pqc,DC=local"
    entry1.certificateTemplates = ["WebServer", "User"]
    entry1.flags = "10"

    entry2 = MagicMock()
    entry2.cn = "SubCA"
    entry2.dNSHostName = "ca2.pqc.local"
    entry2.cACertificateDN = "CN=SubCA,DC=pqc,DC=local"
    entry2.certificateTemplates = []
    entry2.flags = None

    mock_connection_instance.entries = [entry1, entry2]

    # DB mocks
    mock_db_result_new = MagicMock()
    mock_db_result_new.scalar_one_or_none.return_value = None

    existing_asset = Asset(
        name="adcs:SubCA",
        asset_type="certificate_authority",
        asset_metadata={}
    )
    mock_db_result_existing = MagicMock()
    mock_db_result_existing.scalar_one_or_none.return_value = existing_asset
    
    mock_db.execute.side_effect = [mock_db_result_new, mock_db_result_existing]

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds):
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 1
        
        mock_ldap3.Server.assert_called_once_with(
            "dc.local",
            port=636,
            use_ssl=True,
            get_info="ALL"
        )
        mock_ldap3.Connection.assert_called_once_with(
            mock_ldap3.Server.return_value,
            user="admin@pqc.local",
            password="pwd",
            authentication="SIMPLE",
            auto_bind=True
        )
        
        mock_connection_instance.search.assert_called_once_with(
            search_base="CN=Configuration,DC=pqc,DC=local",
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName", "cACertificateDN", "certificateTemplates", "flags"]
        )


@pytest.mark.asyncio
async def test_adcs_sync_success_default_base_dn(mock_db):
    connector = ADCSConnector(domain_controller="dc.local", credentials_ref={}, use_ldaps=False)
    creds = {"username": "admin@pqc.local", "password": "pwd"}

    mock_connection_instance = MagicMock()
    mock_ldap3.Connection.return_value = mock_connection_instance
    mock_connection_instance.entries = []

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=creds):
        await connector.sync(mock_db)
        # base_dn derived from username domain suffix
        mock_connection_instance.search.assert_called_once_with(
            search_base="CN=Configuration,pqc.local",
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName", "cACertificateDN", "certificateTemplates", "flags"]
        )


@pytest.mark.asyncio
async def test_adcs_sync_connection_failed(mock_db):
    connector = ADCSConnector("dc.local", {})
    mock_ldap3.Connection.side_effect = Exception("LDAP Bind failed")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"username": "u@pqc.local", "password": "p"}):
        res = await connector.sync(mock_db)
        assert "ADCS connection failed: LDAP Bind failed" in res["errors"][0]


@pytest.mark.asyncio
async def test_adcs_sync_database_exception(mock_db):
    connector = ADCSConnector("dc.local", {})
    mock_connection_instance = MagicMock()
    mock_ldap3.Connection.return_value = mock_connection_instance
    entry = MagicMock()
    entry.cn = "CA"
    mock_connection_instance.entries = [entry]

    # DB execute crashes to trigger database exception block at line 443-444
    mock_db.execute.side_effect = Exception("Database write error")

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"username": "admin@pqc.local", "password": "p"}):
        res = await connector.sync(mock_db)
        assert "Database error for CA entry CA: Database write error" in res["errors"][0]
