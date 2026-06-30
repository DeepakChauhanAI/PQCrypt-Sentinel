import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

# Mock cx_Oracle in sys.modules
mock_cx_oracle = MagicMock()
sys.modules["cx_Oracle"] = mock_cx_oracle

# Mock pyodbc in sys.modules
mock_pyodbc = MagicMock()
sys.modules["pyodbc"] = mock_pyodbc

from app.models.models import Asset
from app.connectors.tde_connector import OracleTDEConnector, SQLServerTDEConnector


@pytest.fixture(autouse=True)
def reset_tde_mocks():
    mock_cx_oracle.reset_mock()
    mock_cx_oracle.connect.side_effect = None
    mock_cx_oracle.connect.return_value = MagicMock()
    mock_pyodbc.reset_mock()
    mock_pyodbc.connect.side_effect = None
    mock_pyodbc.connect.return_value = MagicMock()


# ==================== OracleTDEConnector Tests ====================


@pytest.mark.asyncio
async def test_oracle_get_credentials_variants():
    connector = OracleTDEConnector(
        credentials_ref={"vault_path": "sec", "version": 1}, host="10.0.0.3"
    )
    with patch(
        "app.connectors.tde_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"username": "admin"}
        creds = await connector._get_credentials()
        assert creds == {"username": "admin"}

    class ObjRef:
        vault_path = "sec-obj"
        version = None

    connector2 = OracleTDEConnector(credentials_ref=ObjRef(), host="10.0.0.3")
    with patch(
        "app.connectors.tde_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"username": "admin-obj"}
        creds = await connector2._get_credentials()
        assert creds == {"username": "admin-obj"}


@pytest.mark.asyncio
async def test_oracle_sync_missing_import():
    orig = sys.modules.get("cx_Oracle")
    sys.modules["cx_Oracle"] = None
    try:
        connector = OracleTDEConnector(credentials_ref={}, host="10.0.0.3")
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "cx_Oracle is required" in str(exc.value)
    finally:
        sys.modules["cx_Oracle"] = orig


@pytest.mark.asyncio
async def test_oracle_sync_missing_credentials():
    connector = OracleTDEConnector(credentials_ref={}, host="10.0.0.3")
    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value={}
    ):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "requires username/password" in str(exc.value)


@pytest.mark.asyncio
async def test_oracle_sync_success_use_wallet(mock_db):
    connector = OracleTDEConnector(
        credentials_ref={"vault_path": "sec"},
        host="oracle-host",
        port=1521,
        service_name="ORCL",
        use_wallet=True,
    )

    creds = {"username": "sys", "password": "pwd", "wallet_location": "/wallet"}

    mock_cx_oracle.makedsn.return_value = "fake-dsn-string"

    mock_conn = MagicMock()
    mock_cx_oracle.connect.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # Fetch results for the 4 queries
    # 1. Wallet info
    wallet_row = ("FILE", "/wallet", "OPEN", "AUTOLOGIN")

    # 2. Encrypted tablespaces (one encrypted, one unencrypted)
    ts_rows = [("USERS", "ENCRYPTED", "AES256"), ("SYSTEM", "UNENCRYPTED", None)]

    # 3. Master keys
    key_rows = [("key-1", "1", "tag-1", "2026-01-01", "2026-01-02")]

    # 4. Column encryption
    col_rows = [("SCOTT", "EMP", "SAL", "AES192", "YES", "SHA-1")]

    mock_cursor.fetchone.return_value = wallet_row
    mock_cursor.fetchall.side_effect = [ts_rows, key_rows, col_rows]

    # DB result mocks
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value=creds
    ):
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 0

        # Verify cx_Oracle connect args
        mock_cx_oracle.connect.assert_called_once_with(
            user="sys",
            password="pwd",
            dsn="fake-dsn-string",
            config_dir="/wallet",
            wallet_location="/wallet",
        )

        mock_db.add.assert_called_once()
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.name == "oracle-tde:oracle-host:1521/ORCL"
        assert added_asset.asset_type == "database"

        metadata = added_asset.asset_metadata
        assert metadata["tde_enabled"] is True
        assert metadata["wallet"]["status"] == "OPEN"
        assert metadata["encrypted_tablespaces"][0]["tablespace_name"] == "USERS"
        assert metadata["encrypted_tablespaces"][0]["encrypted"] is True
        assert metadata["encrypted_tablespaces"][1]["encrypted"] is False
        assert metadata["master_keys"][0]["key_id"] == "key-1"
        assert metadata["encrypted_columns"][0]["column_name"] == "SAL"


@pytest.mark.asyncio
async def test_oracle_sync_success_no_wallet_existing_asset(mock_db):
    connector = OracleTDEConnector(
        credentials_ref={"vault_path": "sec"},
        host="oracle-host",
        port=1521,
        service_name="ORCL",
        use_wallet=False,
    )

    creds = {"username": "sys", "password": "pwd"}

    mock_cx_oracle.makedsn.return_value = "fake-dsn-string"

    mock_conn = MagicMock()
    mock_cx_oracle.connect.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # fetchone returns None (wallet not configured)
    mock_cursor.fetchone.return_value = None
    mock_cursor.fetchall.side_effect = [[], [], []]

    existing_asset = Asset(
        name="oracle-tde:oracle-host:1521/ORCL",
        asset_type="database",
        asset_metadata={},
    )
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = existing_asset
    mock_db.execute.return_value = mock_db_result

    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value=creds
    ):
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 1

        mock_cx_oracle.connect.assert_called_once_with(
            user="sys", password="pwd", dsn="fake-dsn-string"
        )

        assert existing_asset.asset_metadata["wallet"] == {}
        assert existing_asset.asset_metadata["tde_enabled"] is False


@pytest.mark.asyncio
async def test_oracle_sync_connection_failed(mock_db):
    connector = OracleTDEConnector(
        credentials_ref={"vault_path": "sec"}, host="oracle-host"
    )
    mock_cx_oracle.connect.side_effect = Exception("Oracle service unavailable")

    with patch.object(
        connector,
        "_get_credentials",
        new_callable=AsyncMock,
        return_value={"username": "sys", "password": "pwd"},
    ):
        res = await connector.sync(mock_db)
        assert res["status"] == "error"
        assert "Oracle TDE scan failed: Oracle service unavailable" in res["errors"][0]


# ==================== SQLServerTDEConnector Tests ====================


@pytest.mark.asyncio
async def test_sqlserver_get_credentials_variants():
    connector = SQLServerTDEConnector(
        credentials_ref={"vault_path": "sec", "version": 1}, host="10.0.0.4"
    )
    with patch(
        "app.connectors.tde_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"username": "sa"}
        creds = await connector._get_credentials()
        assert creds == {"username": "sa"}

    class ObjRef:
        vault_path = "sec-obj"
        version = None

    connector2 = SQLServerTDEConnector(credentials_ref=ObjRef(), host="10.0.0.4")
    with patch(
        "app.connectors.tde_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"username": "sa-obj"}
        creds = await connector2._get_credentials()
        assert creds == {"username": "sa-obj"}


@pytest.mark.asyncio
async def test_sqlserver_sync_missing_import():
    orig = sys.modules.get("pyodbc")
    sys.modules["pyodbc"] = None
    try:
        connector = SQLServerTDEConnector(credentials_ref={}, host="10.0.0.4")
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "pyodbc is required" in str(exc.value)
    finally:
        sys.modules["pyodbc"] = orig


@pytest.mark.asyncio
async def test_sqlserver_sync_missing_credentials():
    connector = SQLServerTDEConnector(credentials_ref={}, host="10.0.0.4")
    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value={}
    ):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "requires username/password" in str(exc.value)


@pytest.mark.asyncio
async def test_sqlserver_sync_success_new_asset(mock_db):
    connector = SQLServerTDEConnector(
        credentials_ref={"vault_path": "sec"},
        host="sql-host",
        port=1433,
        database="master",
    )

    creds = {"username": "sa", "password": "pwd"}

    mock_conn = MagicMock()
    mock_pyodbc.connect.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # 1. sys.dm_database_encryption_keys (loop over different encryption states to cover 0-6 mapping)
    db_keys_rows = [
        (
            "DB1",
            3,
            "AES_256",
            256,
            "CERTIFICATE",
            b"\xab\xcd",
            100,
        ),  # Encrypted (Code 3)
        ("DB2", 1, "AES_128", 128, "ASYMMETRIC KEY", None, 0),  # Unencrypted (Code 1)
        ("DB3", 8, "TRIPLE_DES", 192, "NONE", None, 0),  # Unknown code
    ]

    # 2. sys.certificates
    cert_rows = [
        (
            "TDECert",
            b"\x12\x34",
            "TDE Subject",
            "2030-01-01",
            "2026-01-01",
            "sa",
            "SOFTWARE_KEY",
        )
    ]

    # 3. sys.symmetric_keys
    sym_rows = [("SymKey1", "AES_256", 256, "guid-1234", "2026-01-01")]

    # 4. sys.columns Always Encrypted columns
    col_rows = [
        (
            "dbo",
            "Employees",
            "SSN",
            "DETERMINISTIC",
            "AE_AES_256_CBC",
            "CMK1",
            "AZURE_KEY_VAULT",
        )
    ]

    mock_cursor.fetchall.side_effect = [db_keys_rows, cert_rows, sym_rows, col_rows]

    # DB mocks
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value=creds
    ):
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 0

        # Verify pyodbc connect string parameters
        mock_pyodbc.connect.assert_called_once_with(
            "DRIVER={ODBC Driver 17 for SQL Server};SERVER=sql-host,1433;DATABASE=master;UID=sa;PWD=pwd;Encrypt=yes;TrustServerCertificate=yes;",
            timeout=30,
        )

        mock_db.add.assert_called_once()
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.name == "sqlserver-tde:sql-host:1433"
        assert added_asset.asset_type == "database"

        metadata = added_asset.asset_metadata
        assert metadata["tde_enabled"] is True  # True because DB1 code is 3 (Encrypted)
        assert metadata["tde_databases"][0]["encryption_state"] == "Encrypted"
        assert metadata["tde_databases"][1]["encryption_state"] == "Unencrypted"
        assert metadata["tde_databases"][2]["encryption_state"] == "Unknown (8)"
        assert metadata["tde_databases"][0]["encryptor_thumbprint"] == "abcd"
        assert metadata["certificates"][0]["thumbprint"] == "1234"
        assert metadata["symmetric_keys"][0]["name"] == "SymKey1"
        assert metadata["encrypted_columns"][0]["column"] == "SSN"


@pytest.mark.asyncio
async def test_sqlserver_sync_success_existing_asset(mock_db):
    connector = SQLServerTDEConnector(credentials_ref={}, host="sql-host")
    creds = {"username": "sa", "password": "pwd"}

    mock_conn = MagicMock()
    mock_pyodbc.connect.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # DB keys status returns code 1 (Unencrypted) for all databases
    db_keys_rows = [("DB1", 1, "AES_256", 256, "CERTIFICATE", None, 0)]
    mock_cursor.fetchall.side_effect = [db_keys_rows, [], [], []]

    existing_asset = Asset(
        name="sqlserver-tde:sql-host:1433", asset_type="database", asset_metadata={}
    )
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = existing_asset
    mock_db.execute.return_value = mock_db_result

    with patch.object(
        connector, "_get_credentials", new_callable=AsyncMock, return_value=creds
    ):
        res = await connector.sync(mock_db)

        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 1

        assert existing_asset.asset_metadata["tde_enabled"] is False


@pytest.mark.asyncio
async def test_sqlserver_sync_connection_failed(mock_db):
    connector = SQLServerTDEConnector(credentials_ref={}, host="sql-host")
    mock_pyodbc.connect.side_effect = Exception("ODBC connection failed")

    with patch.object(
        connector,
        "_get_credentials",
        new_callable=AsyncMock,
        return_value={"username": "sa", "password": "pwd"},
    ):
        res = await connector.sync(mock_db)
        assert res["status"] == "error"
        assert "SQL Server TDE scan failed: ODBC connection failed" in res["errors"][0]
