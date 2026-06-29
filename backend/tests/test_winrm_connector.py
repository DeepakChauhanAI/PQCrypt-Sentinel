import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import json

# Setup mock modules for winrm
mock_winrm = MagicMock()
mock_winrm_protocol = MagicMock()
mock_winrm.protocol = mock_winrm_protocol
sys.modules["winrm"] = mock_winrm
sys.modules["winrm.protocol"] = mock_winrm_protocol

from app.models.models import Asset
from app.connectors.winrm_connector import WinRMConnector


@pytest.fixture(autouse=True)
def reset_winrm_mocks():
    mock_winrm.reset_mock()
    mock_winrm_protocol.reset_mock()


@pytest.mark.asyncio
async def test_winrm_get_credentials_dict():
    connector = WinRMConnector(
        credentials_ref={"vault_path": "secret/pqc/winrm", "version": 3},
        host="10.0.0.2"
    )
    with patch("app.connectors.winrm_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"username": "admin", "password": "pwd"}
        creds = await connector._get_credentials()
        mock_get.assert_called_once_with("secret/pqc/winrm", 3)
        assert creds == {"username": "admin", "password": "pwd"}


@pytest.mark.asyncio
async def test_winrm_get_credentials_obj():
    class FakeRef:
        def __init__(self):
            self.vault_path = "secret/pqc/winrm-obj"
            self.version = 1

    connector = WinRMConnector(credentials_ref=FakeRef(), host="10.0.0.2")
    with patch("app.connectors.winrm_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"username": "admin-obj"}
        creds = await connector._get_credentials()
        mock_get.assert_called_once_with("secret/pqc/winrm-obj", 1)
        assert creds == {"username": "admin-obj"}


@pytest.mark.asyncio
async def test_winrm_run_ps_command_missing_library():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    # Hide pywinrm module
    orig = sys.modules.get("winrm.protocol")
    sys.modules["winrm.protocol"] = None
    try:
        with pytest.raises(RuntimeError) as exc:
            await connector._run_ps_command({"username": "u", "password": "p"}, "Get-Process")
        assert "pywinrm is required" in str(exc.value)
    finally:
        sys.modules["winrm.protocol"] = orig


@pytest.mark.asyncio
async def test_winrm_run_ps_command_success():
    connector = WinRMConnector(
        credentials_ref={},
        host="10.0.0.2",
        port=5986,
        transport="ntlm",
        use_https=True,
        verify_ssl=False
    )
    
    # Mock Protocol instance and methods
    mock_protocol_instance = MagicMock()
    mock_winrm_protocol.Protocol.return_value = mock_protocol_instance
    
    mock_protocol_instance.open_shell.return_value = "shell-123"
    mock_protocol_instance.run_command.return_value = "cmd-123"
    mock_protocol_instance.get_command_output.return_value = (b"output-stdout\n", b"output-stderr\n", 0)
    
    res = await connector._run_ps_command(
        {"username": "user1", "password": "pwd1"},
        "Get-Service"
    )
    
    mock_winrm_protocol.Protocol.assert_called_once_with(
        endpoint="https://10.0.0.2:5986/wsman",
        transport="ntlm",
        username="user1",
        password="pwd1",
        server_cert_validation="ignore"
    )
    
    mock_protocol_instance.open_shell.assert_called_once()
    mock_protocol_instance.run_command.assert_called_once_with(
        "shell-123",
        "powershell -NoProfile -NonInteractive -Command Get-Service"
    )
    mock_protocol_instance.get_command_output.assert_called_once_with("shell-123", "cmd-123")
    mock_protocol_instance.cleanup_command.assert_called_once_with("shell-123", "cmd-123")
    mock_protocol_instance.close_shell.assert_called_once_with("shell-123")

    assert res == {
        "exit_code": 0,
        "stdout": "output-stdout",
        "stderr": "output-stderr",
    }


@pytest.mark.asyncio
async def test_winrm_run_ps_command_exception():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    
    mock_protocol_instance = MagicMock()
    mock_winrm_protocol.Protocol.return_value = mock_protocol_instance
    mock_protocol_instance.open_shell.side_effect = Exception("WinRM network reset")
    
    res = await connector._run_ps_command({"username": "u", "password": "p"}, "Get-Service")
    assert res == {
        "exit_code": -1,
        "stdout": "",
        "stderr": "WinRM network reset",
    }


@pytest.mark.asyncio
async def test_winrm_get_cert_store_variants():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: JSON List
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {
            "exit_code": 0,
            "stdout": '[{"Thumbprint": "T1", "Subject": "S1"}, {"Thumbprint": "T2", "Subject": "S2"}]',
            "stderr": ""
        }
        res = await connector._get_cert_store(proto, "My")
        assert len(res) == 2
        assert res[0]["Thumbprint"] == "T1"

    # Case 2: JSON Single Object (should be wrapped to list)
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {
            "exit_code": 0,
            "stdout": '{"Thumbprint": "T3", "Subject": "S3"}',
            "stderr": ""
        }
        res = await connector._get_cert_store(proto, "My")
        assert len(res) == 1
        assert res[0]["Thumbprint"] == "T3"

    # Case 3: Bad JSON stdout
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {
            "exit_code": 0,
            "stdout": 'not a json',
            "stderr": ""
        }
        res = await connector._get_cert_store(proto, "My")
        assert res == []

    # Case 4: Non-zero exit code
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {
            "exit_code": 1,
            "stdout": '[{"Thumbprint": "T1"}]',
            "stderr": "error"
        }
        res = await connector._get_cert_store(proto, "My")
        assert res == []


@pytest.mark.asyncio
async def test_winrm_get_all_cert_stores():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    with patch.object(connector, "_get_cert_store", new_callable=AsyncMock) as mock_get:
        # Mock My and Root stores returning certificates, other stores empty
        mock_get.side_effect = lambda p, store: [{"Thumbprint": f"T_{store}"}] if store in ["My", "Root"] else []
        
        stores = await connector._get_all_cert_stores(proto)
        assert len(stores) == 2
        assert stores["My"] == [{"Thumbprint": "T_My"}]
        assert stores["Root"] == [{"Thumbprint": "T_Root"}]


@pytest.mark.asyncio
async def test_winrm_get_cng_keys():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: List returned
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '[{"Name": "K1"}, {"Name": "K2"}]'}
        res = await connector._get_cng_keys(proto)
        assert len(res) == 2
        assert res[0]["Name"] == "K1"

    # Case 2: Single object returned
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"Name": "K3"}'}
        res = await connector._get_cng_keys(proto)
        assert len(res) == 1
        assert res[0]["Name"] == "K3"

    # Case 3: Parse exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_cng_keys(proto)
        assert res == []

    # Case 4: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 1, "stdout": '[]'}
        res = await connector._get_cng_keys(proto)
        assert res == []


@pytest.mark.asyncio
async def test_winrm_get_schannel_settings():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: success
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"TLS 1.2": {"Enabled": 1}}'}
        res = await connector._get_schannel_settings(proto)
        assert res == {"TLS 1.2": {"Enabled": 1}}

    # Case 2: parsing exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_schannel_settings(proto)
        assert res == {}

    # Case 3: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": -1, "stdout": '{}'}
        res = await connector._get_schannel_settings(proto)
        assert res == {}


@pytest.mark.asyncio
async def test_winrm_get_iis_bindings():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: list
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '[{"SiteName": "S1"}]'}
        res = await connector._get_iis_bindings(proto)
        assert len(res) == 1
        assert res[0]["SiteName"] == "S1"

    # Case 2: exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_iis_bindings(proto)
        assert res == []

    # Case 3: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 127, "stdout": '[]'}
        res = await connector._get_iis_bindings(proto)
        assert res == []

    # Case 4: Single object
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"SiteName": "S2"}'}
        res = await connector._get_iis_bindings(proto)
        assert len(res) == 1
        assert res[0]["SiteName"] == "S2"


@pytest.mark.asyncio
async def test_winrm_get_bitlocker_status():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: list
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '[{"MountPoint": "C:"}]'}
        res = await connector._get_bitlocker_status(proto)
        assert res["volumes"] == [{"MountPoint": "C:"}]

    # Case 2: single object
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"MountPoint": "D:"}'}
        res = await connector._get_bitlocker_status(proto)
        assert res["volumes"] == [{"MountPoint": "D:"}]

    # Case 3: exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_bitlocker_status(proto)
        assert res["volumes"] == []

    # Case 4: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": -1, "stdout": ''}
        res = await connector._get_bitlocker_status(proto)
        assert res["volumes"] == []


@pytest.mark.asyncio
async def test_winrm_get_firmware_info():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: success
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"SecureBoot": true}'}
        res = await connector._get_firmware_info(proto)
        assert res == {"SecureBoot": True}

    # Case 2: exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_firmware_info(proto)
        assert res == {}

    # Case 3: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 1, "stdout": ''}
        res = await connector._get_firmware_info(proto)
        assert res == {}


@pytest.mark.asyncio
async def test_winrm_get_tpm_info():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    proto = {"username": "u", "password": "p"}

    # Case 1: success
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": '{"TpmPresent": true}'}
        res = await connector._get_tpm_info(proto)
        assert res == {"TpmPresent": True}

    # Case 2: exception
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": 'bad json'}
        res = await connector._get_tpm_info(proto)
        assert res == {}

    # Case 3: Exit code non-zero
    with patch.object(connector, "_run_ps_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 1, "stdout": ''}
        res = await connector._get_tpm_info(proto)
        assert res == {}


@pytest.mark.asyncio
async def test_winrm_connector_sync_new_asset(mock_db):
    connector = WinRMConnector(
        credentials_ref={"vault_path": "secret/pqc/winrm"},
        host="10.0.0.2",
        port=5985
    )
    
    mock_creds = {"username": "admin", "password": "pwd"}
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_get_all_cert_stores", new_callable=AsyncMock, return_value={"My": [{"Thumbprint": "T1"}]}), \
         patch.object(connector, "_get_cng_keys", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_schannel_settings", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_iis_bindings", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_bitlocker_status", new_callable=AsyncMock, return_value={"volumes": []}), \
         patch.object(connector, "_get_firmware_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 0
        
        mock_db.add.assert_called_once()
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.name == "winrm:10.0.0.2:5985"
        assert added_asset.asset_type == "endpoint"
        assert added_asset.asset_metadata["cert_stores"]["My"] == [{"Thumbprint": "T1"}]
        mock_db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_winrm_connector_sync_existing_asset(mock_db):
    connector = WinRMConnector(
        credentials_ref={"vault_path": "secret/pqc/winrm"},
        host="10.0.0.2",
        port=5985
    )
    
    mock_creds = {"username": "admin", "password": "pwd"}
    
    existing_asset = Asset(
        name="winrm:10.0.0.2:5985",
        asset_type="endpoint",
        asset_metadata={}
    )
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = existing_asset
    mock_db.execute.return_value = mock_db_result

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_get_all_cert_stores", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_cng_keys", new_callable=AsyncMock, return_value=[{"Name": "CNGKey1"}]), \
         patch.object(connector, "_get_schannel_settings", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_iis_bindings", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_bitlocker_status", new_callable=AsyncMock, return_value={"volumes": []}), \
         patch.object(connector, "_get_firmware_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 1
        
        assert existing_asset.asset_metadata["cng_keys"] == [{"Name": "CNGKey1"}]
        mock_db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_winrm_connector_sync_missing_creds():
    connector = WinRMConnector(credentials_ref={}, host="10.0.0.2")
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={}):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "requires username and password" in str(exc.value)


@pytest.mark.asyncio
async def test_winrm_connector_sync_parallel_exceptions(mock_db):
    connector = WinRMConnector(
        credentials_ref={"vault_path": "secret/pqc/winrm"},
        host="10.0.0.2",
        port=5985
    )
    
    mock_creds = {"username": "admin", "password": "pwd"}
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    # Raise exceptions in all methods to test fallbacks
    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_get_all_cert_stores", side_effect=Exception("cert error")), \
         patch.object(connector, "_get_cng_keys", side_effect=Exception("cng error")), \
         patch.object(connector, "_get_schannel_settings", side_effect=Exception("schannel error")), \
         patch.object(connector, "_get_iis_bindings", side_effect=Exception("iis error")), \
         patch.object(connector, "_get_bitlocker_status", side_effect=Exception("bitlocker error")), \
         patch.object(connector, "_get_firmware_info", side_effect=Exception("firmware error")), \
         patch.object(connector, "_get_tpm_info", side_effect=Exception("tpm error")):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.asset_metadata["cert_stores"] == {}
        assert added_asset.asset_metadata["cng_keys"] == []
        assert added_asset.asset_metadata["schannel"] == {}
        assert added_asset.asset_metadata["iis_bindings"] == []
        assert added_asset.asset_metadata["bitlocker"] == {}
        assert added_asset.asset_metadata["firmware"] == {}
        assert added_asset.asset_metadata["tpm"] == {}
