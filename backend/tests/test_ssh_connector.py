import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
from io import StringIO
from datetime import datetime, timezone
import os

# Create mock module for paramiko to avoid import errors
mock_paramiko = MagicMock()
sys.modules["paramiko"] = mock_paramiko

from app.models.models import Asset
from app.connectors.ssh_connector import SSHConnector


@pytest.fixture(autouse=True)
def reset_paramiko_mock():
    mock_paramiko.reset_mock()


@pytest.mark.asyncio
async def test_get_ssh_credentials_dict():
    # Test resolving credential reference when it's a dict
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh", "version": 2},
        host="10.0.0.1",
    )
    with patch("app.connectors.ssh_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"username": "admin"}
        creds = await connector._get_ssh_credentials()
        mock_get.assert_called_once_with("secret/pqc/ssh", 2)
        assert creds == {"username": "admin"}


@pytest.mark.asyncio
async def test_get_ssh_credentials_obj():
    # Test resolving credential reference when it has attributes
    class FakeRef:
        def __init__(self):
            self.vault_path = "secret/pqc/ssh-obj"
            self.version = 5

    connector = SSHConnector(
        credentials_ref=FakeRef(),
        host="10.0.0.1",
    )
    with patch("app.connectors.ssh_connector.get_vault_secret", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"username": "admin-obj"}
        creds = await connector._get_ssh_credentials()
        mock_get.assert_called_once_with("secret/pqc/ssh-obj", 5)
        assert creds == {"username": "admin-obj"}


@pytest.mark.asyncio
async def test_run_ssh_command_basic():
    # Test execution without sudo
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
    )
    mock_client = MagicMock()
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"hello world\n"
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

    res = await connector._run_ssh_command(mock_client, "echo hello")
    mock_client.exec_command.assert_called_once_with("echo hello", timeout=30)
    assert res == {
        "exit_code": 0,
        "stdout": "hello world",
        "stderr": "",
    }


@pytest.mark.asyncio
async def test_run_ssh_command_sudo_with_password():
    # Test execution with sudo and password
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        sudo=True,
        sudo_password_ref={"vault_path": "secret/pqc/sudo_pwd"},
    )
    mock_client = MagicMock()
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"root"
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock) as mock_creds:
        mock_creds.return_value = {"sudo_password": "supersecretpassword"}
        res = await connector._run_ssh_command(mock_client, "whoami", sudo=True)
        
        mock_client.exec_command.assert_called_once_with("sudo -S whoami", timeout=30)
        mock_stdin.write.assert_called_once_with("supersecretpassword\n")
        mock_stdin.flush.assert_called_once()
        assert res["exit_code"] == 0


@pytest.mark.asyncio
async def test_run_ssh_command_exception():
    # Test exception handling during execution
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = Exception("SSH connection timeout")

    res = await connector._run_ssh_command(mock_client, "echo test")
    assert res == {
        "exit_code": -1,
        "stdout": "",
        "stderr": "SSH connection timeout",
    }


@pytest.mark.asyncio
async def test_enumerate_keystores():
    # Test enumeration of keystores
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()
    
    # Run _enumerate_keystores where find_cmd finds two paths
    find_result = {
        "exit_code": 0,
        "stdout": "/path/to/keystore.jks\n/path/to/cert.pem\n\n",
        "stderr": "",
    }
    
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run, \
         patch.object(connector, "_analyze_keystore", new_callable=AsyncMock) as mock_analyze:
        
        mock_run.return_value = find_result
        mock_analyze.side_effect = [
            {"path": "/path/to/keystore.jks", "format": "JKS"},
            {"path": "/path/to/cert.pem", "format": "PEM"}
        ]
        
        keystores = await connector._enumerate_keystores(mock_client)
        assert len(keystores) == 2
        assert keystores[0]["format"] == "JKS"
        assert keystores[1]["format"] == "PEM"
        assert mock_analyze.call_count == 2


@pytest.mark.asyncio
async def test_analyze_keystore_types():
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()

    # Case 1: JKS
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "Java KeyStore file"},
            {"exit_code": 0, "stdout": "JKS entry list output"}
        ]
        res = await connector._analyze_keystore(mock_client, "/path/to/my.jks")
        assert res["format"] == "JKS"
        assert res["entries_raw"] == "JKS entry list output"
        assert "keytool -list" in mock_run.call_args_list[1][0][1]

    # Case 2: PKCS12
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "PKCS#12 Certificate"},
            {"exit_code": 0, "stdout": "PKCS12 entry list output"}
        ]
        res = await connector._analyze_keystore(mock_client, "/path/to/my.p12")
        assert res["format"] == "PKCS12"
        assert res["entries_raw"] == "PKCS12 entry list output"
        assert "openssl pkcs12" in mock_run.call_args_list[1][0][1]

    # Case 3: PEM
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "PEM certificate"},
            {"exit_code": 0, "stdout": "PEM certificate text"}
        ]
        res = await connector._analyze_keystore(mock_client, "/path/to/my.pem")
        assert res["format"] == "PEM"
        assert res["entries_raw"] == "PEM certificate text"
        assert "openssl x509" in mock_run.call_args_list[1][0][1]

    # Case 4: Unknown
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": "ASCII text"}
        res = await connector._analyze_keystore(mock_client, "/path/to/unknown.txt")
        assert res["format"] == "unknown"


@pytest.mark.asyncio
async def test_get_openssl_info():
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()

    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "OpenSSL 1.1.1f  31 Mar 2020\nbuilt on: ..."},
            {"exit_code": 0, "stdout": "OPENSSLDIR: \"/usr/lib/ssl\""}
        ]
        info = await connector._get_openssl_info(mock_client)
        assert info["version"] == "1.1.1f"
        assert info["version_output"] == "OpenSSL 1.1.1f  31 Mar 2020\nbuilt on: ..."
        assert info["config_dir"] == "OPENSSLDIR: \"/usr/lib/ssl\""

    # Edge case: split length < 2 or version cmd fails
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "OpenSSL\n"},
            {"exit_code": -1, "stdout": ""}
        ]
        info = await connector._get_openssl_info(mock_client)
        assert info["version"] == "unknown"
        assert "config_dir" not in info


@pytest.mark.asyncio
async def test_get_ssh_config():
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()

    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "Port 22\nPermitRootLogin no"},  # sshd_config
            {"exit_code": 1, "stdout": ""},                          # sshd_config.d/*.conf
            {"exit_code": 0, "stdout": "Host *\nSendEnv LANG"},       # ssh_config
            {"exit_code": 1, "stdout": ""},                          # ssh_config.d/*.conf
        ]
        configs = await connector._get_ssh_config(mock_client)
        assert configs["server"]["/etc/ssh/sshd_config"] == "Port 22\nPermitRootLogin no"
        assert "/etc/ssh/sshd_config.d/*.conf" not in configs["server"]
        assert configs["client"]["/etc/ssh/ssh_config"] == "Host *\nSendEnv LANG"


@pytest.mark.asyncio
async def test_get_kerberos_config():
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()

    # Case 1: contains RC4
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "default_tgs_enctypes = rc4-hmac aes256-cts"},
            {"exit_code": 0, "stdout": "-rw-r--r-- keytab"}
        ]
        krb = await connector._get_kerberos_config(mock_client)
        assert krb["has_rc4"] is True
        assert krb["keytabs"] == "-rw-r--r-- keytab"

    # Case 2: no RC4
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": "default_tgs_enctypes = aes256-cts"},
            {"exit_code": 1, "stdout": ""}
        ]
        krb = await connector._get_kerberos_config(mock_client)
        assert krb["has_rc4"] is False
        assert "keytabs" not in krb


@pytest.mark.asyncio
async def test_get_tpm_info():
    connector = SSHConnector(credentials_ref={}, host="10.0.0.1")
    mock_client = MagicMock()

    # Case 1: command fails
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 1, "stdout": ""}
        assert await connector._get_tpm_info(mock_client) == {}

    # Case 2: properties output has manufacturer (raw + value) and firmware, and algorithms list
    props_output = (
        "TPM2_PT_MANUFACTURER:\n"
        "  raw: 0x49424d00\n"
        "  value: \"IBM\"\n"
        "TPM2_PT_FIRMWARE_VERSION_1:\n"
        "  raw: 0x000b0002\n"
        "TPM2_PT_FIRMWARE_VERSION_2:\n"
        "  raw: 0x00040005\n"
    )
    alg_output = (
        "\n" # empty line to cover line 245-246
        "rsa:\n"
        "sha256(hash):\n"
        "ecc(signing):\n"
        "  symmetric: rsa\n"
    )
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": props_output},
            {"exit_code": 0, "stdout": alg_output}
        ]
        tpm = await connector._get_tpm_info(mock_client)
        assert tpm["manufacturer"] == "IBM"
        assert tpm["firmware_version"] == "11.2.4.5"
        assert "rsa" in tpm["algorithms"]
        assert "sha256" in tpm["algorithms"]
        assert "ecc" in tpm["algorithms"]

    # Case 3: properties output manufacturer raw only (ASCII convertible)
    props_output_raw = (
        "TPM2_PT_MANUFACTURER:\n"
        "  raw: 0x54434700\n"
        "TPM2_PT_FIRMWARE_VERSION_1:\n"
        "  raw: 0x000b0002\n"
    )
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": props_output_raw},
            {"exit_code": 1, "stdout": ""}
        ]
        tpm = await connector._get_tpm_info(mock_client)
        assert tpm["manufacturer"] == "TCG\x00"
        assert tpm["firmware_version"] == "0x000b0002"

    # Case 4: properties output manufacturer raw failure / non-convertible (regex does not match)
    props_output_bad = (
        "TPM2_PT_MANUFACTURER:\n"
        "  raw: 0xZZZZZZZZ\n"
    )
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": props_output_bad}
        tpm = await connector._get_tpm_info(mock_client)
        assert tpm["manufacturer"] == "unknown"

    # Case 5: manufacturer exception parsing covers line 223 (odd length hex causes ValueError)
    props_output_odd = (
        "TPM2_PT_MANUFACTURER:\n"
        "  raw: 0x123\n"
    )
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"exit_code": 0, "stdout": props_output_odd}
        tpm = await connector._get_tpm_info(mock_client)
        assert tpm["manufacturer"] == "0x123"

    # Case 6: firmware version exception parsing covers line 234
    props_output_fw_err = (
        "TPM2_PT_MANUFACTURER:\n"
        "  raw: 0x49424d00\n"
        "  value: \"IBM\"\n"
        "TPM2_PT_FIRMWARE_VERSION_1:\n"
        "  raw: 0x000b0002\n"
        "TPM2_PT_FIRMWARE_VERSION_2:\n"
        "  raw: 0x00040005\n"
    )
    with patch.object(connector, "_run_ssh_command", new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            {"exit_code": 0, "stdout": props_output_fw_err},
            {"exit_code": 1, "stdout": ""}
        ]
        with patch("builtins.int", side_effect=ValueError("int conversion error")):
            tpm = await connector._get_tpm_info(mock_client)
            assert tpm["firmware_version"] == "0x000b0002.0x00040005"


@pytest.mark.asyncio
async def test_ssh_connector_sync_success_new_asset(mock_db):
    # Test full sync when no asset exists in the DB (inserts new Asset)
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )
    
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    
    # Mock credentials returned
    mock_creds = {"username": "admin", "password": "password123"}
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    # Mock all internal enumeration methods
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[{"path": "/a.jks"}]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={"version": "1.1.1"}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={"server": {}}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}):
             
        res = await connector.sync(mock_db)
        
        # Verify paramiko connect was called with username/password
        mock_client.connect.assert_called_once_with(
            "10.0.0.1",
            port=22,
            username="admin",
            password="password123",
            timeout=30,
            banner_timeout=30,
        )
        mock_client.close.assert_called_once()
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        assert res["updated"] == 0
        
        mock_db.add.assert_called_once()
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.name == "ssh:10.0.0.1:22"
        assert added_asset.asset_type == "server"
        assert added_asset.ip_address == "10.0.0.1"
        assert added_asset.asset_metadata["keystores_count"] == 1
        assert added_asset.asset_metadata["openssl"] == {"version": "1.1.1"}
        mock_db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_connector_sync_success_existing_asset(mock_db):
    # Test full sync when the asset already exists in the DB (updates existing Asset)
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )
    
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    
    mock_creds = {"username": "admin", "password": "password123"}
    
    existing_asset = Asset(
        name="ssh:10.0.0.1:22",
        asset_type="server",
        asset_metadata={}
    )
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = existing_asset
    mock_db.execute.return_value = mock_db_result

    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={"version": "3.0.0"}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 0
        assert res["updated"] == 1
        
        assert existing_asset.asset_metadata["openssl"] == {"version": "3.0.0"}
        assert existing_asset.last_verified_at is not None
        mock_db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_connector_sync_private_key_auth(mock_db):
    # Test sync using private key authentication
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )
    
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    
    # Mock private key credentials
    mock_creds = {
        "username": "keyuser",
        "private_key": "---BEGIN RSA PRIVATE KEY---\n...",
        "key_passphrase": "keypassphrase123"
    }
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}), \
         patch("paramiko.RSAKey.from_private_key") as mock_pkey:
             
        mock_rsa_key = MagicMock()
        mock_pkey.return_value = mock_rsa_key
        
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        
        # Verify RSAKey was loaded
        mock_pkey.assert_called_once()
        # Verify client.connect used pkey
        mock_client.connect.assert_called_once_with(
            "10.0.0.1",
            port=22,
            username="keyuser",
            pkey=mock_rsa_key,
            timeout=30,
            banner_timeout=30,
        )


@pytest.mark.asyncio
async def test_ssh_connector_sync_auto_add_policy(mock_db):
    # Test connection when auto add host key policy is opt-in
    connector = SSHConnector(credentials_ref={"vault_path": "secret/pqc/ssh"}, host="10.0.0.1")
    
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    
    mock_creds = {"username": "admin", "password": "pwd"}
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    with patch.dict(os.environ, {"PQC_SSH_AUTO_ADD_HOST_KEY": "1"}), \
         patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_tpm_info", new_callable=AsyncMock, return_value={}):
             
        await connector.sync(mock_db)
        mock_client.set_missing_host_key_policy.assert_called_with(mock_paramiko.AutoAddPolicy())


@pytest.mark.asyncio
async def test_ssh_connector_sync_missing_creds():
    # Test sync error when credentials are incomplete
    connector = SSHConnector(credentials_ref={"vault_path": "secret/pqc/ssh"}, host="10.0.0.1")
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value={}):
        with pytest.raises(RuntimeError) as exc:
            await connector.sync(MagicMock())
        assert "SSH connector requires username" in str(exc.value)


@pytest.mark.asyncio
async def test_ssh_connector_sync_connection_failed(mock_db):
    # Test connection exception handled correctly
    connector = SSHConnector(credentials_ref={"vault_path": "secret/pqc/ssh"}, host="10.0.0.1")
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    mock_client.connect.side_effect = Exception("Authentication failed")

    mock_creds = {"username": "admin", "password": "pwd"}
    
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds):
        res = await connector.sync(mock_db)
        assert res["status"] == "error"
        assert "Authentication failed" in res["error"]
        mock_client.close.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_connector_sync_parallel_tasks_exception(mock_db):
    # Test when parallel gather tasks return exceptions
    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )
    
    mock_client = MagicMock()
    mock_paramiko.SSHClient.return_value = mock_client
    
    mock_creds = {"username": "admin", "password": "pwd"}
    
    mock_db_result = MagicMock()
    mock_db_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_db_result

    # Raise exceptions in the tasks
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value=mock_creds), \
         patch.object(connector, "_enumerate_keystores", side_effect=Exception("keystore err")), \
         patch.object(connector, "_get_openssl_info", side_effect=Exception("openssl err")), \
         patch.object(connector, "_get_ssh_config", side_effect=Exception("ssh config err")), \
         patch.object(connector, "_get_kerberos_config", side_effect=Exception("kerberos err")), \
         patch.object(connector, "_get_tpm_info", side_effect=Exception("tpm err")):
             
        res = await connector.sync(mock_db)
        
        assert res["status"] == "success"
        assert res["imported"] == 1
        
        added_asset = mock_db.add.call_args[0][0]
        assert added_asset.asset_metadata["keystores_count"] == 0
        assert added_asset.asset_metadata["keystores"] == []
        assert added_asset.asset_metadata["openssl"] == {}
        assert added_asset.asset_metadata["ssh_config"] == {}
        assert added_asset.asset_metadata["kerberos"] == {}
        assert added_asset.asset_metadata["tpm"] == {}
