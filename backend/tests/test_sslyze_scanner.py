import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from app.scanners.sslyze_scanner import (
    SSLyzeScanResult,
    _run_sslyze_sync,
    scan_endpoint_with_sslyze,
)

def test_sslyze_scan_result_init():
    res = SSLyzeScanResult(
        host="example.com",
        port=443,
        success=True,
        error_message=None,
        tls_versions={"TLS_1_3_CIPHER_SUITES": {"accepted_ciphers": []}},
        cert_data={"subject": "CN=test"},
        supported_versions=["TLS_1_3_CIPHER_SUITES"]
    )
    assert res.host == "example.com"
    assert res.port == 443
    assert res.success is True
    assert res.error_message is None
    assert res.tls_versions == {"TLS_1_3_CIPHER_SUITES": {"accepted_ciphers": []}}
    assert res.cert_data == {"subject": "CN=test"}
    assert res.supported_versions == ["TLS_1_3_CIPHER_SUITES"]

@patch("app.scanners.sslyze_scanner.parse_certificate")
def test_run_sslyze_sync_success(mock_parse_cert):
    mock_parse_cert.return_value = {"subject": "CN=mocked"}

    # Mock sslyze modules
    mock_location = MagicMock()
    mock_connectivity = MagicMock()
    mock_request = MagicMock()
    
    # Mock ScanCommand
    class MockScanCommand:
        CERTIFICATE_INFO = MagicMock()
        TLS_1_3_CIPHER_SUITES = MagicMock()
        TLS_1_2_CIPHER_SUITES = MagicMock()
        TLS_1_1_CIPHER_SUITES = MagicMock()
        TLS_1_0_CIPHER_SUITES = MagicMock()
        
    MockScanCommand.CERTIFICATE_INFO.name = "CERTIFICATE_INFO"
    MockScanCommand.TLS_1_3_CIPHER_SUITES.name = "TLS_1_3_CIPHER_SUITES"
    MockScanCommand.TLS_1_2_CIPHER_SUITES.name = "TLS_1_2_CIPHER_SUITES"
    MockScanCommand.TLS_1_1_CIPHER_SUITES.name = "TLS_1_1_CIPHER_SUITES"
    MockScanCommand.TLS_1_0_CIPHER_SUITES.name = "TLS_1_0_CIPHER_SUITES"

    with patch("sslyze.ServerNetworkLocation", return_value=mock_location), \
         patch("sslyze.server_connectivity.check_connectivity_to_server", return_value=mock_connectivity), \
         patch("sslyze.ServerNetworkConfiguration"), \
         patch("sslyze.ServerScanRequest", return_value=mock_request), \
         patch("sslyze.ScanCommand", MockScanCommand), \
         patch("sslyze.Scanner") as mock_scanner_cls:
             
             # Setup scanner results
             mock_scanner = MagicMock()
             mock_scanner_cls.return_value = mock_scanner
             
             # Setup a result entry
             mock_result = MagicMock()
             mock_scanner.get_results.return_value = [mock_result]
             
             # Setup cipher suites
             mock_cs_1_3 = MagicMock()
             mock_cs_1_3.name = "TLS_AES_256_GCM_SHA384"
             mock_cs_1_3.key_size = 256
             
             mock_cipher_result = MagicMock()
             mock_cipher_result.accepted_cipher_suites = [mock_cs_1_3]
             mock_cipher_result.rejected_cipher_suites = []
             
             # Setup cert info results
             mock_cert_info = MagicMock()
             mock_leaf = MagicMock()
             mock_cert_info.certificate_deployments = [mock_leaf]
             
             mock_cert_obj = MagicMock()
             mock_cert_obj.public_bytes_pem.return_value = b"PEM_DATA"
             mock_chain_item = MagicMock()
             mock_chain_item.certificate = mock_cert_obj
             mock_leaf.received_certificate_chain = [mock_chain_item]

             mock_result.scan_commands_results = {
                 MockScanCommand.TLS_1_3_CIPHER_SUITES: mock_cipher_result,
                 MockScanCommand.CERTIFICATE_INFO: mock_cert_info,
             }
             
             res = _run_sslyze_sync("example.com", 443)
             
             assert res["success"] is True
             assert "TLS_1_3_CIPHER_SUITES" in res["tls_versions"]
             assert res["tls_versions"]["TLS_1_3_CIPHER_SUITES"]["accepted_ciphers"][0]["name"] == "TLS_AES_256_GCM_SHA384"
             assert res["cert_data"] == {"subject": "CN=mocked"}
             assert res["supported_versions"] == ["TLS_1_3_CIPHER_SUITES"]

def test_run_sslyze_sync_connectivity_failure():
    mock_location = MagicMock()
    with patch("sslyze.ServerNetworkLocation", return_value=mock_location), \
         patch("sslyze.ServerNetworkConfiguration"), \
         patch("sslyze.server_connectivity.check_connectivity_to_server", side_effect=Exception("Connection timed out")):
             res = _run_sslyze_sync("example.com", 443)
             assert res["success"] is False
             assert "Connection timed out" in res["error"]

@patch("app.scanners.sslyze_scanner.parse_certificate", side_effect=Exception("Parse error"))
def test_run_sslyze_sync_cert_parse_failure(mock_parse_cert):
    mock_location = MagicMock()
    mock_connectivity = MagicMock()
    mock_request = MagicMock()
    
    # Mock ScanCommand
    class MockScanCommand:
        CERTIFICATE_INFO = MagicMock()
        TLS_1_3_CIPHER_SUITES = MagicMock()
        TLS_1_2_CIPHER_SUITES = MagicMock()
        TLS_1_1_CIPHER_SUITES = MagicMock()
        TLS_1_0_CIPHER_SUITES = MagicMock()
        
    MockScanCommand.CERTIFICATE_INFO.name = "CERTIFICATE_INFO"
    MockScanCommand.TLS_1_3_CIPHER_SUITES.name = "TLS_1_3_CIPHER_SUITES"
    MockScanCommand.TLS_1_2_CIPHER_SUITES.name = "TLS_1_2_CIPHER_SUITES"
    MockScanCommand.TLS_1_1_CIPHER_SUITES.name = "TLS_1_1_CIPHER_SUITES"
    MockScanCommand.TLS_1_0_CIPHER_SUITES.name = "TLS_1_0_CIPHER_SUITES"

    with patch("sslyze.ServerNetworkLocation", return_value=mock_location), \
         patch("sslyze.server_connectivity.check_connectivity_to_server", return_value=mock_connectivity), \
         patch("sslyze.ServerNetworkConfiguration"), \
         patch("sslyze.ServerScanRequest", return_value=mock_request), \
         patch("sslyze.ScanCommand", MockScanCommand), \
         patch("sslyze.Scanner") as mock_scanner_cls:
             
             mock_scanner = MagicMock()
             mock_scanner_cls.return_value = mock_scanner
             
             mock_result = MagicMock()
             mock_scanner.get_results.return_value = [mock_result]
             
             mock_cert_info = MagicMock()
             mock_leaf = MagicMock()
             mock_cert_info.certificate_deployments = [mock_leaf]
             
             mock_cert_obj = MagicMock()
             mock_cert_obj.public_bytes_pem.return_value = b"PEM_DATA"
             mock_chain_item = MagicMock()
             mock_chain_item.certificate = mock_cert_obj
             mock_leaf.received_certificate_chain = [mock_chain_item]

             mock_result.scan_commands_results = {
                 MockScanCommand.CERTIFICATE_INFO: mock_cert_info,
             }
             
             res = _run_sslyze_sync("example.com", 443)
             assert res["success"] is True
             assert res["cert_data"] is None

@pytest.mark.asyncio
async def test_scan_endpoint_with_sslyze_success():
    mock_result = {
        "success": True,
        "tls_versions": {"TLS_1_3_CIPHER_SUITES": {"accepted_ciphers": []}},
        "cert_data": {"subject": "CN=test"},
        "supported_versions": ["TLS_1_3_CIPHER_SUITES"],
    }
    with patch("app.scanners.sslyze_scanner._run_sslyze_sync", return_value=mock_result):
        res = await scan_endpoint_with_sslyze("example.com", 443)
        assert res.success is True
        assert res.tls_versions == {"TLS_1_3_CIPHER_SUITES": {"accepted_ciphers": []}}
        assert res.cert_data == {"subject": "CN=test"}
        assert res.supported_versions == ["TLS_1_3_CIPHER_SUITES"]

@pytest.mark.asyncio
async def test_scan_endpoint_with_sslyze_failure():
    mock_result = {
        "success": False,
        "error": "Scan failed",
    }
    with patch("app.scanners.sslyze_scanner._run_sslyze_sync", return_value=mock_result):
        res = await scan_endpoint_with_sslyze("example.com", 443)
        assert res.success is False
        assert res.error_message == "Scan failed"

@pytest.mark.asyncio
async def test_scan_endpoint_with_sslyze_exception():
    with patch("app.scanners.sslyze_scanner._run_sslyze_sync", side_effect=Exception("Unexpected executor error")):
        res = await scan_endpoint_with_sslyze("example.com", 443)
        assert res.success is False
        assert res.error_message == "Unexpected executor error"
