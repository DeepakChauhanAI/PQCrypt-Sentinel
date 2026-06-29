import asyncio
import json
import os
import shutil
import pytest
import sys
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from app.services.cli_scanner_service import (
    run_cli_tool,
    run_pqcscan,
    run_ssh_audit,
    run_testssl,
    run_ike_scan,
    run_trivy,
    run_semgrep,
)


@pytest.fixture
def mock_subprocess():
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        proc = MagicMock()
        proc.communicate = AsyncMock()
        proc.wait = AsyncMock()
        proc.kill = MagicMock()
        proc.returncode = 0
        mock_exec.return_value = proc
        yield mock_exec, proc


@pytest.mark.asyncio
async def test_run_cli_tool_success(mock_subprocess):
    mock_exec, proc = mock_subprocess
    proc.communicate.return_value = (b"output-stdout", b"output-stderr")
    
    res = await run_cli_tool(["mytool", "arg1"])
    assert res["success"] is True
    assert res["stdout"] == "output-stdout"
    assert res["stderr"] == "output-stderr"
    assert res["exit_code"] == 0
    assert res["error"] is None


@pytest.mark.asyncio
async def test_run_cli_tool_exit_code_failure(mock_subprocess):
    mock_exec, proc = mock_subprocess
    proc.returncode = 1
    proc.communicate.return_value = (b"", b"some error happened")
    
    res = await run_cli_tool(["mytool"])
    assert res["success"] is False
    assert res["exit_code"] == 1
    assert res["error"] == "some error happened"


@pytest.mark.asyncio
async def test_run_cli_tool_timeout(mock_subprocess):
    mock_exec, proc = mock_subprocess
    
    # Simulate TimeoutError in wait_for
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
        res = await run_cli_tool(["mytool"], timeout=1)
        
        proc.kill.assert_called_once()
        proc.wait.assert_called_once()
        assert res["success"] is False
        assert res["error"] == "CLI tool timed out"


@pytest.mark.asyncio
async def test_run_cli_tool_timeout_process_lookup_error(mock_subprocess):
    mock_exec, proc = mock_subprocess
    proc.kill.side_effect = ProcessLookupError()
    proc.wait.side_effect = Exception("wait error")
    
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
        res = await run_cli_tool(["mytool"], timeout=1)
        assert res["success"] is False


@pytest.mark.asyncio
async def test_run_cli_tool_not_found(mock_subprocess):
    mock_exec, proc = mock_subprocess
    mock_exec.side_effect = FileNotFoundError()
    
    res = await run_cli_tool(["mytool"])
    assert res["success"] is False
    assert res["skipped"] is True
    assert "not found on PATH" in res["error"]


@pytest.mark.asyncio
async def test_run_cli_tool_generic_exception(mock_subprocess):
    mock_exec, proc = mock_subprocess
    mock_exec.side_effect = Exception("spawn crash")
    
    res = await run_cli_tool(["mytool"])
    assert res["success"] is False
    assert res["skipped"] is True
    assert res["error"] == "spawn crash"


@pytest.mark.asyncio
async def test_run_cli_tool_json_parse(mock_subprocess):
    mock_exec, proc = mock_subprocess
    proc.communicate.return_value = (b"raw stdout", b"")
    
    # Check valid JSON read
    fake_json_data = {"key": "val"}
    with patch("pathlib.Path.exists", return_value=True), \
         patch("builtins.open") as mock_open:
             
             # Mock the file read
             mock_file = MagicMock()
             mock_file.__enter__.return_value = mock_file
             mock_file.read.return_value = json.dumps(fake_json_data)
             mock_open.return_value = mock_file
             
             res = await run_cli_tool(["mytool"], json_output_path="out.json")
             assert res["raw_output"] == fake_json_data

    # Check invalid JSON read fallback
    with patch("pathlib.Path.exists", return_value=True), \
         patch("builtins.open") as mock_open:
             mock_file = MagicMock()
             mock_file.__enter__.return_value = mock_file
             mock_file.read.return_value = "not json"
             mock_open.return_value = mock_file
             
             res = await run_cli_tool(["mytool"], json_output_path="out.json")
             assert res["raw_output"] == "raw stdout"


@pytest.mark.asyncio
async def test_run_pqcscan(mock_subprocess):
    mock_exec, proc = mock_subprocess
    
    # Case 1: skipped (not on path)
    with patch("shutil.which", return_value=None):
        res = await run_pqcscan("127.0.0.1")
        assert res["skipped"] is True
        assert "not found on PATH" in res["error"]

    # Case 2: success
    with patch("shutil.which", return_value="/usr/bin/pqcscan"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             mock_run_tool.return_value = {
                 "success": True,
                 "raw_output": {
                     "tls_version": "TLSv1.3",
                     "cipher_suite": "TLS_AES_256_GCM_SHA384",
                     "key_exchange_group": "X25519",
                     "is_pqc": False
                 }
             }
             
             res = await run_pqcscan("127.0.0.1", 443)
             assert res["tool"] == "pqcscan"
             assert res["tls_version"] == "TLSv1.3"
             assert res["pqc_status"] == "vulnerable"

             # Test PQC ready status
             mock_run_tool.return_value["raw_output"]["is_pqc"] = True
             res = await run_pqcscan("127.0.0.1", 443)
             assert res["pqc_status"] == "pqc_ready"

             # Test raw output string fallback
             mock_run_tool.return_value = {"success": True, "raw_output": "some raw string"}
             res = await run_pqcscan("127.0.0.1", 443)
             assert res["raw_output"] == "some raw string"

             # Test failed status propagation
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_pqcscan("127.0.0.1", 443)
             assert res["success"] is False


@pytest.mark.asyncio
async def test_run_ssh_audit(mock_subprocess):
    # Case 1: skipped
    with patch("shutil.which", return_value=None):
        res = await run_ssh_audit("127.0.0.1")
        assert res["skipped"] is True

    # Case 2: success
    with patch("shutil.which", return_value="/usr/bin/ssh-audit"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             mock_run_tool.return_value = {
                 "success": True,
                 "raw_output": {
                     "algorithms": {
                         "kex": ["curve25519-sha256", "sntrup761x25519-sha256@openssh.com"],
                         "key": ["ssh-rsa"]
                     }
                 }
             }
             
             res = await run_ssh_audit("127.0.0.1", 22)
             assert res["pqc_kex_available"] is True
             assert res["pqc_status"] == "pqc_ready"

             # Case 2b: no PQC algorithms
             mock_run_tool.return_value["raw_output"]["algorithms"]["kex"] = ["curve25519-sha256"]
             res = await run_ssh_audit("127.0.0.1", 22)
             assert res["pqc_kex_available"] is False
             assert res["pqc_status"] == "vulnerable"

             # Test raw output string fallback
             mock_run_tool.return_value = {"success": True, "raw_output": "raw string"}
             res = await run_ssh_audit("127.0.0.1", 22)
             assert res["raw_output"] == "raw string"

             # Test failed status propagation
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_ssh_audit("127.0.0.1", 22)
             assert res["success"] is False


@pytest.mark.asyncio
async def test_run_testssl(mock_subprocess):
    # Case 1: skipped
    with patch("shutil.which", return_value=None):
        res = await run_testssl("127.0.0.1")
        assert res["skipped"] is True

    # Case 2: tool success, but file reading exception
    with patch("shutil.which", return_value="/usr/bin/testssl.sh"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             mock_run_tool.return_value = {"success": True}
             with patch("builtins.open", side_effect=FileNotFoundError):
                 res = await run_testssl("127.0.0.1")
                 assert res["success"] is False
                 assert "JSON output not found" in res["error"]

    # Case 3: tool success, files read successfully (list format and dict format)
    mock_findings_list = [
        {"id": "protocol_tls13", "severity": "INFO"},
        {"id": "cipher_ECDHE-RSA-AES256-GCM-SHA384", "severity": "HIGH"},
        {"id": "cipher_hybrid-ml-kem", "severity": "INFO", "finding_id": "hybrid_ml_kem"},
        "invalid_entry" # Cover line 199-200
    ]
    with patch("shutil.which", return_value="/usr/bin/testssl.sh"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool, \
         patch("builtins.open") as mock_open, \
         patch("os.remove") as mock_remove:
             
             mock_run_tool.return_value = {"success": True}
             mock_file = MagicMock()
             mock_file.__enter__.return_value = mock_file
             mock_file.read.return_value = json.dumps(mock_findings_list)
             mock_open.return_value = mock_file
             
             # Test List format
             res = await run_testssl("127.0.0.1")
             assert res["success"] is True
             assert len(res["protocols"]) == 1
             assert len(res["cipher_suites"]) == 2
             assert len(res["vulnerabilities"]) == 1
             assert len(res["pqc_findings"]) == 1

             # Test dict format with "results" key
             mock_file.read.return_value = json.dumps({"results": mock_findings_list})
             res = await run_testssl("127.0.0.1")
             assert res["success"] is True
             
             # Test dict format empty
             mock_file.read.return_value = json.dumps({"other": "format"})
             res = await run_testssl("127.0.0.1")
             assert res["success"] is True
             assert len(res["protocols"]) == 0

             # Test failed status propagation
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_testssl("127.0.0.1")
             assert res["success"] is False


@pytest.mark.asyncio
async def test_run_ike_scan(mock_subprocess):
    # Case 1: skipped
    with patch("shutil.which", return_value=None):
        res = await run_ike_scan("127.0.0.1")
        assert res["skipped"] is True

    # Case 2: success
    with patch("shutil.which", return_value="/usr/bin/ike-scan"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             stdout_data = (
                 "encryption algorithm: AES-CBC/256\n"
                 "hash algorithm: SHA2-256\n"
                 "group: [14] (MODP 2048)\n"
                 "group: [invalid] (MODP)\n" # Cover line 258-259
                 "group: [38] (ML-KEM-768)\n"
             )
             mock_run_tool.return_value = {
                 "success": True,
                 "stdout": stdout_data
             }
             
             res = await run_ike_scan("127.0.0.1")
             assert res["success"] is True
             assert "AES-CBC/256" in res["encryption_algorithms"]
             assert "SHA2-256" in res["integrity_algorithms"]
             assert "2048-bit MODP" in res["dh_groups"]
             assert "ML-KEM-768" in res["dh_groups"]
             assert "DH Group invalid" in res["dh_groups"]
             assert res["pqc_status"] == "pqc_ready"

             # Test failure
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_ike_scan("127.0.0.1")
             assert res["success"] is False


@pytest.mark.asyncio
async def test_run_trivy(mock_subprocess):
    # Case 1: skipped
    with patch("shutil.which", return_value=None):
        res = await run_trivy("/path")
        assert res["skipped"] is True

    # Case 2: success
    with patch("shutil.which", return_value="/usr/bin/trivy"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             trivy_list = [
                 {"VulnerabilityID": "CVE-1", "PkgName": "openssl"},
                 {"VulnerabilityID": "CVE-2", "PkgName": "nginx"},
                 "invalid" # Cover line 297-298
             ]
             mock_run_tool.return_value = {
                 "success": True,
                 "raw_output": trivy_list
             }
             
             res = await run_trivy("/path")
             assert res["success"] is True
             assert res["total_results"] == 3
             assert res["crypto_related"] == 1
             assert res["findings"][0]["PkgName"] == "openssl"

             # Test string raw output fallback
             mock_run_tool.return_value = {"success": True, "raw_output": "raw output"}
             res = await run_trivy("/path")
             assert res["raw_output"] == "raw output"

             # Test failure
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_trivy("/path")
             assert res["success"] is False


@pytest.mark.asyncio
async def test_run_semgrep(mock_subprocess):
    # Case 1: skipped
    with patch("shutil.which", return_value=None):
        res = await run_semgrep("/path")
        assert res["skipped"] is True

    # Case 2: success
    with patch("shutil.which", return_value="/usr/bin/semgrep"), \
         patch("app.services.cli_scanner_service.run_cli_tool", new_callable=AsyncMock) as mock_run_tool:
             
             semgrep_output = {
                 "results": [
                     {
                         "path": "test.py",
                         "start": {"line": 10},
                         "check_id": "rules.md5",
                         "extra": {
                             "severity": "WARNING",
                             "message": "Use of MD5 is insecure",
                             "lines": "h = hashlib.md5()"
                         }
                     },
                     {
                         "path": "test.py",
                         "start": {"line": 20},
                         "check_id": "rules.safe",
                         "extra": {
                             "severity": "INFO",
                             "message": "Safe code",
                             "lines": "print('hello')"
                         }
                     },
                     "invalid" # Cover line 334-335
                 ]
             }
             mock_run_tool.return_value = {
                 "success": True,
                 "raw_output": semgrep_output
             }
             
             res = await run_semgrep("/path", configs=["p/python"])
             assert res["success"] is True
             assert res["total_results"] == 3
             assert res["crypto_findings"] == 1
             assert res["findings"][0]["file"] == "test.py"

             # Test string raw output fallback
             mock_run_tool.return_value = {"success": True, "raw_output": "raw output"}
             res = await run_semgrep("/path")
             assert res["raw_output"] == "raw output"

             # Test failure
             mock_run_tool.return_value = {"success": False, "error": "failed"}
             res = await run_semgrep("/path")
             assert res["success"] is False
