import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from app.connectors.sast_connector import SASTConnector
from app.models.models import Asset


@pytest.mark.asyncio
async def test_sast_connector_get_credentials():
    # Test without credentials_ref
    conn = SASTConnector(target_path="/fake/path")
    creds = await conn._get_credentials()
    assert creds == {}

    # Test with dict credentials_ref
    ref_dict = {"vault_path": "secret/sast", "version": 2}
    conn2 = SASTConnector(target_path="/fake/path", credentials_ref=ref_dict)
    with patch(
        "app.connectors.sast_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"token": "123"}
        creds = await conn2._get_credentials()
        mock_vault.assert_called_once_with("secret/sast", 2)
        assert creds == {"token": "123"}

    # Test with object credentials_ref
    class FakeRef:
        vault_path = "secret/obj"
        version = 1

    conn3 = SASTConnector(target_path="/fake/path", credentials_ref=FakeRef())
    with patch(
        "app.connectors.sast_connector.get_vault_secret", new_callable=AsyncMock
    ) as mock_vault:
        mock_vault.return_value = {"token": "456"}
        creds = await conn3._get_credentials()
        mock_vault.assert_called_once_with("secret/obj", 1)
        assert creds == {"token": "456"}


@pytest.mark.asyncio
async def test_scan_python_files(tmp_path):
    # Create mock python file with cryptography pattern
    d = tmp_path / "src"
    d.mkdir()
    py_file = d / "main.py"
    py_file.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\nprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        encoding="utf-8",
    )

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_python_files()

    # Verify we found the RSA keygen pattern
    assert len(findings) > 0
    assert any(
        f["category"] == "rsa_keygen"
        and ("main.py" in f["file"] or "main.py" in f["file"].replace("\\", "/"))
        for f in findings
    )

    # Test exception block
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        findings_err = await conn._scan_python_files()
        assert len(findings_err) == 0


@pytest.mark.asyncio
async def test_scan_java_files(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    java_file = d / "Main.java"
    java_file.write_text('KeyPairGenerator.getInstance("RSA");', encoding="utf-8")

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_java_files()
    assert len(findings) > 0
    assert any(
        f["category"] == "rsa_keygen" and "Main.java" in f["file"] for f in findings
    )

    # Test exception block
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        findings_err = await conn._scan_java_files()
        assert len(findings_err) == 0


@pytest.mark.asyncio
async def test_scan_go_files(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    go_file = d / "main.go"
    go_file.write_text('import "crypto/md5"', encoding="utf-8")

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_go_files()
    assert len(findings) > 0
    assert any(
        f["category"] == "weak_hash" and "main.go" in f["file"] for f in findings
    )

    # Test exception block
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        findings_err = await conn._scan_go_files()
        assert len(findings_err) == 0


@pytest.mark.asyncio
async def test_scan_manifests(tmp_path):
    # Python requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("pycrypto==2.6.1\nrequests==2.31.0\n", encoding="utf-8")

    # setup.py
    setup_file = tmp_path / "setup.py"
    setup_file.write_text("install_requires=['pycrypto', 'm2crypto']", encoding="utf-8")

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_manifests()
    assert len(findings) >= 3
    assert any(
        f["package"] == "pycrypto" and f["manifest"] == "requirements.txt"
        for f in findings
    )
    assert any(
        f["package"] == "m2crypto" and f["manifest"] == "setup.py" for f in findings
    )

    # Test exception block
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        findings_err = await conn._scan_manifests()
        assert len(findings_err) == 0


@pytest.mark.asyncio
async def test_run_semgrep():
    # Case 1: semgrep not available
    with patch("shutil.which", return_value=None):
        conn = SASTConnector(target_path="/fake/path")
        res = await conn._run_semgrep()
        assert res == []

    # Case 2: semgrep successful execution
    with patch("shutil.which", return_value="/usr/bin/semgrep"):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b'{"results": [{"check_id": "test_rule"}]}', b"")
        )
        mock_proc.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_proc
            conn = SASTConnector(target_path="/fake/path")
            res = await conn._run_semgrep()
            assert len(res) == 1
            assert res[0]["check_id"] == "test_rule"

    # Case 3: semgrep timeout
    with patch("shutil.which", return_value="/usr/bin/semgrep"):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_proc
            conn = SASTConnector(target_path="/fake/path")
            res = await conn._run_semgrep()
            assert res == []


@pytest.mark.asyncio
async def test_sast_sync_new_asset():
    conn = SASTConnector(target_path="/fake/path")

    # Mock return values for internal scan methods using async def functions
    async def mock_python():
        return [{"category": "rsa_keygen", "language": "python"}]

    async def mock_empty():
        return []

    async def mock_manifests():
        return [
            {
                "category": "vulnerable_dependency",
                "package": "pycrypto",
                "language": "python",
            }
        ]

    conn._scan_python_files = mock_python
    conn._scan_java_files = mock_empty
    conn._scan_go_files = mock_empty
    conn._scan_js_ts_files = mock_empty
    conn._scan_manifests = mock_manifests
    conn._run_semgrep = mock_empty

    session = AsyncMock()
    session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    result = await conn.sync(session)
    assert result["status"] == "success"
    assert result["imported"] == 1
    assert result["updated"] == 0
    assert len(result["errors"]) == 0

    # Verify session.add is called with the Asset object
    added_objects = [call[0][0] for call in session.add.call_args_list]
    asset = next(obj for obj in added_objects if isinstance(obj, Asset))
    assert asset.name == "sast:path"
    assert asset.asset_type == "source_code"
    assert asset.asset_metadata["total_findings"] == 2
    assert asset.asset_metadata["crypto_findings"] == 1
    assert asset.asset_metadata["dependency_findings"] == 1


@pytest.mark.asyncio
async def test_sast_sync_existing_asset():
    conn = SASTConnector(target_path="/fake/path")

    async def mock_empty():
        return []

    conn._scan_python_files = mock_empty
    conn._scan_java_files = mock_empty
    conn._scan_go_files = mock_empty
    conn._scan_js_ts_files = mock_empty
    conn._scan_manifests = mock_empty
    conn._run_semgrep = mock_empty

    session = AsyncMock()
    session.add = MagicMock()
    existing_asset = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_asset
    session.execute.return_value = mock_result

    result = await conn.sync(session)
    assert result["status"] == "success"
    assert result["imported"] == 0
    assert result["updated"] == 1
    assert len(result["errors"]) == 0

    assert existing_asset.asset_type == "source_code"
    assert existing_asset.asset_metadata["total_findings"] == 0


@pytest.mark.asyncio
async def test_sast_sync_scan_exception():
    conn = SASTConnector(target_path="/fake/path")

    async def mock_python_fail():
        raise Exception("Python scan error")

    async def mock_empty():
        return []

    conn._scan_python_files = mock_python_fail
    conn._scan_java_files = mock_empty
    conn._scan_go_files = mock_empty
    conn._scan_js_ts_files = mock_empty
    conn._scan_manifests = mock_empty
    conn._run_semgrep = mock_empty
    conn._scan_container_files = mock_empty
    conn._scan_kerberos_files = mock_empty

    session = AsyncMock()
    session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    result = await conn.sync(session)
    assert result["status"] == "success"
    assert "python: Python scan error" in result["errors"]

    # Now let's test a top-level exception in the sync method (e.g. database query crash)
    session.execute.side_effect = Exception("DB Crash")
    result_err = await conn.sync(session)
    assert result_err["status"] == "error"
    assert "DB Crash" in result_err["errors"]


@pytest.mark.asyncio
async def test_scan_container_files(tmp_path):
    # Create mock Dockerfile with weak base image and insecure package
    d = tmp_path / "docker"
    d.mkdir()
    df = d / "Dockerfile"
    df.write_text(
        "FROM ubuntu:14.04\nRUN apt-get install -y openssl-1.0\nENV TLS_PROTO=TLSv1\n",
        encoding="utf-8",
    )

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_container_files()

    assert len(findings) >= 3
    assert any(f["category"] == "weak_base_image" for f in findings)
    assert any(f["category"] == "insecure_container_package" for f in findings)
    assert any(f["category"] == "weak_protocol_reference" for f in findings)


@pytest.mark.asyncio
async def test_scan_kerberos_files(tmp_path):
    # Create mock krb5.conf with weak enctype
    d = tmp_path / "krb"
    d.mkdir()
    kf = d / "krb5.conf"
    kf.write_text(
        "[libdefaults]\n  default_tkt_enctypes = rc4-hmac\n  permitted_enctypes = des-cbc-crc\n",
        encoding="utf-8",
    )

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_kerberos_files()

    assert len(findings) >= 3
    assert any(f["category"] == "weak_kerberos_encryption" for f in findings)
    assert any(f["category"] == "weak_kerberos_encryption_policy" for f in findings)


@pytest.mark.asyncio
async def test_sast_sync_creates_findings_db():
    conn = SASTConnector(target_path="/fake/path")

    async def mock_python():
        return [
            {
                "category": "rsa_keygen",
                "language": "python",
                "file": "main.py",
                "line": 10,
                "code_snippet": "rsa.generate_private_key()",
                "pattern": "rsa",
            }
        ]

    async def mock_manifests():
        return [
            {
                "category": "vulnerable_dependency",
                "package": "pycrypto",
                "language": "python",
                "file": "requirements.txt",
                "line": 2,
                "manifest": "requirements.txt",
                "warning": "Unmaintained",
            }
        ]

    async def mock_empty():
        return []

    conn._scan_python_files = mock_python
    conn._scan_java_files = mock_empty
    conn._scan_go_files = mock_empty
    conn._scan_js_ts_files = mock_empty
    conn._scan_manifests = mock_manifests
    conn._run_semgrep = mock_empty
    conn._scan_container_files = mock_empty
    conn._scan_kerberos_files = mock_empty

    session = AsyncMock()
    session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    result = await conn.sync(session)
    assert result["status"] == "success"
    assert result["findings_created"] == 2

    # Assert session.add was called multiple times (for Asset, placeholder scan, and findings)
    assert session.add.call_count >= 3
    added_objects = [call[0][0] for call in session.add.call_args_list]
    persisted_findings = [obj for obj in added_objects if hasattr(obj, "finding_type")]
    assert persisted_findings
    assert all(f.first_detected_at is not None for f in persisted_findings)


@pytest.mark.asyncio
async def test_scan_js_ts_files(tmp_path):
    d = tmp_path / "src"
    d.mkdir()

    ts_file = d / "crypto.ts"
    ts_file.write_text(
        "import { mlkem } from 'ml-kem';\nconst keyPair = await mlkem.generateKeyPair();\n",
        encoding="utf-8",
    )

    jsx_file = d / "App.jsx"
    jsx_file.write_text(
        "import { Dilithium } from 'noble-post-quantum';\nexport const sign = (msg) => Dilithium.sign(msg);\n",
        encoding="utf-8",
    )

    plain_file = d / "plain.ts"
    plain_file.write_text(
        "const destination = ctx.destination;\nconst summary = 'summary';\n",
        encoding="utf-8",
    )

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_js_ts_files()

    assert len(findings) >= 2
    assert any(
        f["category"] == "pqc_algorithms" and f["language"] == "typescript"
        for f in findings
    )
    assert any(
        f["category"] == "pqc_libs" and f["language"] == "javascript" for f in findings
    )
    assert not any(
        f["category"] == "weak_cipher" and "plain.ts" in f["file"] for f in findings
    )

    # Test exception block
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        findings_err = await conn._scan_js_ts_files()
        assert len(findings_err) == 0


@pytest.mark.asyncio
async def test_scan_python_pqc_algorithms(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    py_file = d / "pqc.py"
    py_file.write_text(
        "from oqs import KeyEncapsulation\n"
        "kem = KeyEncapsulation('ML-KEM-768')\n"
        "sig = ML_DSA.sign(message)\n",
        encoding="utf-8",
    )

    conn = SASTConnector(target_path=str(tmp_path))
    findings = await conn._scan_python_files()

    assert any(
        f["category"] == "pqc_libs" and f["language"] == "python" for f in findings
    )
    assert any(
        f["category"] == "pqc_algorithms" and f["language"] == "python"
        for f in findings
    )
