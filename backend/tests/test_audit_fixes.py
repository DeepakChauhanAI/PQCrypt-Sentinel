"""Tests for the audit-driven fixes in scanners and report_service."""
import json
import sys
import pytest
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _make_cert(meta=None, pqc_capable=False, sig="sha256WithRSAEncryption", pub="rsa"):
    return SimpleNamespace(
        id="abc",
        thumbprint="a" * 64,
        pub_key_size=256,
        not_before=None,
        not_after=None,
        asset_metadata=meta or {},
        pqc_capable=pqc_capable,
        sig_algorithm=sig,
        pub_key_algorithm=pub,
        is_ca=False,
        curve_name=None,
        subject="CN=example",
        issuer="CN=Test CA",
        serial_number="01",
    )


def test_ike_dh_group_31_34_classified_vulnerable():
    """brainpool and curve25519 standalone groups must be classified 'vulnerable'."""
    from app.scanners.ike_scanner import _DH_GROUP_POLICY
    for g in ("31", "32", "33", "34", "35"):
        assert _DH_GROUP_POLICY[g]["pqc_status"] == "vulnerable", f"Group {g} should be 'vulnerable'"


def test_ike_dh_group_hybrid_classified_hybrid():
    """Hybrid curve25519/curve448 groups must remain 'hybrid'."""
    from app.scanners.ike_scanner import _DH_GROUP_POLICY
    assert _DH_GROUP_POLICY["36"]["pqc_status"] == "hybrid"
    assert _DH_GROUP_POLICY["37"]["pqc_status"] == "hybrid"


def test_cbom_dependency_types_use_valid_vocabulary():
    """Generated CBOM dependencies must use CycloneDX 1.7 valid dependencyType values."""
    from app.services import report_service

    bom_json = json.dumps({
        "components": [],
        "dependencies": [
            {
                "ref": "asset-x",
                "dependsOn": [
                    "cert-1",
                    "algo-1",
                    "key-1",
                    "protocol-1",
                    "asset-y",
                ],
            }
        ],
    })

    result = json.loads(report_service.post_process_cbom(bom_json, assets_map={}))
    new_dep = result["dependencies"][0]
    for child in new_dep["dependsOn"]:
        assert child["dependencyType"] in {"unknown", "required", "optional", "provided"}, \
            f"invalid depType {child['dependencyType']}"
        if child["ref"].startswith(("cert-", "key-")):
            assert child["dependencyType"] == "provided"
        else:
            assert child["dependencyType"] == "required"


def test_cbom_protocol_component_falls_back_when_metadata_missing():
    """When asset_metadata is empty, the protocol version should be 'unknown' (not hardcoded '1.2')."""
    from app.services import report_service

    cert_obj = _make_cert(meta={})
    cert_bom = json.dumps({
        "components": [
            {"bom-ref": "cert-abc", "type": "cryptographic-asset", "name": "Cert abc"}
        ],
        "dependencies": [],
    })
    out = json.loads(
        report_service.post_process_cbom(cert_bom, assets_map={"cert-abc": cert_obj})
    )
    proto = next((c for c in out["components"] if c.get("bom-ref") == "protocol-abc"), None)
    assert proto is not None
    assert proto["cryptoProperties"]["version"] == "unknown"
    assert proto["cryptoProperties"]["cipherSuites"] == []


def test_cbom_protocol_component_uses_actual_tls_version():
    """Protocol component must surface the actual negotiated TLS version and cipher."""
    from app.services import report_service

    cert_obj = _make_cert(meta={
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "asset_type": "edge",
    })
    cert_bom = json.dumps({
        "components": [
            {"bom-ref": "cert-xyz", "type": "cryptographic-asset", "name": "Cert xyz"}
        ],
        "dependencies": [],
    })
    out = json.loads(
        report_service.post_process_cbom(cert_bom, assets_map={"cert-xyz": cert_obj})
    )
    proto = next((c for c in out["components"] if c.get("bom-ref") == "protocol-xyz"), None)
    assert proto is not None
    cp = proto["cryptoProperties"]
    assert cp["version"] == "TLSv1.3"
    assert cp["cipherSuites"] == ["TLS_AES_256_GCM_SHA384"]
    assert cp.get("variant") == "edge"


def test_cbom_crypto_properties_field_order_follows_spec():
    """cryptoProperties must list fields in CycloneDX 1.7 canonical order."""
    from app.services.report_service import _reorder_crypto_properties, _CRYPTO_PROPERTIES_ORDER

    data = {
        "components": [
            {
                "bom-ref": "cert-X",
                "type": "cryptographicAsset",
                "name": "X",
                "cryptoProperties": {
                    "pqcSafe": True,                                    # custom
                    "implementationPlatform": "x86_64/OS",              # standard
                    "certificateProperties": {"subjectName": "CN=x"},   # standard
                    "alphaCustom": "z",                                  # custom
                    "assetType": "certificate",                          # standard (must be first)
                },
            }
        ]
    }
    _reorder_crypto_properties(data)
    keys = list(data["components"][0]["cryptoProperties"].keys())
    for i, expected in enumerate(["assetType", "certificateProperties", "implementationPlatform"]):
        assert keys[i] == expected, f"expected {expected!r} at position {i}, got {keys[i]!r}"
    custom = [k for k in keys if k not in _CRYPTO_PROPERTIES_ORDER]
    assert custom == sorted(custom), f"custom fields not sorted: {custom}"


def test_cbom_crypto_properties_reorder_is_idempotent():
    """Running reorder twice must produce the same result."""
    from app.services.report_service import _reorder_crypto_properties

    data = {
        "components": [
            {
                "bom-ref": "c",
                "type": "cryptographicAsset",
                "cryptoProperties": {
                    "pqcSafe": True,
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "signature"},
                    "executionEnvironment": "software",
                    "zoo": "x",
                    "apple": "y",
                },
            }
        ]
    }
    _reorder_crypto_properties(data)
    keys_first = list(data["components"][0]["cryptoProperties"].keys())
    _reorder_crypto_properties(data)
    keys_second = list(data["components"][0]["cryptoProperties"].keys())
    assert keys_first == keys_second


def test_cbom_crypto_properties_reorder_handles_missing_component():
    """Components without cryptoProperties must be skipped silently."""
    from app.services.report_service import _reorder_crypto_properties

    data = {
        "components": [
            {"bom-ref": "no-crypto", "type": "library", "name": "lib"},
            {"bom-ref": "with-crypto", "type": "cryptographicAsset",
             "cryptoProperties": {"assetType": "algorithm", "zoo": "x"}},
        ]
    }
    _reorder_crypto_properties(data)
    assert "cryptoProperties" not in data["components"][0]


def test_ssh_scanner_pqc_constants_pqc_kex_first():
    """The PQC KEX list must come first in the preferred list to maximise PQC negotiation."""
    from app.scanners.ssh_scanner import PQC_KEX_ALGORITHMS
    first = PQC_KEX_ALGORITHMS[0]
    assert first.startswith("sntrup") or first.startswith("mlkem") or first.startswith("kyber")


def test_kmip_ssl_version_uses_module_constant():
    """The KMIP client must be built with the real ssl.PROTOCOL_TLSv1_2 constant, not the string."""
    import inspect
    from app.connectors import pkcs11_connector
    src = inspect.getsource(pkcs11_connector)
    assert 'ssl_version="PROTOCOL_TLSv1_2"' not in src, "string form still present in pkcs11_connector"
    assert "_ssl.PROTOCOL_TLSv1_2" in src or "ssl.PROTOCOL_TLSv1_2" in src


def test_ssh_result_carries_mac_algorithms():
    """SSHScanResult must include a mac_algorithms attribute (Phase 1.10)."""
    from app.scanners.ssh_scanner import SSHScanResult
    r = SSHScanResult(host="x", port=22, success=True, mac_algorithms=["hmac-sha2-512"])
    assert hasattr(r, "mac_algorithms")
    assert r.mac_algorithms == ["hmac-sha2-512"]


def test_tls_scanner_default_is_verify_tls_true():
    """_do_tls_connect must default to verify_tls=True (security).

    The default flipped from False to True to deny-by-default: a
    production scan that accidentally passes verify_tls=False will be
    MITM-vulnerable. The opt-in path is via Scan.config["strict_tls"].
    """
    import inspect
    from app.scanners import tls_scanner
    sig = inspect.signature(tls_scanner._do_tls_connect)
    assert "verify_tls" in sig.parameters
    assert sig.parameters["verify_tls"].default is True


def test_mail_scanner_accepts_verify_tls():
    """_do_mail_connect must accept verify_tls=False and not raise."""
    import inspect
    from app.scanners import mail_scanner
    sig = inspect.signature(mail_scanner._do_mail_connect)
    assert "verify_tls" in sig.parameters
    assert sig.parameters["verify_tls"].default is False


def test_rsa_deadline_buckets():
    """Per NIST IR 8547: RSA-2048 -> 2030, RSA-3072+ -> 2035, RSA-1024 -> 2026."""
    from app.analysis.algo_classifier import get_deprecation_deadline_year
    assert get_deprecation_deadline_year("RSA-3072", 3072) == 2035
    assert get_deprecation_deadline_year("RSA", 2048) == 2030
    assert get_deprecation_deadline_year("RSA", 4096) == 2035
    assert get_deprecation_deadline_year("RSA", 1024) == 2026


def test_aes_quantum_levels():
    """AES-128/192 -> 2030, AES-256 -> 2099 (safe, Grover still leaves 128-bit margin)."""
    from app.analysis.algo_classifier import get_deprecation_deadline_year
    assert get_deprecation_deadline_year("AES-128-GCM", 128) == 2030
    assert get_deprecation_deadline_year("AES-192-CBC", 192) == 2030
    assert get_deprecation_deadline_year("AES-256-GCM", 256) == 2099


def test_cert_parser_disallowed_now_override():
    """MD5-signed certs must be marked disallowed_now, not vulnerable."""
    import inspect
    from app.scanners import cert_parser
    src = inspect.getsource(cert_parser)
    assert "is_disallowed_now" in src, "cert_parser must invoke is_disallowed_now for the override"
    # Behaviour: invoking the override with MD5 must flip status to disallowed_now
    from app.services.risk_service import is_disallowed_now
    pqc_status = "vulnerable"
    sig_algo_name = "md5WithRSAEncryption"
    if is_disallowed_now(sig_algo_name):
        pqc_status = "disallowed_now"
    assert pqc_status == "disallowed_now"


def test_cert_parser_extract_key_usage_helper_exists():
    """cert_parser must expose _extract_key_usage as a reusable helper."""
    from app.scanners import cert_parser
    assert hasattr(cert_parser, "_extract_key_usage")
    assert callable(cert_parser._extract_key_usage)


def test_cert_parser_extract_key_usage_handles_missing_extension():
    """A cert without the KeyUsage extension must return an empty list."""
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from app.scanners.cert_parser import _extract_key_usage

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now)
        .sign(key, hashes.SHA256())
    )
    # Default cert builder has no KeyUsage extension.
    result = _extract_key_usage(cert)
    assert isinstance(result, list)
    assert result == []


def test_cert_parser_extract_key_usage_returns_set_flags():
    """Flags set on the extension must appear in the result."""
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from app.scanners.cert_parser import _extract_key_usage

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    result = _extract_key_usage(cert)
    assert "digitalSignature" in result
    assert "keyEncipherment" in result
    assert "keyCertSign" in result
    assert "nonRepudiation" not in result


def test_sast_connector_hoists_shutil_import():
    """shutil must be imported at module top, not inside a function."""
    import inspect
    from app.connectors import sast_connector
    src = inspect.getsource(sast_connector)
    # The audit concern was a misplaced import inside _run_semgrep.
    # Verify the top-level import exists and the inner one is gone.
    assert "import shutil" in src.splitlines()[0:15].__repr__() or any(
        line.strip() == "import shutil" for line in src.splitlines()[:15]
    )
    # The inner import should no longer exist
    assert "    import shutil" not in src, "shutil still imported inside function"


# ----------------------------------------------------------- SARIF ---------
def test_generate_sarif_for_sast_findings_basic():
    """SARIF v2.1.0 is produced with one run and the expected top-level fields."""
    from app.services.report_service import generate_sarif_for_sast_findings

    sarif = generate_sarif_for_sast_findings("scan-1")
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "PQCrypt Sentinel SAST"


def test_generate_sarif_for_sast_findings_with_semgrep_results():
    """Semgrep findings are translated into SARIF rules + results."""
    from app.services.report_service import generate_sarif_for_sast_findings

    sarif = generate_sarif_for_sast_findings(
        "scan-1",
        semgrep_results={
            "success": True,
            "findings": [
                {
                    "rule": "weak-rsa-keygen",
                    "file": "app/crypto.py",
                    "line": 42,
                    "message": "RSA 1024 detected",
                    "severity": "ERROR",
                }
            ],
        },
    )
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    assert any(r["id"] == "weak-rsa-keygen" for r in rules)
    assert any("app/crypto.py" in str(r.get("locations", "")) or r.get("ruleId") == "weak-rsa-keygen" for r in results)
    assert results[0]["ruleIndex"] == 0


def test_generate_sarif_for_sast_findings_with_trivy_results():
    """Trivy findings surface as SARIF results with `trivy-` prefixed rule id."""
    from app.services.report_service import generate_sarif_for_sast_findings

    sarif = generate_sarif_for_sast_findings(
        "scan-2",
        trivy_results={
            "success": True,
            "findings": [
                {
                    "Target": "requirements.txt",
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "pycryptodome",
                    "InstalledVersion": "3.10.1",
                    "Severity": "HIGH",
                    "Title": "pycryptodome < 3.20 has weak RSA defaults",
                }
            ],
        },
    )
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"].startswith("trivy-") for r in rules)


def test_generate_sarif_for_sast_findings_ignores_failed_semgrep():
    """A semgrep run flagged success=False is ignored entirely."""
    from app.services.report_service import generate_sarif_for_sast_findings

    sarif = generate_sarif_for_sast_findings(
        "scan-3",
        semgrep_results={"success": False, "findings": [{"rule": "x", "file": "f", "line": 1, "message": "m", "severity": "warning"}]},
    )
    assert sarif["runs"][0]["results"] == []


def test_generate_sarif_for_sast_findings_dedups_rules():
    """Reusing the same rule id must not create duplicate rules."""
    from app.services.report_service import generate_sarif_for_sast_findings

    sarif = generate_sarif_for_sast_findings(
        "scan-4",
        semgrep_results={
            "success": True,
            "findings": [
                {"rule": "r1", "file": "a", "line": 1, "message": "m", "severity": "warning"},
                {"rule": "r1", "file": "b", "line": 2, "message": "m2", "severity": "error"},
            ],
        },
    )
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "r1"


@pytest.mark.asyncio
async def test_ssh_sudo_command_injection_prevention():
    """Verify that SSH sudo password does not use shell echo string formatting,
    which is vulnerable to command injection.
    """
    from app.connectors.ssh_connector import SSHConnector
    from unittest.mock import MagicMock, AsyncMock, patch

    mock_client = MagicMock()
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"success"
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )
    connector.sudo_password_ref = "secret/pqc/ssh"

    fake_creds = {"sudo_password": "'; whoami; '"}
    
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock) as mock_creds:
        mock_creds.return_value = fake_creds
        result = await connector._run_ssh_command(mock_client, "whoami", sudo=True)

    mock_client.exec_command.assert_called_once_with("sudo -S whoami", timeout=30)
    mock_stdin.write.assert_called_once_with("'; whoami; '\n")
    mock_stdin.flush.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_connector_locals_mutation_exception_handling():
    """Verify that if one of the SSH gather tasks raises an Exception,
    the SSH connector handles it correctly (no locals() mutation bug)
    and defaults the metadata field appropriately.
    """
    from app.connectors.ssh_connector import SSHConnector
    from app.models.models import Asset
    from unittest.mock import MagicMock, AsyncMock, patch

    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )

    mock_client = MagicMock()
    
    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock) as mock_creds, \
         patch.object(connector, "_enumerate_keystores", side_effect=ValueError("keystores crash")), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={"version": "1.1.1"}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={"Port": "22"}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={"realm": "PQC.LOCAL"}), \
         patch("paramiko.SSHClient", return_value=mock_client):
        
        mock_creds.return_value = {"username": "user", "password": "pwd"}
        
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        result = await connector.sync(session)
        assert result["status"] == "success"
        
        assert session.add.call_count == 1
        asset = session.add.call_args[0][0]
        assert asset.asset_metadata["keystores"] == []
        assert asset.asset_metadata["keystores_count"] == 0
        assert asset.asset_metadata["openssl"] == {"version": "1.1.1"}


@pytest.mark.asyncio
async def test_k8s_connector_locals_mutation_exception_handling():
    """Verify that if one of the K8s gather tasks raises an Exception,
    the K8s connector handles it correctly (no locals() mutation bug)
    and defaults metadata fields appropriately.
    """
    from app.connectors.k8s_connector import KubernetesConnector
    from unittest.mock import MagicMock, AsyncMock, patch

    connector = KubernetesConnector(
        credentials_ref={"vault_path": "secret/pqc/k8s"},
    )

    with patch.object(connector, "_create_k8s_client", new_callable=AsyncMock), \
         patch.object(connector, "_get_secrets", side_effect=RuntimeError("secrets crash")), \
         patch.object(connector, "_get_certificates", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_etcd_encryption", new_callable=AsyncMock, return_value={"status": "enabled"}), \
         patch.object(connector, "_get_apiserver_cert", new_callable=AsyncMock, return_value={"valid": True}), \
         patch.object(connector, "_get_kubelet_certs", new_callable=AsyncMock, return_value=[]):
        
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        result = await connector.sync(session)
        assert result["status"] == "success"
        assert len(result["errors"]) > 0
        assert any("secrets" in err for err in result["errors"])
        
        assert session.add.call_count == 1
        asset = session.add.call_args[0][0]
        assert asset.asset_metadata["total_secrets"] == 0
        assert asset.asset_metadata["etcd_encryption"] == {"status": "enabled"}


@pytest.mark.asyncio
async def test_winrm_connector_locals_mutation_exception_handling():
    """Verify that if one of the WinRM gather tasks raises an Exception,
    the WinRM connector handles it correctly (no locals() mutation bug)
    and defaults metadata fields appropriately.
    """
    from app.connectors.winrm_connector import WinRMConnector
    from unittest.mock import MagicMock, AsyncMock, patch

    connector = WinRMConnector(
        credentials_ref={"vault_path": "secret/pqc/winrm"},
        host="10.0.0.2",
    )

    with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"username": "a", "password": "b"}), \
         patch.object(connector, "_get_all_cert_stores", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_cng_keys", side_effect=ValueError("cng crash")), \
         patch.object(connector, "_get_schannel_settings", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_iis_bindings", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_bitlocker_status", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_firmware_info", new_callable=AsyncMock, return_value={}), \
         patch("app.connectors.winrm_connector.WinRMConnector._run_ps_command", new_callable=AsyncMock):
        
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        result = await connector.sync(session)
        assert result["status"] == "success"
        
        assert session.add.call_count == 1
        asset = session.add.call_args[0][0]
        assert asset.asset_metadata["cng_keys"] == []
        assert asset.asset_metadata["cert_stores"] == {}


def test_pyshark_capture_tshark_deferred_check():
    """Verify that importing pyshark_capture does not raise RuntimeError when tshark is missing,
    but calling capture functions does.
    """
    import sys
    from unittest.mock import patch

    with patch("app.scanners.pyshark_capture._get_tshark_path", return_value=None):
        from app.scanners.pyshark_capture import capture_tls_handshakes, analyze_pcap_file
        
        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(capture_tls_handshakes("eth0"))
        assert "tshark not found" in str(excinfo.value)

        with pytest.raises(RuntimeError) as excinfo2:
            asyncio.run(analyze_pcap_file("test.pcap"))
        assert "tshark not found" in str(excinfo2.value)


@pytest.mark.asyncio
async def test_k8s_connector_kubeconfig_cleanup():
    """Verify that the temporary kubeconfig file is cleaned up after loading configuration."""
    from unittest.mock import patch, MagicMock, AsyncMock
    import sys
    import os

    mock_k8s = MagicMock()
    with patch.dict(sys.modules, {"kubernetes": mock_k8s, "kubernetes.config": mock_k8s.config}):
        from app.connectors.k8s_connector import KubernetesConnector

        connector = KubernetesConnector(
            credentials_ref={"vault_path": "secret/pqc/k8s"},
        )
        
        fake_kubeconfig_content = "apiVersion: v1\nkind: Config"
        
        with patch.object(connector, "_get_credentials", new_callable=AsyncMock, return_value={"kubeconfig": fake_kubeconfig_content}):
             
            temp_paths = []
            def side_effect(config_file, context=None):
                temp_paths.append(config_file)
                assert os.path.exists(config_file)

            mock_k8s.config.load_kube_config.side_effect = side_effect
            await connector._create_k8s_client()
            
            assert len(temp_paths) == 1
            assert not os.path.exists(temp_paths[0])


@pytest.mark.asyncio
async def test_ssh_connector_timestamp_real_time():
    """Verify that when updating an existing asset, the verified timestamp is actual time, not loop time."""
    from app.connectors.ssh_connector import SSHConnector
    from app.models.models import Asset
    from unittest.mock import MagicMock, AsyncMock, patch
    from datetime import datetime, timezone

    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )

    mock_client = MagicMock()
    existing_asset = Asset(
        name="ssh:10.0.0.1:22",
        asset_type="server",
        ip_address="10.0.0.1",
        port=22,
    )

    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value={"username": "u", "password": "p"}), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch("paramiko.SSHClient", return_value=mock_client):
        
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_asset
        session.execute.return_value = mock_result

        result = await connector.sync(session)
        assert result["status"] == "success"
        
        assert existing_asset.last_verified_at is not None
        diff = datetime.now(timezone.utc) - existing_asset.last_verified_at
        assert diff.total_seconds() < 10


def test_cbom_recursive_ecma424_ordering():
    """Verify that only cryptoProperties dictionaries are ordered according to ECMA-424, and others are untouched."""
    from app.services.report_service import _reorder_crypto_properties
    
    data = {
        "metadata": {
            "timestamp": "2026-06-06T00:00:00Z",
            "tools": [{"name": "PQCrypt"}],
        },
        "components": [
            {
                "bom-ref": "cert-1",
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "pqcSafe": False,
                    "executionEnvironment": "software",
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": "CN=test",
                        "serialNumber": "123",
                    }
                }
            }
        ]
    }
    
    _reorder_crypto_properties(data)
    
    # Top-level keys must remain in their original order
    assert list(data.keys()) == ["metadata", "components"]
    
    # Nested component keys must remain in their original order
    comp = data["components"][0]
    assert list(comp.keys()) == ["bom-ref", "type", "cryptoProperties"]
    
    # cryptoProperties MUST follow _CRYPTO_PROPERTIES_ORDER
    cp = comp["cryptoProperties"]
    assert list(cp.keys()) == ["assetType", "certificateProperties", "executionEnvironment", "pqcSafe"]
    
    # certificateProperties keys must remain in their original order
    cert_props = cp["certificateProperties"]
    assert list(cert_props.keys()) == ["subjectName", "serialNumber"]


def test_cbom_asset_type_mappings():
    """Verify that algorithm types and related-crypto-material map to correct CycloneDX v1.7 values."""
    from app.services.report_service import post_process_cbom
    from types import SimpleNamespace
    
    cert_obj = SimpleNamespace(
        id="xyz",
        thumbprint="ab" * 32,
        pub_key_size=2048,
        not_before=None,
        not_after=None,
        pqc_capable=False,
        sig_algorithm="sha256WithRSAEncryption",
        pub_key_algorithm="rsa",
        is_ca=False,
        curve_name=None,
        subject="CN=test",
        issuer="CN=test ca",
        serial_number="123",
        sig_algorithm_oid="1.2.840.113549.1.1.11",
    )
    
    algo_obj = SimpleNamespace(
        id="xyz",
        algorithm_name="ECDHE-RSA-AES256-GCM-SHA384",
        algorithm_type="key_exchange",
        pqc_status="vulnerable",
        key_size=256,
        curve="secp256r1",
        oid=None,
    )
    
    bom = json.dumps({
        "components": [
            {"bom-ref": "cert-xyz", "type": "cryptographic-asset", "name": "Cert"},
            {"bom-ref": "algo-xyz", "type": "cryptographic-asset", "name": "Algo"},
        ]
    })
    
    processed = json.loads(post_process_cbom(bom, {"cert-xyz": cert_obj, "algo-xyz": algo_obj}))
    
    key_comp = next(c for c in processed["components"] if c["bom-ref"] == "key-xyz")
    assert key_comp["cryptoProperties"]["assetType"] == "related-crypto-material"
    
    algo_comp = next(c for c in processed["components"] if c["bom-ref"] == "algo-xyz")
    assert algo_comp["cryptoProperties"]["assetType"] == "protocol"


def test_celery_task_retry_on_exception():
    """Verify that execute_scan retries on failure with the correct countdown backoff."""
    from app.tasks import execute_scan
    from unittest.mock import MagicMock, PropertyMock, patch
    from celery.exceptions import Retry

    mock_request = MagicMock()
    mock_request.retries = 1

    with patch("celery.Task.request", new_callable=PropertyMock) as mock_request_prop, \
         patch.object(execute_scan, "retry", side_effect=Retry("retrying")) as mock_retry, \
         patch("app.tasks.ScanOrchestrator") as mock_orchestrator:
        
        mock_request_prop.return_value = mock_request
        
        mock_orchestrator.return_value.run_scan.side_effect = RuntimeError("DB OperationalError")

        with pytest.raises(Retry):
            execute_scan.run("scan-1")

        mock_retry.assert_called_once()
        kwargs = mock_retry.call_args[1]
        assert "exc" in kwargs
        assert isinstance(kwargs["exc"], RuntimeError)
        assert kwargs["countdown"] == 20


def test_passive_ssh_capture():
    from app.scanners.pyshark_capture import capture_ssh_handshakes
    from unittest.mock import MagicMock, patch

    fake_packet = MagicMock()
    fake_packet.sniff_time.isoformat.return_value = "2026-06-06T12:00:00Z"
    fake_packet.ip.src = "10.0.0.1"
    fake_packet.ip.dst = "10.0.0.2"
    fake_packet.tcp.dstport = 22

    fake_ssh = MagicMock()
    fake_ssh.field_names = ["kex_algorithms", "server_host_key_algorithms", "encryption_algorithms", "mac_algorithms"]
    fake_ssh.kex_algorithms = "sntrup761x25519-sha512@openssh.com,curve25519-sha256"
    fake_ssh.server_host_key_algorithms = "ssh-ed25519"
    fake_ssh.encryption_algorithms = "aes256-gcm@openssh.com"
    fake_ssh.mac_algorithms = "hmac-sha2-512"

    fake_packet.ssh = fake_ssh

    mock_live_cap = MagicMock()
    mock_live_cap.sniff_continuously.return_value = [fake_packet]

    with patch("pyshark.LiveCapture", return_value=mock_live_cap), \
         patch("app.scanners.pyshark_capture._get_tshark_path", return_value="/usr/bin/tshark"):
        
        res = asyncio.run(capture_ssh_handshakes("eth0", 5))

    assert len(res) == 1
    assert res[0]["type"] == "SSH_KEXINIT"
    assert res[0]["has_pqc"] is True
    assert any("sntrup761x25519" in alg for alg in res[0]["kex_algorithms"])


def test_saml_metadata_connector():
    from app.connectors.saml_connector import SAMLMetadataConnector
    from app.models.models import Asset
    from unittest.mock import AsyncMock, patch
    from datetime import datetime, timezone

    # Mock XML with an X509Certificate
    xml_blob = """<?xml version="1.0"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
      <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
          <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
              <X509Certificate>
                MIIDBTCCAe2gAwIBAgIQY7nN...
              </X509Certificate>
            </X509Data>
          </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>
    """

    mock_cert_meta = {
        "thumbprint": "abcdef1234567890",
        "subject": "CN=example.com",
        "issuer": "CN=example.com",
        "sig_algorithm": "sha256WithRSAEncryption",
        "pub_key_algorithm": "RSA",
        "pub_key_size": 2048,
        "curve_name": None,
        "not_before": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "not_after": datetime(2036, 1, 1, tzinfo=timezone.utc),
        "pqc_capable": False,
        "pqc_details": {
            "pqc_status": "vulnerable",
        }
    }

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    with patch("app.connectors.saml_connector.parse_certificate", return_value=mock_cert_meta):
        connector = SAMLMetadataConnector(xml_blob=xml_blob)
        res = asyncio.run(connector.sync(mock_db))

    assert res["imported"] == 1
    assert res["status"] == "success"
    mock_db.add.assert_called_once()
    added_asset = mock_db.add.call_args[0][0]
    assert added_asset.asset_type == "saml_metadata"
    assert added_asset.asset_metadata["subject"] == "CN=example.com"
    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in added_asset.asset_metadata["bindings"]
    assert "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" in added_asset.asset_metadata["name_id_formats"]


@pytest.mark.asyncio
async def test_ssh_connector_tpm_probing():
    """Verify that SSHConnector successfully executes tpm2_getcap and parses TPM metadata."""
    from app.connectors.ssh_connector import SSHConnector
    from unittest.mock import MagicMock, AsyncMock, patch

    connector = SSHConnector(
        credentials_ref={"vault_path": "secret/pqc/ssh"},
        host="10.0.0.1",
        port=22,
    )

    mock_client = MagicMock()
    
    # Mock _run_ssh_command to return properties-fixed and algorithms output
    async def mock_run_cmd(client, cmd, sudo=False):
        if "properties-fixed" in cmd:
            return {
                "exit_code": 0,
                "stdout": (
                    "TPM2_PT_MANUFACTURER:\n"
                    "  raw: 0x49424D00\n"
                    "  value: \"IBM\"\n"
                    "TPM2_PT_FIRMWARE_VERSION_1:\n"
                    "  raw: 0x0002000c\n"
                    "TPM2_PT_FIRMWARE_VERSION_2:\n"
                    "  raw: 0x00010002\n"
                ),
                "stderr": ""
            }
        elif "algorithms" in cmd:
            return {
                "exit_code": 0,
                "stdout": (
                    "rsa:\n"
                    "  value: 0x1\n"
                    "sha256:\n"
                    "  value: 0xb\n"
                    "ecc (0x0023)\n"
                ),
                "stderr": ""
            }
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    with patch.object(connector, "_get_ssh_credentials", new_callable=AsyncMock, return_value={"username": "u", "password": "p"}), \
         patch.object(connector, "_enumerate_keystores", new_callable=AsyncMock, return_value=[]), \
         patch.object(connector, "_get_openssl_info", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_ssh_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_get_kerberos_config", new_callable=AsyncMock, return_value={}), \
         patch.object(connector, "_run_ssh_command", side_effect=mock_run_cmd), \
         patch("paramiko.SSHClient", return_value=mock_client):

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        result = await connector.sync(session)
        assert result["status"] == "success"

        assert session.add.call_count == 1
        asset = session.add.call_args[0][0]
        tpm = asset.asset_metadata["tpm"]
        assert tpm["manufacturer"] == "IBM"
        assert tpm["firmware_version"] == "2.12.1.2"
        assert "rsa" in tpm["algorithms"]
        assert "sha256" in tpm["algorithms"]
        assert "ecc" in tpm["algorithms"]


def test_execute_scheduled_scan():
    """Verify that execute_scheduled_scan dispatches execute_scan tasks."""
    from app.tasks import execute_scheduled_scan
    from app.models.models import Asset
    from unittest.mock import MagicMock, AsyncMock, patch

    mock_session = MagicMock()
    mock_assets_res = MagicMock()
    mock_assets_res.scalars.return_value.all.return_value = [
        Asset(ip_address="192.168.1.50", name="test-asset-1"),
        Asset(ip_address=None, name="test-asset-2"),
    ]
    mock_session.execute = AsyncMock(return_value=mock_assets_res)
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()

    mock_session_context = MagicMock()
    mock_session_context.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_context.__aexit__ = AsyncMock(return_value=None)

    with patch("app.db.AsyncSessionLocal", return_value=mock_session_context), \
         patch("app.tasks.execute_scan.delay") as mock_delay, \
         patch.dict("os.environ", {"PQC_PERIODIC_SCAN_TARGETS": ""}):
        
        execute_scheduled_scan()
        
        assert mock_session.add.call_count == 2
        
        added_scans = [args[0][0] for args in mock_session.add.call_args_list]
        targets = [s.target for s in added_scans]
        assert "192.168.1.50" in targets
        assert "test-asset-2" in targets
        
        assert mock_delay.call_count == 2


@pytest.mark.asyncio
async def test_saml_metadata_ssrf_blocked():
    from app.connectors.saml_connector import SAMLMetadataConnector
    from unittest.mock import AsyncMock, patch

    mock_db = AsyncMock()
    connector = SAMLMetadataConnector(metadata_url="http://127.0.0.1/metadata.xml")
    
    with patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        res = await connector.sync(mock_db)
    
    assert res["status"] == "error"
    assert any("safe IPs" in err or "loopback" in err.lower() or "ssrf" in err.lower() for err in res["errors"])


@pytest.mark.asyncio
async def test_jwt_connector_ssrf_blocked():
    from app.connectors.jwt_connector import JWTConnector
    from unittest.mock import AsyncMock, patch

    mock_db = AsyncMock()
    connector = JWTConnector(endpoint="http://127.0.0.1/tokens")
    
    with patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
        res = await connector.sync(mock_db)
    
    assert any("safe IPs" in err or "loopback" in err.lower() or "ssrf" in err.lower() for err in res["errors"])


@pytest.mark.asyncio
async def test_ocsp_probe_dynamic_issuer_fetch():
    from app.scanners.ocsp_dnssec_scanner import probe_ocsp
    from unittest.mock import AsyncMock, MagicMock, patch
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone

    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    now = datetime.now(timezone.utc)
    
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(issuer_key, hashes.SHA256())
    )
    issuer_der = issuer_cert.public_bytes(serialization.Encoding.DER)
    
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.local")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.com"),
                ),
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://issuer.local/ca.der"),
                )
            ]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)

    fake_get_resp = MagicMock(status_code=200, content=issuer_der)
    fake_post_resp = MagicMock(status_code=404)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=fake_get_resp)
    mock_client.post = AsyncMock(return_value=fake_post_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with patch("cryptography.x509.ocsp.OCSPRequestBuilder.add_certificate") as mock_add:
            with patch("app.scanners.ocsp_dnssec_scanner.build_safe_target_async", return_value=MagicMock()):
                mock_add.return_value = MagicMock()
                await probe_ocsp("h", cert_der=leaf_der)

                mock_add.assert_called_once()
                called_args, called_kwargs = mock_add.call_args
                assert called_kwargs["issuer"].serial_number == 1


