"""
End-to-end test for the L1 probe endpoint:
  POST /api/v1/scans/{scan_id}/l1-probe

Verifies that the endpoint runs DNSSEC probes and persists findings
into the Finding table via the l1_finding_service.

The probe layer is patched so the test is fully offline and fast.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.auth import get_current_user
from app.db import get_session
from app.models.models import User, Scan


app = create_app()

mock_user = User(
    id="12345678-1234-1234-1234-123456789012",
    email="analyst@pqc.local",
    full_name="Test Analyst",
    role="analyst",
    is_active=True,
)
app.dependency_overrides[get_current_user] = lambda: mock_user


@pytest.fixture
def mock_db():
    session = AsyncMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.pop(get_session, None)


def _scan_row(scan_id: str = "scan-uuid-1") -> Scan:
    now = datetime.now(timezone.utc)
    return Scan(
        id=scan_id,
        scan_type="tls_only",
        target="example.com",
        status="completed",
        advanced_tools=False,
        assets_found=1,
        findings_created=0,
        created_by=mock_user.id,
        created_at=now,
        updated_at=now,
    )


def _asset_row(asset_id: str = "asset-uuid-1") -> SimpleNamespace:
    return SimpleNamespace(
        id=asset_id,
        name="example.com:443",
        asset_type="web_app",
        fqdn="example.com",
        ip_address=None,
        port=443,
        protocol="tcp",
        environment="production",
        business_service=None,
        owner_id=None,
        discovery_source="tls_scan",
        first_scan_id=None,
        last_scan_id=None,
        first_discovered_at=datetime.now(timezone.utc),
        last_verified_at=datetime.now(timezone.utc),
        asset_metadata={},
        cmdb_ci_id=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        deleted_at=None,
    )


def _make_execute_result(items):
    """Build an AsyncMock execute result that yields `items` via .scalars().all()."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def test_l1_probe_endpoint_runs_and_returns_findings(mock_db):
    """
    The endpoint must:
      * Verify the scan exists.
      * Load assets with FQDNs.
      * Run DNSSEC probes (patched).
      * Persist findings via the l1_finding_service.
      * Return a response with `l1_probe.results` and `findings_created`.
    """
    scan = _scan_row()
    asset = _asset_row()

    # Four execute() calls in the endpoint:
    #   1) Look up Scan       -> scalar_one_or_none
    #   2) Load assets        -> scalars().all()
    #   3) Load certificates  -> scalars().all()  (OCSP wiring)
    # We dispatch on call count: first call returns the scan, the rest
    # return the assets / certs list.
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Scan lookup
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=scan)
            return r
        # Asset list, then cert list (OCSP wiring) — both empty for this test
        return _make_execute_result([asset] if call_count["n"] == 2 else [])

    mock_db.execute.side_effect = _execute
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    fake_dnssec_result = SimpleNamespace(
        domain="example.com",
        success=True,
        has_dnskey=True,
        has_rrsig=True,
        has_ds=True,
        algorithms=["RSASHA1", "RSASHA256"],
        chain_of_trust=True,
        error_message=None,
        pqc_status="vulnerable",
    )

    with patch(
        "app.scanners.ocsp_dnssec_scanner.probe_dnssec_batch",
        new=AsyncMock(return_value=[fake_dnssec_result]),
    ), patch(
        "app.scanners.ocsp_dnssec_scanner.probe_ocsp_batch",
        new=AsyncMock(return_value=[]),
    ):
        client = TestClient(app)
        resp = client.post(f"/api/v1/scans/{scan.id}/l1-probe")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scan_id"] == scan.id
    assert body["l1_probe"]["domains_probed"] == 1
    assert len(body["l1_probe"]["dnssec_results"]) == 1
    assert body["findings_created"]["dnssec_findings"] == 1
    # The service should have added one Finding row and committed it.
    assert mock_db.add.call_count == 1
    added = mock_db.add.call_args.args[0]
    assert added.finding_type == "weak_algorithm"
    assert added.severity == "high"
    assert added.layer == "L1"
    assert added.algorithm_type == "dnssec"
    mock_db.commit.assert_awaited()


def test_l1_probe_endpoint_no_assets_returns_zero(mock_db):
    """When there are no assets with FQDNs, the endpoint returns zero counts and skips the probe."""
    scan = _scan_row()

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=scan)
            return r
        return _make_execute_result([])

    mock_db.execute.side_effect = _execute

    client = TestClient(app)
    resp = client.post(f"/api/v1/scans/{scan.id}/l1-probe")
    assert resp.status_code == 200
    body = resp.json()
    assert body["l1_probe"]["domains_probed"] == 0
    assert body["findings_created"] == {
        "ocsp_findings": 0,
        "dnssec_findings": 0,
    }
    mock_db.add.assert_not_called()


def test_l1_probe_endpoint_ocsp_persists_revoked_finding(mock_db):
    """
    OCSP wiring: when a probe returns status=revoked, the endpoint must
    persist a critical cert_expired Finding with layer=L1, algorithm_type=ocsp.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    import uuid

    scan = _scan_row(scan_id=str(uuid.uuid4()))
    asset = _asset_row(asset_id=str(uuid.uuid4()))

    # Build a minimal self-signed PEM cert so the endpoint has raw bytes.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    cert_row = SimpleNamespace(
        id=str(uuid.uuid4()),
        asset_id=asset.id,
        thumbprint=cert.fingerprint(hashes.SHA1()).hex(),
        raw_certificate=pem_bytes.decode("utf-8"),
        not_before=now,
        deleted_at=None,
    )

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=scan)
            return r
        if call_count["n"] == 2:
            return _make_execute_result([asset])
        return _make_execute_result([cert_row])

    mock_db.execute.side_effect = _execute
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    fake_ocsp = SimpleNamespace(
        host="example.com",
        cert_thumbprint=cert_row.thumbprint,
        success=True,
        status="revoked",
        responder_url="http://ocsp.example.com",
        responder_name=None,
        signature_algorithm="sha256WithRSAEncryption",
        pqc_status="vulnerable",
        error_message=None,
        raw={},
    )
    fake_dnssec = SimpleNamespace(
        domain="example.com",
        success=True,
        has_dnskey=True,
        has_rrsig=True,
        has_ds=True,
        algorithms=["ECDSAP256SHA256"],
        chain_of_trust=True,
        error_message=None,
        pqc_status="safe",
    )

    with patch(
        "app.scanners.ocsp_dnssec_scanner.probe_dnssec_batch",
        new=AsyncMock(return_value=[fake_dnssec]),
    ), patch(
        "app.scanners.ocsp_dnssec_scanner.probe_ocsp_batch",
        new=AsyncMock(return_value=[fake_ocsp]),
    ):
        client = TestClient(app)
        resp = client.post(f"/api/v1/scans/{scan.id}/l1-probe")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["l1_probe"]["certs_probed"] == 1
    assert body["l1_probe"]["domains_probed"] == 1
    assert body["findings_created"]["ocsp_findings"] == 1
    # Only the OCSP finding — DNSSEC was safe, no finding raised.
    assert body["findings_created"]["dnssec_findings"] == 0
    assert mock_db.add.call_count == 1
    added = mock_db.add.call_args.args[0]
    assert added.severity == "critical"
    assert added.finding_type == "cert_expired"
    assert added.layer == "L1"
    assert added.algorithm_type == "ocsp"


def test_l1_probe_endpoint_requires_auth():
    """Unauthenticated calls must be rejected (the endpoint requires get_current_user)."""
    # Build a fresh app without the auth override.
    from app.main import create_app as _create
    from app.api.auth import get_current_user as _gcu
    fresh = _create()
    client = TestClient(fresh)
    resp = client.post("/api/v1/scans/00000000-0000-0000-0000-000000000000/l1-probe")
    # 401 (missing token) is the expected response.
    assert resp.status_code in (401, 403)
