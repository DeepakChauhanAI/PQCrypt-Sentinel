import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from datetime import datetime, timezone

from app.models.schemas import (
    UserOut,
    ScanOut,
    ScanLogBase,
    ScanLogCreate,
    ScanLogOut,
    AlgorithmOut,
    CertificateOut,
    AssetOut,
    FindingAssetOut,
    FindingOut,
    ReportOut,
    ScanGroupOut,
)


NOW = datetime.now(timezone.utc)


class TestCoerceUuidToStr:
    def test_user_out_uuid_coercion(self):
        uid = uuid.uuid4()
        obj = UserOut(
            id=uid,
            email="test@example.com",
            role="admin",
            is_active=True,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(uid)
        assert isinstance(obj.id, str)

    def test_user_out_str_passthrough(self):
        obj = UserOut(
            id="abc-123",
            email="test@example.com",
            role="admin",
            is_active=True,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "abc-123"

    def test_scan_out_uuid_coercion(self):
        sid = uuid.uuid4()
        gid = uuid.uuid4()
        obj = ScanOut(
            id=sid,
            scan_type="full",
            target="example.com",
            status="completed",
            scan_group_id=gid,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(sid)
        assert obj.scan_group_id == str(gid)

    def test_scan_out_none_scan_group_id(self):
        obj = ScanOut(
            id="s1",
            scan_type="full",
            target="example.com",
            status="completed",
            scan_group_id=None,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.scan_group_id is None

    def test_scan_log_out_uuid_coercion(self):
        lid = uuid.uuid4()
        sid = uuid.uuid4()
        obj = ScanLogOut(
            id=lid,
            scan_id=sid,
            level="info",
            message="test",
            timestamp=NOW,
        )
        assert obj.id == str(lid)
        assert obj.scan_id == str(sid)

    def test_algorithm_out_uuid_coercion(self):
        aid = uuid.uuid4()
        asset_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        obj = AlgorithmOut(
            id=aid,
            asset_id=asset_id,
            scan_id=scan_id,
            algorithm_name="RSA",
            algorithm_type="asymmetric",
            pqc_status="vulnerable",
            is_quantum_vulnerable=True,
        )
        assert obj.id == str(aid)
        assert obj.asset_id == str(asset_id)
        assert obj.scan_id == str(scan_id)

    def test_certificate_out_uuid_coercion(self):
        cid = uuid.uuid4()
        asset_id = uuid.uuid4()
        obj = CertificateOut(
            id=cid,
            asset_id=asset_id,
            thumbprint="abc",
            subject="CN=test",
            issuer="CN=CA",
            sig_algorithm="sha256RSA",
            pub_key_algorithm="RSA",
            not_before=NOW,
            not_after=NOW,
            is_self_signed=False,
            is_ca=False,
            pqc_capable=False,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(cid)
        assert obj.asset_id == str(asset_id)

    def test_asset_out_uuid_coercion(self):
        aid = uuid.uuid4()
        owner_id = uuid.uuid4()
        first_scan_id = uuid.uuid4()
        last_scan_id = uuid.uuid4()
        obj = AssetOut(
            id=aid,
            name="server1",
            asset_type="server",
            environment="production",
            owner_id=owner_id,
            first_scan_id=first_scan_id,
            last_scan_id=last_scan_id,
            first_discovered_at=NOW,
            asset_metadata={},
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(aid)
        assert obj.owner_id == str(owner_id)
        assert obj.first_scan_id == str(first_scan_id)
        assert obj.last_scan_id == str(last_scan_id)

    def test_finding_asset_out_uuid_coercion(self):
        fid = uuid.uuid4()
        obj = FindingAssetOut(
            id=fid,
            name="server1",
            asset_type="server",
            environment="production",
        )
        assert obj.id == str(fid)

    def test_finding_out_uuid_coercion(self):
        fid = uuid.uuid4()
        asset_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        gid = uuid.uuid4()
        obj = FindingOut(
            id=fid,
            asset_id=asset_id,
            scan_id=scan_id,
            finding_type="weak_algorithm",
            severity="high",
            title="test",
            status="open",
            first_detected_at=NOW,
            created_at=NOW,
            updated_at=NOW,
            scan_group_id=gid,
        )
        assert obj.id == str(fid)
        assert obj.asset_id == str(asset_id)
        assert obj.scan_id == str(scan_id)
        assert obj.scan_group_id == str(gid)

    def test_report_out_uuid_coercion(self):
        rid = uuid.uuid4()
        created_by = uuid.uuid4()
        obj = ReportOut(
            id=rid,
            report_type="full",
            format="pdf",
            scope_filters={},
            status="completed",
            created_by=created_by,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(rid)
        assert obj.created_by == str(created_by)

    def test_scan_group_out_uuid_coercion(self):
        gid = uuid.uuid4()
        obj = ScanGroupOut(
            id=gid,
            name="group1",
            status="completed",
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == str(gid)


class TestNormalizeLevel:
    def test_scan_log_base_uppercase_normalized(self):
        obj = ScanLogBase(
            scan_id="s1",
            level="INFO",
            message="test",
        )
        assert obj.level == "info"

    def test_scan_log_base_mixed_case_normalized(self):
        obj = ScanLogBase(
            scan_id="s1",
            level="Warning",
            message="test",
        )
        assert obj.level == "warning"

    def test_scan_log_base_lowercase_passthrough(self):
        obj = ScanLogBase(
            scan_id="s1",
            level="error",
            message="test",
        )
        assert obj.level == "error"

    def test_scan_log_create_uppercase_normalized(self):
        obj = ScanLogCreate(
            level="DEBUG",
            message="test",
        )
        assert obj.level == "debug"

    def test_scan_log_create_mixed_case_normalized(self):
        obj = ScanLogCreate(
            level="Critical",
            message="test",
        )
        assert obj.level == "critical"

    def test_scan_log_create_lowercase_passthrough(self):
        obj = ScanLogCreate(
            level="info",
            message="test",
        )
        assert obj.level == "info"

    def test_scan_log_base_normalize_non_string(self):
        assert ScanLogBase.normalize_level(None) is None
        assert ScanLogBase.normalize_level(123) == 123

    def test_scan_log_create_normalize_non_string(self):
        assert ScanLogCreate.normalize_level(None) is None
        assert ScanLogCreate.normalize_level(123) == 123


class TestCoerceUuidToStrPassthrough:
    """Cover the `return value` branch of every coerce_uuid_to_str validator."""

    def test_scan_out_str_passthrough(self):
        obj = ScanOut(
            id="scan-1",
            scan_type="full",
            target="example.com",
            status="completed",
            scan_group_id="group-1",
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "scan-1"
        assert obj.scan_group_id == "group-1"

    def test_scan_log_out_str_passthrough(self):
        obj = ScanLogOut(
            id="log-1",
            scan_id="scan-1",
            level="info",
            message="test",
            timestamp=NOW,
        )
        assert obj.id == "log-1"
        assert obj.scan_id == "scan-1"

    def test_algorithm_out_str_passthrough(self):
        obj = AlgorithmOut(
            id="algo-1",
            asset_id="asset-1",
            scan_id="scan-1",
            algorithm_name="RSA",
            algorithm_type="asymmetric",
            pqc_status="vulnerable",
            is_quantum_vulnerable=True,
        )
        assert obj.id == "algo-1"
        assert obj.asset_id == "asset-1"
        assert obj.scan_id == "scan-1"

    def test_certificate_out_str_passthrough(self):
        obj = CertificateOut(
            id="cert-1",
            asset_id="asset-1",
            thumbprint="abc",
            subject="CN=test",
            issuer="CN=CA",
            sig_algorithm="sha256RSA",
            pub_key_algorithm="RSA",
            not_before=NOW,
            not_after=NOW,
            is_self_signed=False,
            is_ca=False,
            pqc_capable=False,
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "cert-1"
        assert obj.asset_id == "asset-1"

    def test_asset_out_str_passthrough(self):
        obj = AssetOut(
            id="asset-1",
            name="server1",
            asset_type="server",
            environment="production",
            owner_id="owner-1",
            first_scan_id="scan-1",
            last_scan_id="scan-2",
            first_discovered_at=NOW,
            asset_metadata={},
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "asset-1"
        assert obj.owner_id == "owner-1"

    def test_finding_asset_out_str_passthrough(self):
        obj = FindingAssetOut(
            id="fa-1",
            name="server1",
            asset_type="server",
            environment="production",
        )
        assert obj.id == "fa-1"

    def test_finding_out_str_passthrough(self):
        obj = FindingOut(
            id="finding-1",
            asset_id="asset-1",
            scan_id="scan-1",
            finding_type="weak_algorithm",
            severity="high",
            title="test",
            status="open",
            first_detected_at=NOW,
            created_at=NOW,
            updated_at=NOW,
            scan_group_id="group-1",
        )
        assert obj.id == "finding-1"
        assert obj.asset_id == "asset-1"
        assert obj.scan_id == "scan-1"
        assert obj.scan_group_id == "group-1"

    def test_report_out_str_passthrough(self):
        obj = ReportOut(
            id="report-1",
            report_type="full",
            format="pdf",
            scope_filters={},
            status="completed",
            created_by="user-1",
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "report-1"
        assert obj.created_by == "user-1"

    def test_scan_group_out_str_passthrough(self):
        obj = ScanGroupOut(
            id="group-1",
            name="group1",
            status="completed",
            created_at=NOW,
            updated_at=NOW,
        )
        assert obj.id == "group-1"


