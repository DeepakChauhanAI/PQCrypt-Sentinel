from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, field_validator


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    is_active: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class ScanBase(BaseModel):
    scan_type: str
    target: Optional[str] = None
    status: str = "queued"
    config: Optional[str] = None
    credential_profile: Optional[str] = None
    advanced_tools: bool = False
    error_message: Optional[str] = None
    assets_found: int = 0
    findings_created: int = 0


class ScanCreate(ScanBase):
    """A standalone scan request.

    For grouped scans, use ``ScanGroupCreate`` instead — it fans out to
    multiple ``Scan`` rows under one logical operation.
    """
    # Optional correlation metadata. May be supplied by the client or
    # derived server-side from the target string.
    target_label: Optional[str] = None
    target_kind: Optional[str] = None
    scan_group_id: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    assets_found: Optional[int] = None
    findings_created: Optional[int] = None
    error_message: Optional[str] = None


class ScanOut(ScanBase):
    id: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    # Phase B — correlation model
    scan_group_id: Optional[str] = None
    target_label: Optional[str] = None
    target_kind: Optional[str] = None

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", "scan_group_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class ScanLogBase(BaseModel):
    scan_id: str
    level: str
    phase: Optional[str] = None
    message: str
    details: Optional[dict] = None

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, value):
        if isinstance(value, str):
            return value.lower()
        return value


class ScanLogCreate(BaseModel):
    level: str
    phase: Optional[str] = None
    message: str
    details: Optional[dict] = None

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, value):
        if isinstance(value, str):
            return value.lower()
        return value


class ScanLogOut(ScanLogBase):
    id: str
    timestamp: datetime

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", "scan_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class AlgorithmOut(BaseModel):
    id: str
    asset_id: str
    scan_id: str
    algorithm_name: str
    algorithm_type: str
    key_size: Optional[int] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    pqc_status: str
    is_quantum_vulnerable: bool
    oid: Optional[str] = None

    model_config = {"from_attributes": True}

    @field_validator("id", "asset_id", "scan_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class CertificateOut(BaseModel):
    id: str
    asset_id: Optional[str] = None
    thumbprint: str
    subject: str
    issuer: str
    serial_number: Optional[str] = None
    sig_algorithm: str
    pub_key_algorithm: str
    pub_key_size: Optional[int] = None
    curve_name: Optional[str] = None
    not_before: datetime
    not_after: datetime
    is_self_signed: bool
    is_ca: bool
    key_usage: Optional[List[str]] = None
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None
    pqc_capable: bool
    pqc_details: Optional[dict] = None
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

    @field_validator("id", "asset_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class AssetOut(BaseModel):
    id: str
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    os: Optional[str] = None
    environment: str
    business_service: Optional[str] = None
    owner_id: Optional[str] = None
    discovery_source: Optional[str] = None
    first_scan_id: Optional[str] = None
    last_scan_id: Optional[str] = None
    first_discovered_at: datetime
    last_verified_at: Optional[datetime] = None
    asset_metadata: dict
    created_at: datetime
    updated_at: datetime
    risk_score: Optional[int] = 0
    pqc_status: Optional[str] = "vulnerable"
    algorithms: List["AlgorithmOut"] = []
    certificates: List["CertificateOut"] = []
    findings: List["FindingOut"] = []
    # Phase B — scan-group correlation enrichment (populated by
    # app.api.assets._enrich_assets_with_scan_groups)
    last_scan_group_id: Optional[str] = None
    last_scan_group_name: Optional[str] = None
    first_scan_group_id: Optional[str] = None
    first_scan_group_name: Optional[str] = None

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", "owner_id", "first_scan_id", "last_scan_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class FindingAssetOut(BaseModel):
    id: str
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    environment: str

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class FindingOut(BaseModel):
    id: str
    asset_id: str
    scan_id: str
    finding_type: str
    severity: str
    title: str
    description: Optional[str] = None
    algorithm: Optional[str] = None
    algorithm_type: Optional[str] = None
    pqc_status: Optional[str] = None
    risk_score: Optional[int] = None
    hndl_exposure: Optional[str] = None
    evidence: Optional[dict] = None
    remediation: Optional[str] = None
    recommended_algorithm: Optional[str] = None
    status: str
    first_detected_at: datetime
    last_verified_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    priority_queue: Optional[str] = None
    asset: Optional[FindingAssetOut] = None
    # Phase B — correlation context. The FindingOut previously exposed only
    # scan_id as an opaque UUID, which made it impossible to tell from the
    # Findings page which campaign a finding belonged to. These three fields
    # are denormalised from the parent Scan at read time so the UI can
    # render "Q2 Estate Audit › TLS_ONLY" without an extra hop.
    scan_type: Optional[str] = None
    scan_target: Optional[str] = None
    scan_target_label: Optional[str] = None
    scan_group_id: Optional[str] = None
    scan_group_name: Optional[str] = None

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", "asset_id", "scan_id", "scan_group_id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    reason: Optional[str] = None # For marking false positive/accepting with reason


class DashboardSummary(BaseModel):
    pqc_readiness_score: float
    total_assets: int
    vulnerable_count: int
    hybrid_count: int
    pqc_ready_count: int
    safe_count: int
    critical_findings: int
    high_findings: int
    drift_alerts_count: int


class DashboardRiskDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class DashboardProgressItem(BaseModel):
    scan_date: str
    vulnerable: int
    hybrid: int
    pqc_ready: int


class DashboardLayerCoverage(BaseModel):
    layers: List[dict]
    overall_coverage_pct: float


class ReportOut(BaseModel):
    id: str
    report_type: str
    format: str
    scope_filters: dict
    status: str
    file_path: Optional[str] = None
    error_message: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", "created_by", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


# ----------------------------------------------------------------------
# Phase B — correlation model: ScanGroup
# ----------------------------------------------------------------------


class ScanGroupMemberSpec(BaseModel):
    """One member scan within a ScanGroup request.

    The member's ``scan_type`` and ``target`` are required; everything else
    is inherited from the group (e.g. advanced_tools) unless overridden.
    """
    scan_type: str
    target: str
    target_label: Optional[str] = None
    target_kind: Optional[str] = None
    config: Optional[str] = None
    credential_profile: Optional[str] = None
    advanced_tools: Optional[bool] = None


class ScanGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    members: list[ScanGroupMemberSpec]
    # Optional group-level flags inherited by every member unless overridden
    advanced_tools: bool = False


class ScanGroupOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    # Roll-ups — computed at read time by the API
    member_count: int = 0
    assets_found: int = 0
    findings_created: int = 0

    model_config = {
        "from_attributes": True,
    }

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid_to_str(cls, value):
        if hasattr(value, "hex"):
            return str(value)
        return value


class ScanGroupDetailOut(ScanGroupOut):
    """Detailed view with the full member list."""
    members: list[ScanOut] = []


