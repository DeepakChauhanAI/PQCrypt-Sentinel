from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, validates


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(
        Enum("admin", "analyst", "viewer", "api", name="user_role_enum", native_enum=False),
        nullable=False,
        server_default="viewer",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    replaced_by: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("refresh_tokens.id"), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    scan_type: Mapped[str] = mapped_column(
        Enum(
            # Host / network scans
            "full",
            "tls_only",
            "ssh_only",
            "targeted",
            "ct_monitor",
            "ca_sync",
            "cloud_sync",
            "cmdb_sync",
            "passive",
            # Connector-backed scans (must match the scan_type values used in
            # app/api/connectors.py — otherwise the Scan insert throws
            # IntegrityError against the CHECK constraint).
            "winrm",
            "kubernetes",
            "oracle_tde",
            "sqlserver_tde",
            "pkcs11_hsm",
            "kmip_kms",
            "adcs_ldap",
            "jwt_audit",
            "windows_cert_store",
            name="scan_type_enum",
            native_enum=False,
        ),
        nullable=False,
    )
    target: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            name="scan_status_enum",
            native_enum=False,
        ),
        nullable=False,
        server_default="queued",
    )
    config: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    credential_profile: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    advanced_tools: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    assets_found: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    logs: Mapped[list["ScanLog"]] = relationship(
        "ScanLog", back_populates="scan", cascade="all, delete-orphan"
    )

    # Phase B — correlation model
    scan_group_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_groups.id", ondelete="SET NULL"), nullable=True
    )
    target_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_kind: Mapped[Optional[str]] = mapped_column(
        Enum(
            "host", "cloud_account", "code_repo", "domain",
            "saas_tenant", "network_range", "interface", "other",
            name="scan_target_kind_enum", native_enum=False,
        ),
        nullable=True,
    )

    group: Mapped[Optional["ScanGroup"]] = relationship(
        "ScanGroup", back_populates="scans", foreign_keys=[scan_group_id]
    )


class ScanGroup(Base):
    """A logical grouping of related scans (e.g. a "Q2 Estate Audit" campaign
    that fans out to a TLS scan, an AWS scan, and an SSH scan on the same estate).

    A scan belongs to at most one group. Groups carry human-readable naming,
    status roll-ups, and a single cancellation / re-run entry point.
    """
    __tablename__ = "scan_groups"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(
            "queued", "running", "completed", "failed", "cancelled",
            name="scan_group_status_enum", native_enum=False,
        ),
        nullable=False,
        server_default="queued",
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    scans: Mapped[list["Scan"]] = relationship(
        "Scan", back_populates="group", foreign_keys="Scan.scan_group_id"
    )


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    level: Mapped[str] = mapped_column(
        Enum("debug", "info", "warn", "error", "fatal", name="log_level_enum", native_enum=False),
        nullable=False,
    )
    phase: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="logs")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_type: Mapped[str] = mapped_column(
        Enum(
            "server", "endpoint", "network_device", "load_balancer",
            "vpn_gateway", "database", "web_app", "api",
            "container", "kubernetes_cluster", "cloud_resource",
            "hsm", "kms", "certificate_authority", "smart_card",
            "firmware", "saas", "other",
            "source_code", "jwt", "hsm_key", "kms_key",
            "kubernetes", "saml_metadata", "windows_cert_store",
            name="asset_type_enum", native_enum=False
        ),
        nullable=False,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True) # INET maps to String
    fqdn: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    environment: Mapped[str] = mapped_column(
        Enum("production", "staging", "development", "testing", "unknown", "cloud", "onprem", name="asset_env_enum", native_enum=False),
        nullable=False,
        server_default="unknown",
    )
    business_service: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owner_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    discovery_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    first_scan_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    last_scan_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    first_discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, server_default="{}")
    cmdb_ci_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    certificates: Mapped[list["Certificate"]] = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    algorithms: Mapped[list["Algorithm"]] = relationship("Algorithm", back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    asset_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    thumbprint: Mapped[str] = mapped_column(String(128), nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    sig_algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    pub_key_algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    pub_key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    curve_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_ca: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    key_usage: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    san_dns: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    san_ip: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    pqc_capable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    pqc_details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    chain_position: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ca_thumbprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    raw_certificate: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="certificates")


class Algorithm(Base):
    __tablename__ = "algorithms"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    asset_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    algorithm_name: Mapped[str] = mapped_column(String(100), nullable=False)
    algorithm_type: Mapped[str] = mapped_column(
        Enum("key_exchange", "signature", "symmetric", "hash", "mac", "kem", "composite", name="algo_type_enum", native_enum=False),
        nullable=False,
    )
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    curve: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    pqc_status: Mapped[str] = mapped_column(
        Enum("vulnerable", "transitioning", "hybrid", "pqc_ready", "safe", name="algo_pqc_enum", native_enum=False),
        nullable=False,
    )
    is_quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    oid: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    algo_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    asset: Mapped["Asset"] = relationship("Asset", back_populates="algorithms")

    @validates("pqc_status")
    def validate_pqc_status(self, key: str, value: str) -> str:
        valid_statuses = {"vulnerable", "transitioning", "hybrid", "pqc_ready", "safe"}
        if value in valid_statuses:
            return value
        
        # Normalize detailed registry/classification status to database enum
        v = value.lower() if value else ""
        if v in ("pqc_ready", "pqc_candidate"):
            return "pqc_ready"
        if v == "hybrid":
            return "hybrid"
        if v == "safe":
            return "safe"
        # Registry statuses: pqc_ready, pqc_candidate, hybrid, safe, safe_until_2030,
        # safe_until_2035, vulnerable, deprecated_now, disallowed_now, unknown.
        # All non-safe statuses (including safe_until_2030/2035) map to DB enum 'vulnerable'.
        return "vulnerable"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    asset_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_type: Mapped[str] = mapped_column(
        Enum(
            'weak_algorithm', 'weak_key_size', 'tls_version',
            'pqc_not_supported', 'pqc_downgrade', 'cert_expiring',
            'cert_expired', 'self_signed', 'unknown_ca',
            'ssh_weak_kex', 'ssh_weak_host_key', 'vpn_weak_ike',
            'hsm_vulnerable', 'kms_vulnerable', 'code_weak_crypto',
            'sbom_vulnerable_lib', 'config_drift', 'other',
            name="finding_type_enum", native_enum=False
        ),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="severity_enum", native_enum=False),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    algorithm: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    algorithm_type: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    pqc_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    layer: Mapped[Optional[str]] = mapped_column(String(5), nullable=True, index=True)
    hndl_exposure: Mapped[Optional[str]] = mapped_column(
        Enum("high", "medium", "low", "none", name="hndl_exposure_enum", native_enum=False),
        nullable=True,
    )
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_algorithm: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum("open", "in_progress", "resolved", "accepted", "false_positive", name="finding_status_enum", native_enum=False),
        nullable=False,
        server_default="open",
    )
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")

    @property
    def priority_queue(self) -> str:
        score = self.risk_score or 5
        if score >= 20:
            return "P1"
        elif score >= 15:
            return "P2"
        elif score >= 10:
            return "P3"
        else:
            return "P4"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    report_type: Mapped[str] = mapped_column(
        Enum(
            "cbom",
            "executive",
            "findings",
            name="report_type_enum",
            native_enum=False,
        ),
        nullable=False,
    )
    scope_filters: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    format: Mapped[str] = mapped_column(String(10), nullable=False)  # "json", "pdf", "csv"
    status: Mapped[str] = mapped_column(
        Enum("pending", "generating", "ready", "failed", name="report_status_enum", native_enum=False),
        nullable=False,
        server_default="pending",
    )
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)



