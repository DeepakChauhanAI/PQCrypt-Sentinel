# Backend Schema Document

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Backend Engineering Team  
**Status:** Draft  

---

## 1. Overview

This document defines the complete database schema for the PQCrypt Sentinel platform. The primary database is PostgreSQL 16+ with JSONB support for flexible scan output. The schema follows these principles:

- **Append-only evidence store:** Scan results are immutable; new scans produce new records
- **Normalized core entities:** Assets, certificates, findings, owners as relational tables
- **JSONB for flexible fields:** Algorithm details, cert metadata, raw scan output stored as JSONB
- **Soft deletes:** All entities support archival via `deleted_at` timestamp
- **Temporal tracking:** All records include `created_at`, `updated_at` for audit trail

---

## 2. Entity Relationship Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    users     │     │  connectors  │     │    scans     │
│              │     │              │     │              │
│ id (PK)      │     │ id (PK)      │     │ id (PK)      │
│ email        │     │ name         │     │ scan_type    │
│ password_hash│     │ type         │     │ target       │
│ role         │     │ config       │     │ status       │
│ created_at   │     │ status       │     │ started_at   │
│ updated_at   │     │ last_sync_at │     │ completed_at │
│ deleted_at   │     │ created_by   │     │ created_by   │
└──────┬───────┘     │ created_at   │     │ config       │
       │             │ updated_at   │     │ results      │
       │             │ deleted_at   │     │ created_at   │
       │             └──────────────┘     └──────┬───────┘
       │                                        │
       │             ┌──────────────┐            │
       │             │    assets    │            │
       │             │              │            │
       │             │ id (PK)      │◄───────────┤
       │             │ name         │     scan_id(FK)
       │             │ asset_type   │            │
       │             │ ip_address   │            │
       │             │ fqdn         │            │
       │             │ port         │            │
       │             │ owner_id(FK) │            │
       │             │ business_svc │            │
       │             │ environment  │            │
       │             │ metadata     │            │
       │             │ created_at   │            │
       │             │ updated_at   │            │
       │             │ deleted_at   │            │
       │             └──────┬───────┘            │
       │                    │                    │
       │             ┌──────▼───────┐     ┌──────▼───────┐
       │             │certificates  │     │  findings    │
       │             │              │     │              │
       │             │ id (PK)      │     │ id (PK)      │
       │             │ asset_id(FK) │     │ asset_id(FK) │
       │             │ thumbprint   │     │ scan_id(FK)  │
       │             │ subject      │     │ finding_type │
       │             │ issuer       │     │ algorithm    │
       │             │ sig_alg      │     │ severity     │
       │             │ pub_key_alg  │     │ pqc_status   │
       │             │ pub_key_size │     │ risk_score   │
       │             │ not_before   │     │ evidence     │
       │             │ not_after    │     │ remediation  │
       │             │ pqc_capable  │     │ status       │
       │             │ raw_cert     │     │ assigned_to  │
       │             │ created_at   │     │ created_at   │
       │             │ updated_at   │     │ updated_at   │
       │             └──────────────┘     │ deleted_at   │
       │                                  └──────────────┘
       │
       │             ┌──────────────┐
       │             │ scan_logs    │
       │             │              │
       └────────────►│ id (PK)      │
                     │ scan_id(FK)  │
                     │ level        │
                     │ message      │
                     │ timestamp    │
                     └──────────────┘
```

---

## 3. Table Definitions

### 3.1 `users`

Stores platform user accounts and authentication data.

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('admin', 'analyst', 'viewer', 'api')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_role ON users(role) WHERE deleted_at IS NULL;
```

**Columns:**

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | No | gen_random_uuid() | Primary key |
| `email` | VARCHAR(255) | No | — | Unique email address |
| `password_hash` | VARCHAR(255) | No | — | bcrypt hash of password |
| `full_name` | VARCHAR(255) | No | — | Display name |
| `role` | VARCHAR(20) | No | 'viewer' | RBAC role |
| `is_active` | BOOLEAN | No | true | Account enabled/disabled |
| `last_login_at` | TIMESTAMPTZ | Yes | NULL | Last successful login |
| `created_at` | TIMESTAMPTZ | No | NOW() | Account creation time |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Last modification time |
| `deleted_at` | TIMESTAMPTZ | Yes | NULL | Soft delete timestamp |

---

### 3.2 `connectors`

Stores configured integrations with external systems (CMDBs, cloud providers, CAs).

```sql
CREATE TABLE connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    connector_type  VARCHAR(50) NOT NULL
                    CHECK (connector_type IN (
                        'servicenow', 'netbox', 'bmc_helix', 'device42',
                        'aws', 'azure', 'gcp', 'oci',
                        'ad_cs', 'vault_pki', 'ejbca', 'aws_pca',
                        'github', 'gitlab', 'bitbucket',
                        'kubernetes',
                        'csv_import'
                    )),
    config          JSONB NOT NULL DEFAULT '{}',
    credentials_ref VARCHAR(255),  -- Reference to vault secret, not the actual secret
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'connected', 'error', 'disabled')),
    last_sync_at    TIMESTAMPTZ,
    last_error      TEXT,
    sync_schedule   VARCHAR(50),  -- cron expression
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_connectors_type ON connectors(connector_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_connectors_status ON connectors(status) WHERE deleted_at IS NULL;
```

**Columns:**

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | No | gen_random_uuid() | Primary key |
| `name` | VARCHAR(255) | No | — | User-defined connector name |
| `connector_type` | VARCHAR(50) | No | — | Integration type |
| `config` | JSONB | No | '{}' | Connection config (URLs, ports, options) |
| `credentials_ref` | VARCHAR(255) | Yes | NULL | Vault reference for credentials |
| `status` | VARCHAR(20) | No | 'pending' | Connection health status |
| `last_sync_at` | TIMESTAMPTZ | Yes | NULL | Last successful data sync |
| `last_error` | TEXT | Yes | NULL | Last error message |
| `sync_schedule` | VARCHAR(50) | Yes | NULL | Cron expression for scheduled sync |
| `created_by` | UUID | Yes | NULL | FK to users |
| `created_at` | TIMESTAMPTZ | No | NOW() | Creation time |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Last modification time |
| `deleted_at` | TIMESTAMPTZ | Yes | NULL | Soft delete timestamp |

---

### 3.3 `scans`

Stores scan job definitions and execution state.

```sql
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type       VARCHAR(30) NOT NULL
                    CHECK (scan_type IN (
                        'full', 'tls_only', 'ssh_only', 'targeted',
                        'ct_monitor', 'ca_sync', 'cloud_sync', 'cmdb_sync'
                    )),
    target          TEXT,  -- IP ranges, domain list, or "all"
    status          VARCHAR(20) NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    config          JSONB NOT NULL DEFAULT '{}',
    credential_profile VARCHAR(255),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_seconds INTEGER,
    assets_found    INTEGER DEFAULT 0,
    findings_created INTEGER DEFAULT 0,
    error_message   TEXT,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_type ON scans(scan_type);
```

**Columns:**

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | No | gen_random_uuid() | Primary key |
| `scan_type` | VARCHAR(30) | No | — | Type of scan |
| `target` | TEXT | Yes | NULL | Scan target specification |
| `status` | VARCHAR(20) | No | 'queued' | Execution status |
| `config` | JSONB | No | '{}' | Scan configuration (throttle, timeout, etc.) |
| `credential_profile` | VARCHAR(255) | Yes | NULL | Credential set to use |
| `started_at` | TIMESTAMPTZ | Yes | NULL | Execution start time |
| `completed_at` | TIMESTAMPTZ | Yes | NULL | Execution end time |
| `duration_seconds` | INTEGER | Yes | NULL | Total execution duration |
| `assets_found` | INTEGER | No | 0 | Count of assets discovered |
| `findings_created` | INTEGER | No | 0 | Count of findings created |
| `error_message` | TEXT | Yes | NULL | Error details if failed |
| `created_by` | UUID | Yes | NULL | FK to users |
| `created_at` | TIMESTAMPTZ | No | NOW() | Creation time |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Last modification time |

---

### 3.4 `assets`

Stores discovered cryptographic assets (servers, endpoints, services).

```sql
CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(500) NOT NULL,
    asset_type      VARCHAR(50) NOT NULL
                    CHECK (asset_type IN (
                        'server', 'endpoint', 'network_device', 'load_balancer',
                        'vpn_gateway', 'database', 'web_app', 'api',
                        'container', 'kubernetes_cluster', 'cloud_resource',
                        'hsm', 'kms', 'certificate_authority', 'smart_card',
                        'firmware', 'saas', 'other'
                    )),
    ip_address      INET,
    fqdn            VARCHAR(500),
    port            INTEGER,
    protocol        VARCHAR(20),  -- tcp, udp
    os              VARCHAR(100),
    environment     VARCHAR(20) DEFAULT 'unknown'
                    CHECK (environment IN ('production', 'staging', 'development', 'testing', 'unknown')),
    business_service VARCHAR(255),
    owner_id        UUID REFERENCES users(id),
    discovery_source VARCHAR(50),  -- tls_scan, ssh_scan, cmdb, cloud_api, ct_log, etc.
    first_scan_id   UUID REFERENCES scans(id),
    last_scan_id    UUID REFERENCES scans(id),
    first_discovered_at TIMESTAMPTZ NOT NULL,
    last_verified_at    TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}',
    cmdb_ci_id      VARCHAR(255),  -- External CMDB reference
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_assets_type ON assets(asset_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_ip ON assets(ip_address) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_fqdn ON assets(fqdn) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_owner ON assets(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_env ON assets(environment) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_business_svc ON assets(business_service) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_last_scan ON assets(last_scan_id);
CREATE INDEX idx_assets_cmdb ON assets(cmdb_ci_id) WHERE cmdb_ci_id IS NOT NULL;
```

**Columns:**

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | No | gen_random_uuid() | Primary key |
| `name` | VARCHAR(500) | No | — | Display name (FQDN, hostname, or IP) |
| `asset_type` | VARCHAR(50) | No | — | Classification of asset |
| `ip_address` | INET | Yes | NULL | IP address |
| `fqdn` | VARCHAR(500) | Yes | NULL | Fully qualified domain name |
| `port` | INTEGER | Yes | NULL | Service port |
| `protocol` | VARCHAR(20) | Yes | NULL | Transport protocol |
| `os` | VARCHAR(100) | Yes | NULL | Operating system |
| `environment` | VARCHAR(20) | No | 'unknown' | Deployment environment |
| `business_service` | VARCHAR(255) | Yes | NULL | Associated business service |
| `owner_id` | UUID | Yes | NULL | FK to users (responsible owner) |
| `discovery_source` | VARCHAR(50) | Yes | NULL | How the asset was discovered |
| `first_scan_id` | UUID | Yes | NULL | FK to scans (first discovery) |
| `last_scan_id` | UUID | Yes | NULL | FK to scans (most recent verification) |
| `first_discovered_at` | TIMESTAMPTZ | No | — | When first discovered |
| `last_verified_at` | TIMESTAMPTZ | Yes | NULL | When last verified by scan |
| `metadata` | JSONB | No | '{}' | Additional asset metadata |
| `cmdb_ci_id` | VARCHAR(255) | Yes | NULL | External CMDB CI reference |
| `created_at` | TIMESTAMPTZ | No | NOW() | Record creation time |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Last modification time |
| `deleted_at` | TIMESTAMPTZ | Yes | NULL | Soft delete timestamp |

---

### 3.5 `certificates`

Stores discovered certificates associated with assets.

```sql
CREATE TABLE certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID REFERENCES assets(id),
    thumbprint      VARCHAR(128) NOT NULL,  -- SHA-256 fingerprint
    subject         TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    serial_number   VARCHAR(128),
    sig_algorithm   VARCHAR(100) NOT NULL,  -- e.g., sha256WithRSAEncryption
    pub_key_algorithm VARCHAR(100) NOT NULL,  -- e.g., RSA, EC, ML-DSA
    pub_key_size    INTEGER,  -- key size in bits (e.g., 2048, 256)
    curve_name      VARCHAR(50),  -- e.g., P-256, P-384, Ed25519
    not_before      TIMESTAMPTZ NOT NULL,
    not_after       TIMESTAMPTZ NOT NULL,
    is_self_signed  BOOLEAN NOT NULL DEFAULT false,
    is_ca           BOOLEAN NOT NULL DEFAULT false,
    key_usage       TEXT[],  -- array of key usage values
    san_dns         TEXT[],  -- Subject Alternative Names (DNS)
    san_ip          INET[],  -- Subject Alternative Names (IP)
    pqc_capable     BOOLEAN NOT NULL DEFAULT false,
    pqc_details     JSONB,  -- PQC-specific analysis
    chain_position  VARCHAR(20),  -- leaf, intermediate, root
    ca_thumbprint   VARCHAR(128),  -- thumbprint of issuing CA cert
    raw_certificate TEXT,  -- PEM-encoded certificate
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_cert_thumbprint ON certificates(thumbprint) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_asset ON certificates(asset_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_issuer ON certificates(issuer) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_not_after ON certificates(not_after);
CREATE INDEX idx_cert_pqc ON certificates(pqc_capable) WHERE deleted_at IS NULL;
CREATE INDEX idx_cert_ca ON certificates(is_ca) WHERE is_ca = true AND deleted_at IS NULL;
```

**Columns:**

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | No | gen_random_uuid() | Primary key |
| `asset_id` | UUID | Yes | NULL | FK to assets |
| `thumbprint` | VARCHAR(128) | No | — | SHA-256 certificate fingerprint |
| `subject` | TEXT | No | — | Certificate subject DN |
| `issuer` | TEXT | No | — | Certificate issuer DN |
| `serial_number` | VARCHAR(128) | Yes | NULL | Certificate serial number |
| `sig_algorithm` | VARCHAR(100) | No | — | Signature algorithm OID |
| `pub_key_algorithm` | VARCHAR(100) | No | — | Public key algorithm |
| `pub_key_size` | INTEGER | Yes | NULL | Key size in bits |
| `curve_name` | VARCHAR(50) | Yes | NULL | Elliptic curve name |
| `not_before` | TIMESTAMPTZ | No | — | Certificate validity start |
| `not_after` | TIMESTAMPTZ | No | — | Certificate validity end |
| `is_self_signed` | BOOLEAN | No | false | Self-signed flag |
| `is_ca` | BOOLEAN | No | false | CA certificate flag |
| `key_usage` | TEXT[] | Yes | NULL | Key usage extensions |
| `san_dns` | TEXT[] | Yes | NULL | SAN DNS entries |
| `san_ip` | INET[] | Yes | NULL | SAN IP entries |
| `pqc_capable` | BOOLEAN | No | false | Uses PQC algorithm |
| `pqc_details` | JSONB | Yes | NULL | PQC analysis details |
| `chain_position` | VARCHAR(20) | Yes | NULL | Position in cert chain |
| `ca_thumbprint` | VARCHAR(128) | Yes | NULL | Issuing CA cert reference |
| `raw_certificate` | TEXT | Yes | NULL | PEM-encoded cert |
| `created_at` | TIMESTAMPTZ | No | NOW() | Record creation time |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Last modification time |
| `deleted_at` | TIMESTAMPTZ | Yes | NULL | Soft delete timestamp |

---

### 3.6 `algorithms`

Stores algorithm inventory per asset (normalized from scan findings).

```sql
CREATE TABLE algorithms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    scan_id         UUID NOT NULL REFERENCES scans(id),
    algorithm_name  VARCHAR(100) NOT NULL,  -- e.g., RSA-2048, ECDHE-P-256, ML-KEM-768
    algorithm_type  VARCHAR(30) NOT NULL
                    CHECK (algorithm_type IN (
                        'key_exchange', 'signature', 'symmetric', 'hash',
                        'mac', 'kem', 'composite'
                    )),
    key_size        INTEGER,
    curve           VARCHAR(50),
    protocol        VARCHAR(50),  -- TLS, SSH, IPsec, etc.
    protocol_version VARCHAR(20),  -- TLS 1.2, TLS 1.3, etc.
    cipher_suite    VARCHAR(200),  -- Full cipher suite name
    pqc_status      VARCHAR(20) NOT NULL
                    CHECK (pqc_status IN ('vulnerable', 'transitioning', 'hybrid', 'pqc_ready', 'safe')),
    is_quantum_vulnerable BOOLEAN NOT NULL DEFAULT false,
    oid             VARCHAR(100),  -- Algorithm OID
    raw_value       TEXT,  -- Raw value from scan
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_algos_asset ON algorithms(asset_id);
CREATE INDEX idx_algos_scan ON algorithms(scan_id);
CREATE INDEX idx_algos_type ON algorithms(algorithm_type);
CREATE INDEX idx_algos_pqc_status ON algorithms(pqc_status);
CREATE INDEX idx_algos_vulnerable ON algorithms(is_quantum_vulnerable) WHERE is_quantum_vulnerable = true;
```

---

### 3.7 `findings`

Stores cryptographic findings (vulnerabilities, risks, recommendations).

```sql
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    scan_id         UUID NOT NULL REFERENCES scans(id),
    finding_type    VARCHAR(50) NOT NULL
                    CHECK (finding_type IN (
                        'weak_algorithm', 'weak_key_size', 'tls_version',
                        'pqc_not_supported', 'pqc_downgrade', 'cert_expiring',
                        'cert_expired', 'self_signed', 'unknown_ca',
                        'ssh_weak_kex', 'ssh_weak_host_key', 'vpn_weak_ike',
                        'hsm_vulnerable', 'kms_vulnerable', 'code_weak_crypto',
                        'sbom_vulnerable_lib', 'config_drift', 'other'
                    )),
    severity        VARCHAR(20) NOT NULL
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    algorithm       VARCHAR(100),  -- The vulnerable algorithm
    algorithm_type  VARCHAR(30),
    pqc_status      VARCHAR(20),
    risk_score      INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    hndl_exposure   VARCHAR(20)
                    CHECK (hndl_exposure IN ('high', 'medium', 'low', 'none')),
    evidence        JSONB,  -- Raw scan evidence
    remediation     TEXT,  -- Recommended fix
    recommended_algorithm VARCHAR(100),  -- PQC replacement
    status          VARCHAR(20) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted', 'false_positive')),
    assigned_to     UUID REFERENCES users(id),
    ticket_id       VARCHAR(255),  -- External ticket reference (Jira, ServiceNow)
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_verified_at  TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX idx_findings_asset ON findings(asset_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_status ON findings(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_assigned ON findings(assigned_to) WHERE assigned_to IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_findings_type ON findings(finding_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_risk ON findings(risk_score DESC) WHERE deleted_at IS NULL;
```

---

### 3.8 `scan_logs`

Stores structured log entries for scan execution (append-only).

```sql
CREATE TABLE scan_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id),
    level           VARCHAR(10) NOT NULL
                    CHECK (level IN ('debug', 'info', 'warn', 'error', 'fatal')),
    phase           VARCHAR(30),  -- discovery, analysis, reporting
    message         TEXT NOT NULL,
    details         JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_logs_scan ON scan_logs(scan_id, timestamp);
CREATE INDEX idx_scan_logs_level ON scan_logs(level) WHERE level IN ('error', 'fatal');
```

---

### 3.9 `asset_relationships`

Stores relationships between assets (dependency graph).

```sql
CREATE TABLE asset_relationships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_asset_id UUID NOT NULL REFERENCES assets(id),
    target_asset_id UUID NOT NULL REFERENCES assets(id),
    relationship_type VARCHAR(50) NOT NULL
                    CHECK (relationship_type IN (
                        'depends_on', 'connects_to', 'authenticates_with',
                        'signed_by', 'issued_by', 'managed_by',
                        'runs_on', 'hosts', 'contains'
                    )),
    confidence      DECIMAL(3,2) DEFAULT 1.00,  -- 0.00 to 1.00
    discovered_by   VARCHAR(50),  -- cmdb, scan_inference, manual
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX idx_rel_source ON asset_relationships(source_asset_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_rel_target ON asset_relationships(target_asset_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_rel_type ON asset_relationships(relationship_type) WHERE deleted_at IS NULL;
```

---

### 3.10 `migration_progress`

Tracks PQC migration state per asset over time.

```sql
CREATE TABLE migration_progress (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    scan_id         UUID NOT NULL REFERENCES scans(id),
    pqc_readiness   VARCHAR(20) NOT NULL
                    CHECK (pqc_readiness IN ('not_started', 'assessed', 'planned', 'in_progress', 'migrated', 'verified')),
    vulnerable_algorithms INTEGER NOT NULL DEFAULT 0,
    hybrid_algorithms     INTEGER NOT NULL DEFAULT 0,
    pqc_algorithms        INTEGER NOT NULL DEFAULT 0,
    safe_algorithms       INTEGER NOT NULL DEFAULT 0,
    readiness_score DECIMAL(5,2),  -- 0.00 to 100.00
    notes           TEXT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_migration_asset ON migration_progress(asset_id, recorded_at DESC);
CREATE INDEX idx_migration_scan ON migration_progress(scan_id);
CREATE INDEX idx_migration_readiness ON migration_progress(pqc_readiness);
```

---

### 3.11 `reports`

Stores generated report metadata.

```sql
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type     VARCHAR(30) NOT NULL
                    CHECK (report_type IN (
                        'cbom', 'executive', 'compliance_nist', 'compliance_cisa',
                        'compliance_ncsc', 'compliance_dora', 'compliance_rbi',
                        'migration_progress', 'raw_data'
                    )),
    format          VARCHAR(10) NOT NULL
                    CHECK (format IN ('json', 'pdf', 'csv')),
    scope           JSONB,  -- filters applied
    file_path       VARCHAR(500),  -- storage path
    file_size_bytes BIGINT,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'generating', 'ready', 'failed')),
    error_message   TEXT,
    generated_by    UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_created ON reports(created_at DESC);
```

---

## 4. JSONB Schema Examples

### 4.1 `assets.metadata`

```json
{
    "os_version": "Ubuntu 22.04",
    "ssh_version": "OpenSSH_8.9p1",
    "tls_versions": ["TLS 1.2", "TLS 1.3"],
    "server_header": "nginx/1.24.0",
    "cloud_provider": "aws",
    "cloud_region": "ap-south-1",
    "cloud_account_id": "123456789012",
    "kubernetes_namespace": "payments",
    "tags": ["production", "pci-scope"]
}
```

### 4.2 `certificates.pqc_details`

```json
{
    "oid": "2.16.840.1.101.3.4.3.17",
    "algorithm_name": "ML-DSA-65",
    "is_hybrid": false,
    "hybrid_partner": null,
    "pqc_standard": "FIPS 204",
    "vendor_support": {
        "openssl": "3.5+",
        "boringssl": "2024-09+",
        "nss": "3.101+"
    }
}
```

### 4.3 `findings.evidence`

```json
{
    "tool": "sslyze",
    "tool_version": "6.0.0",
    "raw_output": "Protocol: TLS 1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384...",
    "cert_thumbprint": "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12",
    "config_line": "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1",
    "negotiated_kex": "X25519",
    "offered_pqc_groups": [],
    "downgrade_possible": true
}
```

---

## 5. Authentication & Session Handling

### Session Table (if using server-side sessions)

```sql
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

### API Keys Table

```sql
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    name            VARCHAR(255) NOT NULL,
    key_hash        VARCHAR(255) NOT NULL UNIQUE,
    scopes          TEXT[] NOT NULL DEFAULT '{}',  -- e.g., {'scans:read', 'assets:read'}
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = true;
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
```

---

## 6. Permissions Matrix

| Resource | Admin | Analyst | Viewer | API |
|---|---|---|---|---|
| **Users** | CRUD | Read | — | — |
| **Connectors** | CRUD | Read, Test | Read | Read |
| **Scans** | CRUD | Create, Read, Cancel | Read | Create, Read |
| **Assets** | CRUD | Read, Update | Read | Read |
| **Findings** | CRUD | Read, Update status/assign | Read | Read |
| **Reports** | CRUD | Create, Read | Read | Create, Read |
| **Settings** | CRUD | Read | Read | — |
| **API Keys** | CRUD | CRUD (own) | — | — |

---

## 7. Data Ownership Rules

| Data | Owner | Retention | Deletion |
|---|---|---|---|
| **Users** | Admin | Until deleted | Soft delete |
| **Connectors** | Admin | Until deleted | Soft delete |
| **Scans** | Creator | 2 years (configurable) | Hard delete after retention |
| **Assets** | System | Until no longer discovered + 90 days | Soft delete, hard after 1 year |
| **Certificates** | System | Until expired + 1 year | Soft delete |
| **Findings** | Assigned user | Until resolved + 1 year | Soft delete |
| **Scan Logs** | System | 90 days | Hard delete |
| **Reports** | Generator | 1 year | Hard delete |
| **Evidence** | System | 2 years | Hard delete |

---

## 8. Indexes Summary

| Table | Index | Purpose |
|---|---|---|
| `assets` | `(ip_address, port)` | Unique asset identification |
| `assets` | `(fqdn, port)` | FQDN-based lookup |
| `assets` | `(last_scan_id)` | Scan result join |
| `certificates` | `(thumbprint)` UNIQUE | Deduplication |
| `certificates` | `(not_after)` | Expiry queries |
| `algorithms` | `(asset_id, algorithm_type)` | Asset algo inventory |
| `findings` | `(asset_id, status)` | Open findings per asset |
| `findings` | `(severity, status)` | Dashboard severity counts |
| `findings` | `(assigned_to, status)` | User backlog |
| `scan_logs` | `(scan_id, timestamp)` | Log timeline |
| `migration_progress` | `(asset_id, recorded_at DESC)` | Progress trend |
