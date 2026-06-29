# PQCrypt Sentinel — Technical Architecture Document

**Version:** 1.0
**Date:** June 2026
**Status:** Draft
**Audience:** Engineering team, architects, DevOps

---

## Table of Contents

1. [Tech Stack & Rationale](#1-tech-stack--rationale)
2. [Project File & Folder Structure](#2-project-file--folder-structure)
3. [Database Schema (Plain English)](#3-database-schema-plain-english)
4. [Environment Variables & Configuration](#4-environment-variables--configuration)
5. [Architecture Overview](#5-architecture-overview)
6. [Deployment Topology](#6-deployment-topology)
7. [Security Model](#7-security-model)
8. [Key Design Decisions](#8-key-design-decisions)

---

## 1. Tech Stack & Rationale

### 1.1 Frontend

| Layer | Choice | Why |
|---|---|---|
| Framework | **React 18+ with TypeScript** | Industry standard, massive talent pool, strong type safety for complex crypto data models. Every enterprise frontend hire already knows React. |
| Build Tool | **Vite** | Fast HMR in dev, native ESM, optimized production builds. Faster than CRA or webpack for large dashboards. |
| UI Components | **shadcn/ui + Tailwind CSS v3** | shadcn/ui gives you Radix UI primitives (accessible, unstyled) with copy-paste components — no vendor lock-in, full control. Tailwind enables rapid, consistent styling. Together they beat Ant Design or MUI for this use case because the design is highly custom (dark-mode-first, security-tool aesthetic). |
| State Management | **TanStack Query (React Query) v5** | Server state is 90% of the app. React Query handles caching, background refetching, loading/error states — you don't need Redux or Zustand for this. Local component state handles the remaining 10%. |
| Routing | **React Router v6** | Standard, battle-tested, supports lazy-loaded routes for dashboard widgets. |
| Charts | **Recharts** | Declarative, composable, built on D3. Good enough for donut, line, bar, and gauge charts. If you need force-graph blast-radius viz later, drop in React Flow. |
| Graph Viz | **React Flow** (Phase 3) | For dependency/blast-radius graphs. Drop-in React component, handles zoom/pan/node drag out of the box. |
| Icons | **Lucide React** | MIT-licensed, consistent design language, tree-shakeable. Replaces the need for FontAwesome or Material Icons. |
| Forms | **React Hook Form + Zod** | Minimal re-renders, Zod schema validation mirrors Pydantic on the backend — same validation rules on both sides. |

**Why not alternatives:**
- Vue/Svelte: Smaller talent pool, fewer enterprise security-tool references.
- Next.js: Overkill for a self-hosted, single-tenant app; adds API route complexity you don't need.
- Axios: TanStack Query already handles HTTP; no need for a separate client.

---

### 1.2 Backend

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.12+** | Richest ecosystem for the actual tools you're wrapping: `cryptography`, `sslyze`, `pyshark`, `paramiko`, `scapy`, `python-nmap`, `dnspython`. A Go or Rust rewrite of these integrations would take months longer. Team familiarity with Python security tooling is a real advantage. |
| Framework | **FastAPI** | Async-first, auto-generates OpenAPI 3.1 docs (critical for an auditable security product), Pydantic v2 validation, native WebSocket support for scan progress streaming. Faster than Django REST Framework, more structured than Flask. |
| ORM | **SQLAlchemy 2.0 (async)** | Mature, supports asyncpg, Alembic migrations built-in, JSONB column support, works well with Pydantic. Django ORM would lock you into Django's structure. |
| Migrations | **Alembic** | Official SQLAlchemy migration tool. Autogenerates migrations from model changes. |
| Task Queue | **Celery 5 + Redis broker** | Most mature distributed task queue in Python. Critical for scan jobs that may run for hours. Celery Beat for scheduled scans. Monitoring via Flower. RQ is simpler but doesn't scale to 100K+ endpoints well. Dramatiq is newer with a cleaner API but smaller ecosystem. |
| Message Broker / Cache | **Redis 7+** | Triple duty: Celery broker, session/cache store, rate limiter state. Single dependency. |
| Authentication | **python-jose (JWT) + passlib (bcrypt)** | OIDC is deferred to Phase 2. For MVP, bcrypt passwords + JWT access/refresh tokens is sufficient and auditable. |
| Validation | **Pydantic v2** | Input validation on every endpoint, generates OpenAPI schema automatically. Use the same schema on frontend (Zod) and backend (Pydantic) for consistency. |
| Serialization | **orjson** | 3-5x faster than stdlib `json`. Drop-in replacement. Useful for large scan results. |

---

### 1.3 Data Layer

| Component | Choice | Why |
|---|---|---|
| Primary Database | **PostgreSQL 16+** | JSONB for flexible scan output, full-text search, mature, ACID-compliant, self-hosted. MongoDB would be easier for scan results but weaker for relational queries (asset → cert → finding joins). MySQL lacks JSONB performance. PostgreSQL is the right balance. |
| Cache / Broker | **Redis 7+** | Listed above under backend. |
| Graph Database | **Neo4j (Phase 3 only)** | Dependency graph traversal (blast radius, impact analysis). Not needed for MVP — PostgreSQL recursive CTEs handle the initial relationship queries. Add Neo4j when you have 10K+ assets and graph queries become slow. |
| Object Storage | **Filesystem (local/NFS)** | Store raw scan outputs (pcap snippets, cert PEMs, tool JSON). No need for S3/MinIO in MVP — the product is self-hosted on-prem. Customers already have storage. |

---

### 1.4 Infrastructure & Deployment

| Component | Choice | Why |
|---|---|---|
| Container Runtime | **Docker + Docker Compose** | Single `docker-compose up` deploys the entire platform. This is a **product requirement** — it's also your competitive moat. Every commercial tool needs 8-12 weeks of professional services; you deploy in 1 hour. |
| Orchestration | **Kubernetes + Helm Chart (Phase 3)** | Docker Compose maxes out at ~10K endpoints. Phase 3 customers (large banks, government) need K8s for scaling, HA, and their own internal deployment standards. Helm chart makes it deployable into existing K8s clusters. |
| Reverse Proxy | **Nginx** (included in Compose) | Serves the React frontend, terminates TLS for the API, provides health checks. |
| Secrets | **Environment variables + encrypted config** | MVP: `.env` file (gitignored). Phase 2: HashiCorp Vault integration. Phase 3: customer-managed vault BYO. |
| Logging | **Structured JSON to stdout** | Docker captures logs. No external log aggregator in MVP. Phase 3: Loki or ELK. |
| Monitoring | **Health endpoint + Celery Flower** | `/health` for liveness, Flower for Celery task monitoring. Phase 3: Prometheus + Grafana. |

---

### 1.5 System Dependencies (Bundled in Docker)

These are CLI tools bundled into the scanner worker Docker image. They are battle-tested — you are integrating, not rebuilding.

| Tool | Language | Purpose | Output |
|---|---|---|---|
| **tshark** (Wireshark) | C | Passive packet capture; required by pyshark | PCAP + live stream |
| **nmap** | C | Network endpoint discovery | XML/JSON via python-nmap |
| **openssl** | C | Certificate operations, PEM parsing | Text/JSON |
| **pqcscan** | Rust | ML-KEM/ML-DSA handshake detection | JSON |
| **testssl.sh** | Bash | Comprehensive TLS grading | JSON (`--jsonfile`) |
| **ssh-audit** | Python/Bash | SSH algorithm audit | JSON (`-j`) |

---

### 1.6 Python Library Stack

| Library | Purpose | Integration |
|---|---|---|
| **pyshark** | Passive/active packet analysis via tshark | Python import (requires tshark binary) |
| **cryptography** (pyca) | X.509 parsing, key analysis, PQC OID classification | Python import |
| **sslyze** | Deep TLS cipher suite/protocol analysis | Python API (not CLI) |
| **paramiko** | SSH transport / KEX enumeration | Python import |
| **scapy** | Packet crafting for PQC group probes | Python import |
| **python-nmap** | nmap wrapper for network discovery | Python import (requires nmap binary) |
| **dnspython** | DNS enumeration for target discovery | Python import |
| **httpx** | Async HTTP client (CT logs, API connectors) | Python import |
| **cyclonedx-python-lib** | CycloneDX CBOM generation | Python import |
| **weasyprint** | PDF report generation | Python import |

---

## 2. Project File & Folder Structure

```
pqcrypt-sentinel/
│
├── docker/                          # Dockerfiles and Compose configs
│   ├── Dockerfile.api               # FastAPI worker image
│   ├── Dockerfile.worker            # Celery worker image (heavier: tshark, nmap, pqcscan)
│   ├── Dockerfile.frontend          # Nginx + React static files
│   ├── nginx.conf                   # Reverse proxy config
│   └── docker-compose.yml           # Single-command deploy
│
├── backend/                         # Python backend
│   ├── pyproject.toml               # Python project config (PEP 621)
│   ├── requirements.txt             # Pinned dependencies
│   ├── requirements-dev.txt         # Test/lint/dev tools
│   │
│   ├── app/                         # FastAPI application
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI app factory, middleware, CORS
│   │   ├── config.py                # Pydantic Settings (env vars → typed config)
│   │   ├── dependencies.py          # Shared DI: DB session, current user, Redis
│   │   │
│   │   ├── auth/                    # Authentication & Authorization
│   │   │   ├── __init__.py
│   │   │   ├── router.py            # /api/v1/auth/* endpoints
│   │   │   ├── service.py           # Login, JWT creation, password hashing
│   │   │   ├── models.py            # SQLAlchemy: users, sessions, api_keys
│   │   │   ├── schemas.py           # Pydantic: LoginRequest, Token, UserOut
│   │   │   └── dependencies.py      # get_current_user, require_role
│   │   │
│   │   ├── api/                     # REST API routers
│   │   │   ├── __init__.py
│   │   │   ├── scans.py             # /api/v1/scans/*
│   │   │   ├── assets.py            # /api/v1/assets/*
│   │   │   ├── findings.py          # /api/v1/findings/*
│   │   │   ├── reports.py           # /api/v1/reports/*
│   │   │   ├── connectors.py        # /api/v1/connectors/*
│   │   │   ├── dashboard.py         # /api/v1/dashboard/*
│   │   │   ├── settings.py          # /api/v1/settings/*
│   │   │   └── users.py             # /api/v1/users/*
│   │   │
│   │   ├── services/                # Business logic (no HTTP, no SQL)
│   │   │   ├── __init__.py
│   │   │   ├── scan_orchestrator.py # Scan job lifecycle: create → queue → run → complete
│   │   │   ├── asset_service.py     # Asset CRUD, deduplication, enrichment
│   │   │   ├── finding_service.py   # Finding generation, status updates, assignment
│   │   │   ├── risk_service.py      # Multi-dimensional risk scoring engine
│   │   │   ├── report_service.py    # CBOM, PDF, CSV report generation
│   │   │   ├── connector_manager.py # Connector lifecycle, scheduling, sync
│   │   │   └── notification_service.py # Email/Slack/webhook for drift alerts
│   │   │
│   │   ├── scanners/                # Scanner worker implementations
│   │   │   ├── __init__.py
│   │   │   ├── base.py              # Abstract base scanner class
│   │   │   ├── tls_scanner.py       # Active TLS scan (sslyze + cryptography)
│   │   │   ├── ssh_scanner.py       # SSH audit (paramiko + ssh-audit CLI)
│   │   │   ├── passive_monitor.py   # pyshark SPAN/PCAP capture
│   │   │   ├── pqcprobe.py          # pqcscan CLI wrapper + scapy PQC group probes
│   │   │   ├── cert_parser.py       # Deep X.509 parsing + PQC OID classification
│   │   │   ├── network_discovery.py # nmap + dnspython target discovery
│   │   │   ├── ct_log_monitor.py    # crt.sh CT log polling
│   │   │   └── scanner_registry.py  # Maps scan_type → scanner class
│   │   │
│   │   ├── connectors/              # External system integrations
│   │   │   ├── __init__.py
│   │   │   ├── base.py              # Abstract base connector
│   │   │   ├── servicenow.py        # ServiceNow CMDB REST API
│   │   │   ├── netbox.py            # NetBox REST API
│   │   │   ├── aws_connector.py     # AWS Config / KMS / ACM
│   │   │   ├── azure_connector.py   # Azure Resource Graph / Key Vault
│   │   │   ├── gcp_connector.py     # GCP Asset Inventory / KMS
│   │   │   ├── ad_cs.py             # AD CS LDAP query
│   │   │   └── vault_pki.py         # HashiCorp Vault PKI
│   │   │
│   │   ├── analysis/                # Analysis engine
│   │   │   ├── __init__.py
│   │   │   ├── algo_classifier.py   # Maps algorithm → PQC status (vulnerable/hybrid/pqc_ready)
│   │   │   ├── risk_scorer.py       # Multi-dimensional risk score calculation
│   │   │   ├── mosca_model.py       # HNDL timeline: data_longevity vs quantum_timeline
│   │   │   ├── vendor_db.py         # Vendor PQC readiness knowledge base
│   │   │   └── diff_engine.py       # Scan-over-scan comparison / drift detection
│   │   │
│   │   └── models/                  # SQLAlchemy ORM models
│   │       ├── __init__.py
│   │       ├── user.py              # User, Session, ApiKey
│   │       ├── asset.py             # Asset
│   │       ├── certificate.py       # Certificate
│   │       ├── algorithm.py         # Algorithm (per-scan record)
│   │       ├── finding.py           # Finding
│   │       ├── scan.py              # Scan, ScanLog
│   │       ├── connector.py         # Connector
│   │       ├── relationship.py      # AssetRelationship
│   │       ├── migration.py         # MigrationProgress
│   │       └── report.py            # Report
│   │
│   ├── workers/                     # Celery worker entrypoints
│   │   ├── __init__.py
│   │   ├── celery_app.py            # Celery app config (Redis broker, result backend)
│   │   ├── scan_worker.py           # Task: execute_scan(scan_id)
│   │   ├── passive_worker.py        # Task: passive_capture_task(scan_id)
│   │   └── connector_worker.py      # Task: run_connector_sync(connector_id)
│   │
│   ├── alembic/                     # Database migrations
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/                # Migration files (auto-generated)
│   │
│   ├── tests/                       # Backend tests
│   │   ├── __init__.py
│   │   ├── conftest.py              # pytest fixtures: DB, test client, mock scanner
│   │   ├── unit/
│   │   │   ├── test_risk_scorer.py
│   │   │   ├── test_algo_classifier.py
│   │   │   ├── test_mosca_model.py
│   │   │   └── test_vendor_db.py
│   │   ├── integration/
│   │   │   ├── test_auth_api.py
│   │   │   ├── test_scan_api.py
│   │   │   ├── test_asset_api.py
│   │   │   └── test_finding_api.py
│   │   └── scanner/
│   │       ├── test_tls_scanner.py
│   │       ├── test_cert_parser.py
│   │       └── test_ssh_scanner.py
│   │
│   └── scripts/                     # Utility scripts
│       ├── seed_dev_data.py         # Populate dev DB with sample assets
│       ├── migrate_pqc_oids.py      # Migrate OID table (if externalized)
│       └── backup_db.sh              # pg_dump wrapper
│
├── frontend/                        # React frontend
│   ├── index.html                   # Entry HTML
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── postcss.config.js
│   │
│   ├── public/
│   │   └── favicon.ico
│   │
│   ├── src/
│   │   ├── main.tsx                 # React entry point
│   │   ├── App.tsx                  # Root component + routing
│   │   ├── vite-env.d.ts
│   │   │
│   │   ├── lib/                     # Core utilities
│   │   │   ├── api-client.ts        # Axios/TanStack Query client factory
│   │   │   ├── auth.ts              # Token storage, login/logout helpers
│   │   │   └── constants.ts          # PQC OID maps, severity constants
│   │   │
│   │   ├── stores/                  # Zustand stores (if needed for non-server state)
│   │   │   └── auth-store.ts
│   │   │
│   │   ├── hooks/                   # Custom React hooks
│   │   │   ├── use-scans.ts
│   │   │   ├── use-assets.ts
│   │   │   └── use-websocket.ts     # Scan progress WebSocket hook
│   │   │
│   │   ├── components/              # Shared UI components
│   │   │   ├── ui/                  # shadcn/ui primitives (Button, Card, Table, etc.)
│   │   │   ├── layout/
│   │   │   │   ├── AppShell.tsx     # Sidebar + header + content wrapper
│   │   │   │   ├── Sidebar.tsx      # Collapsible navigation sidebar
│   │   │   │   └── Header.tsx       # Breadcrumb, user menu
│   │   │   ├── charts/
│   │   │   │   ├── RiskGauge.tsx    # Circular gauge for PQC readiness score
│   │   │   │   ├── RiskDonut.tsx    # Donut: critical/high/medium/low/pqc-ready
│   │   │   │   ├── MigrationTrend.tsx # Line chart: % ready over time
│   │   │   │   └── HNDLTimeline.tsx  # Bar chart: assets by HNDL urgency
│   │   │   ├── severity-badge.tsx
│   │   │   ├── pqc-status-badge.tsx
│   │   │   ├── scan-status-badge.tsx
│   │   │   └── asset-table.tsx      # Reusable filterable/sortable table
│   │   │
│   │   ├── pages/                   # Screen-level components
│   │   │   ├── login/
│   │   │   │   └── LoginPage.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── ExecutiveDashboard.tsx
│   │   │   │   └── OperationalDashboard.tsx
│   │   │   ├── assets/
│   │   │   │   ├── AssetExplorer.tsx
│   │   │   │   └── AssetDetail.tsx
│   │   │   ├── findings/
│   │   │   │   ├── FindingsList.tsx
│   │   │   │   └── FindingDetail.tsx
│   │   │   ├── scans/
│   │   │   │   ├── ScanList.tsx
│   │   │   │   └── ScanDetail.tsx
│   │   │   ├── reports/
│   │   │   │   └── ReportsPage.tsx
│   │   │   ├── migration/
│   │   │   │   └── MigrationProgress.tsx
│   │   │   ├── connectors/
│   │   │   │   └── ConnectorsPage.tsx
│   │   │   └── settings/
│   │   │       ├── GeneralSettings.tsx
│   │   │       ├── UserManagement.tsx
│   │   │       └── CredentialProfiles.tsx
│   │   │
│   │   └── styles/
│   │       ├── index.css            # Tailwind directives + design tokens
│   │       └── global.css
│   │
│   ├── __tests__/                   # Frontend tests
│   │   ├── login.test.tsx
│   │   └── scan-create.test.tsx
│   │
│   └── e2e/                         # Playwright E2E tests
│       ├── auth.spec.ts
│       ├── scan-flow.spec.ts
│       └── report-export.spec.ts
│
├── docs/                            # Documentation
│   ├── api-reference.md             # Generated from OpenAPI spec
│   ├── deployment-guide.md          # Air-gap, on-prem install
│   ├── connector-setup.md           # ServiceNow, AWS, Azure, etc.
│   └── user-guide.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Lint → test → build → docker push
│       ├── security.yml             # Trivy scan, Snyk dependency check
│       └── deploy-staging.yml
│
├── .pre-commit-config.yaml          # Black, Ruff, ESLint, MyPy, prettier
├── pyproject.toml                   # Root Python project config
├── package.json                     # Root (if using workspaces/monorepo)
├── docker-compose.yml               # Production-ready compose file
├── .env.example                     # Template for all required environment variables
├── .gitignore
└── README.md
```

---

### Key Design Choices in Folder Structure

1. **`scanners/` vs `connectors/` separation**: Scanners actively probe targets (TLS, SSH, network). Connectors pull data from external systems (CMDBs, cloud APIs). Keeping them separate prevents accidental credential escalation.

2. **`services/` is pure business logic**: No HTTP, no SQL imports. Easier to unit test. The API routers are thin (parse request → call service → return response).

3. **`workers/` is Celery entry only**: All heavy scan logic lives in `scanners/` and is callable from both sync (API) and async (Celery) contexts.

4. **Frontend `pages/` vs `components/`**: `components/` are reusable (charts, tables, badges). `pages/` are route-level compositions. This prevents the "everything is a component" sprawl.

5. **`docker/` isolated**: Dockerfiles and Compose are in their own folder. The Compose file lives at repo root for `docker-compose up` simplicity.

---

## 3. Database Schema (Plain English)

### The 11 Core Tables — What They Represent

---

#### `users` — "Who logs in"

> Think of this as your building's access card system. Each person who uses the platform has one row here: their email, a hashed password (never plain text), their display name, and their role. The role determines what they can see and do. A "viewer" can look at dashboards but cannot run scans or change settings. An "admin" can do everything. There is also a soft-delete field — when someone leaves, you mark `deleted_at` instead of erasing their scan history.

**Key columns:** `email` (unique login), `password_hash` (bcrypt, never reversible), `role` (admin/analyst/viewer/api), `is_active` (disable without deleting).

---

#### `connectors` — "External systems we talk to"

> Each row represents one integration connection: a ServiceNow instance, an AWS account, a Vault PKI, a NetBox server. The `config` JSONB column holds connection details (URLs, region names, table mappings) — things that are not secrets. Actual credentials (passwords, API keys, tokens) are never stored here; instead `credentials_ref` points to a secret in an external vault. The `status` field tracks health: is this connector connected, erroring out, or disabled? Scheduled syncs use the `sync_schedule` cron field.

**Key columns:** `connector_type` (servicenow/aws/azure/ad_cs/etc.), `config` (JSONB - URLs and settings), `credentials_ref` (vault path, not the secret itself), `status` (pending/connected/error/disabled), `last_sync_at`.

---

#### `scans` — "Scan job records"

> Every time someone clicks "Run Scan" or a scheduled scan fires, one row is created here. It's the job ticket: what type of scan (full/TLS-only/SSH-only/targeted), what was the target (IP range, domain list, or "all known"), what status is it in (queued/running/completed/failed/cancelled), and when did it start and finish. The `results` JSONB column holds the aggregated scan output — algorithm counts, asset counts, summary stats. Scan records are **never edited** after creation. A new scan creates a new row. This append-only pattern is what enables scan-over-scan diff and migration progress tracking.

**Key columns:** `scan_type`, `target`, `status`, `config` (JSONB - throttle rate, timeout, credential profile), `assets_found`, `findings_created`, `duration_seconds`, `created_by`.

---

#### `assets` — "Servers, endpoints, services — everything with crypto"

> This is the heart of the platform. Every TLS endpoint, SSH server, HSM, KMS key, database, load balancer — anything that uses or stores a key — is an asset. Each asset has a type (server/vpn_gateway/hsm/kms/certificate_authority/etc.), network location (IP address, FQDN, port), who owns it (`owner_id` → users), and what business service it belongs to (e.g., "Payments", "Customer Portal", "Infrastructure"). The `discovery_source` field remembers how we found it: was it from a TLS scan? A CMDB pull? A CT log entry? This matters for trust weighting — a directly-scanned asset is more reliable than a CMDB-only entry. The `metadata` JSONB column stores flexible data: OS version, cloud region, Kubernetes namespace, etc. Soft deletes keep history intact.

**Key columns:** `asset_type` (18 possible types), `ip_address` (INET type, supports CIDR), `fqdn`, `port`, `environment` (production/staging/development/testing/unknown), `business_service`, `owner_id`, `discovery_source`, `first_scan_id`, `last_scan_id`, `metadata` (JSONB).

---

#### `certificates` — "X.509 certificates found on assets"

> Every TLS certificate discovered during scanning gets a row here. A single asset may have multiple certificates (e.g., a load balancer with certs for 50 different domains). The key fields are: `thumbprint` (SHA-256 fingerprint, unique across all certs), `subject` and `issuer` (who is this cert for, and who signed it), `sig_algorithm` (e.g., sha256WithRSAEncryption), `pub_key_algorithm` (RSA, EC, ML-DSA), `pub_key_size` (2048, 256, etc.), `not_before`/`not_after` (validity dates), `is_ca` (is this a CA certificate?), and crucially `pqc_capable` (does this cert use a PQC or hybrid algorithm?). The `pqc_details` JSONB stores the full PQC analysis: which OID was found, is it hybrid, what vendor support exists. The `raw_certificate` field stores the PEM text for re-analysis. A unique index on `thumbprint` prevents duplicate cert entries.

**Key columns:** `asset_id` (which asset has this cert), `thumbprint` (unique SHA-256), `sig_algorithm`, `pub_key_algorithm`, `pub_key_size`, `not_after` (for expiry alerting), `is_ca`, `pqc_capable`, `pqc_details` (JSONB), `chain_position` (leaf/intermediate/root).

---

#### `algorithms` — "Every algorithm found on an asset, per scan"

> Where `certificates` stores the cert, `algorithms` stores the individual algorithms discovered on that asset. One asset may have 10 algorithms: RSA-2048 for its TLS cert, X25519 for key exchange, AES-256-GCM for symmetric, SHA-384 for hashing. Each gets its own row. This table is **append-only and per-scan** — every new scan creates new rows. This lets you see how algorithms change over time. The `algorithm_type` categorizes: key_exchange, signature, symmetric, hash, mac, kem, composite. The `pqc_status` is the critical field: vulnerable / transitioning / hybrid / pqc_ready / safe. `is_quantum_vulnerable` is a boolean short-cut for "is this RSA or ECC?"

**Key columns:** `asset_id`, `scan_id`, `algorithm_name` (e.g., RSA-2048, ML-KEM-768), `algorithm_type`, `protocol` (TLS/SSH/IPsec/etc.), `protocol_version`, `cipher_suite` (full TLS cipher suite string), `pqc_status`, `is_quantum_vulnerable`, `oid` (algorithm OID from cert/scan).

---

#### `findings` — "Problems detected: weak crypto, expiring certs, HNDL risk"

> When the scanner identifies a problem, it creates a finding. This is the actionable item — the thing a human needs to review and fix. Finding types include: `weak_algorithm` (using RSA-2048), `weak_key_size` (1024-bit key), `cert_expiring` (cert expires before 2030), `pqc_downgrade` (server supports PQC but also allows classical fallback), `ssh_weak_kex`, `code_weak_crypto` (from SAST), and more. Each finding has a `severity` (critical/high/medium/low/info), a composite `risk_score` (0-100), and `hndl_exposure` (how much data-at-risk will be harvested now for future decryption). The `remediation` field gives concrete instructions: "Upgrade OpenSSL to 3.5+, reissue cert with ML-DSA-65". The `recommended_algorithm` field gives the direct replacement. Findings have a lifecycle: open → in_progress → resolved (or accepted as false positive / accepted risk). `assigned_to` links to the person responsible. Findings are never deleted — they are resolved or accepted.

**Key columns:** `asset_id`, `scan_id`, `finding_type`, `severity`, `risk_score` (0-100), `hndl_exposure` (high/medium/low/none), `evidence` (JSONB - raw scan output), `remediation`, `recommended_algorithm`, `status` (open/in_progress/resolved/accepted/false_positive), `assigned_to`, `ticket_id` (Jira/ServiceNow reference).

---

#### `scan_logs` — "Play-by-play of a scan execution"

> When a scan runs (which can take hours for 10K endpoints), every significant event is logged here: "Starting TLS probe of 10.0.0.1:443", "Certificate expired in 90 days", "Worker 3 timeout, retrying". This is the live log stream you see in the Scan Detail page. It's append-only. Logs are deleted after 90 days (configurable). The `level` field is the standard: debug/info/warn/error/fatal. The `phase` field tracks which part of the scan is running: discovery, analysis, or reporting.

**Key columns:** `scan_id`, `level`, `phase` (discovery/analysis/reporting), `message`, `details` (JSONB - structured extra data), `timestamp`.

---

#### `asset_relationships` — "How assets depend on each other"

> This is the dependency graph. An asset can `depends_on` another (web app depends on database), `connects_to` another (load balancer connects to web server), `signed_by` a CA certificate, `issued_by` a certificate authority, `managed_by` a KMS, or `hosts` a container. The `confidence` field (0.00 to 1.00) represents how sure we are this relationship exists — 1.00 for directly observed (we saw the TLS connection), 0.80 for inferred from CMDB data. `discovered_by` records the source: was it from a scan, from a CMDB relationship pull, or manually entered? The unique constraint on (source, target, type) prevents duplicates.

**Key columns:** `source_asset_id`, `target_asset_id`, `relationship_type` (depends_on/connects_to/authenticates_with/signed_by/issued_by/managed_by/runs_on/hosts/contains), `confidence` (0.0-1.0), `discovered_by` (scan_inference/cmdb/manual).

---

#### `migration_progress` — "How PQC-ready is each asset, over time"

> The migration tracker. Every time a scan completes, a new row is written per asset showing its current PQC readiness state. `pqc_readiness` goes through stages: not_started → assessed → planned → in_progress → migrated → verified. The counts (`vulnerable_algorithms`, `hybrid_algorithms`, `pqc_algorithms`, `safe_algorithms`) show the algorithm breakdown at that point in time. `readiness_score` (0-100) is the percentage of algorithms that are hybrid or PQC-ready. By querying this table over time for a given asset, you can draw the migration trend line. This is what CISOs show to the board to prove progress.

**Key columns:** `asset_id`, `scan_id`, `pqc_readiness` (not_started/assessed/planned/in_progress/migrated/verified), `vulnerable_algorithms`, `hybrid_algorithms`, `pqc_algorithms`, `safe_algorithms`, `readiness_score` (0-100).

---

#### `reports` — "Generated report catalog"

> Every time a user generates a report (CBOM, executive summary, compliance NIST report, migration progress), a row is created here. The `report_type` field categorizes it: cbom, executive, compliance_nist, compliance_cisa, compliance_ncsc, compliance_dora, compliance_rbi, migration_progress, raw_data. The `format` is json/pdf/csv. `scope` (JSONB) remembers what filters were applied — e.g., "all production assets in Payments business service". The `file_path` points to the generated file on disk. `status` tracks generation: pending → generating → ready → failed.

**Key columns:** `report_type`, `format`, `scope` (JSONB), `file_path`, `file_size_bytes`, `status`, `generated_by`.

---

#### `api_keys` — "Programmatic access tokens"

> For CI/CD integration and programmatic access, users generate API keys. The actual key is shown once at creation time and stored as a `key_hash` (bcrypt, like passwords). The `scopes` array defines what the key can do: `scans:read`, `assets:read`, `findings:write`, etc. `last_used_at` tracks when the key was last used for audit purposes. `expires_at` allows time-limited keys.

**Key columns:** `user_id`, `name`, `key_hash` (bcrypt, not plaintext), `scopes` (TEXT[]), `last_used_at`, `expires_at`, `is_active`.

---

### 3.1 Entity Relationship Summary (Plain English)

```
users
  │  owns (via owner_id)
  ├──► assets                      (a person owns many assets)
  │     │  discovered_in
  │     ├──► scans                 (a scan discovers many assets)
  │     │     │  produces
  │     │     ├──► scan_logs       (a scan produces many log entries)
  │     │     │  generates
  │     │     └──► findings        (a scan generates many findings)
  │     │
  │     ├──► certificates          (an asset presents many certificates)
  │     │     │
  │     │     └──► (thumbprint links to CA certs in same table)
  │     │
  │     ├──► algorithms            (a scan finds many algorithms on an asset)
  │     │
  │     └──► asset_relationships   (an asset depends_on / connects_to / signed_by others)
  │
  ├──► connectors                  (a user configures many connectors)
  │
  ├──► reports                     (a user generates many reports)
  │
  └──► api_keys                    (a user creates many API keys)

scans
  │  tracks_progress_for
  └──► migration_progress          (each scan creates a migration snapshot per asset)

findings
  │  assigned_to
  └──► users                       (a finding is assigned to one person)
```

---

### 3.2 Critical Design Patterns

**Append-only evidence:** Scan results, algorithms, scan_logs, and migration_progress rows are never updated or deleted. New scans create new rows. This gives you:
- Complete audit trail (regulators love this)
- Scan-over-scan diff (what changed since last week?)
- No write conflicts when multiple workers run concurrently

**Soft deletes:** Users, connectors, assets, certificates, findings, and relationships all have `deleted_at`. Deleted = hidden from queries but kept in the database. Allows data recovery and preserves referential integrity.

**JSONB for flexibility:** Algorithm details, cert PQC analysis, scan configs, asset metadata, evidence payloads — all JSONB. This means you can add new fields (e.g., a new PQC algorithm OID) without running a migration. Structured enough to query, flexible enough to evolve.

**Temporal tracking:** Every meaningful entity has `created_at` and `updated_at`. Assets additionally track `first_scan_id`, `last_scan_id`, `first_discovered_at`, `last_verified_at`. This is what makes the migration progress dashboard possible.

---

### 3.3 JSONB Column Schemas (Documented Contracts)

These are the expected shapes for JSONB columns — treat them as internal APIs between the scanner engine and the database layer.

**`assets.metadata`** — Flexible asset enrichment:
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
  "tags": ["production", "pci-scope"],
  "hndl_data_longevity_years": 50,
  "business_criticality_tier": "tier_1"
}
```

**`certificates.pqc_details`** — PQC analysis result:
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
  },
  "detection_method": "oid_match",
  "confidence": 1.0
}
```

**`findings.evidence`** — Raw evidence for audit trail:
```json
{
  "tool": "sslyze",
  "tool_version": "6.0.0",
  "raw_output": "Protocol: TLS 1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384...",
  "cert_thumbprint": "AB:CD:EF:12:34:56:78:90:...",
  "config_line": "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1",
  "negotiated_kex": "X25519",
  "offered_pqc_groups": [],
  "downgrade_possible": true
}
```

**`scans.config`** — Scan configuration snapshot:
```json
{
  "throttle_rate": 50,
  "timeout_seconds": 10,
  "ports": [443, 8443, 22, 636],
  "credential_profile": "default-servicenow",
  "passive_interface": "eth0",
  "include_ct_logs": true,
  "include_dns": true
}
```

**`connectors.config`** — Non-secret connection configuration:
```json
{
  "instance_url": "https://sbi.service-now.com",
  "table_prefix": "u_pqc",
  "sync_interval_hours": 24,
  "ci_classes": ["cmdb_ci_server", "cmdb_ci_software_instance"],
  "query_filter": "install_status=1"
}
```

**`scans.results`** — Aggregated scan output:
```json
{
  "summary": {
    "total_hosts_scanned": 1024,
    "tls_endpoints_found": 847,
    "ssh_endpoints_found": 312,
    "certificates_collected": 1567,
    "vulnerable_assets": 423,
    "hybrid_assets": 89,
    "pqc_ready_assets": 12
  },
  "algorithms_breakdown": {
    "RSA-2048": 312,
    "ECDSA-P256": 287,
    "X25519": 445,
    "AES-256-GCM": 1024
  },
  "top_findings": [...]
}
```

---

## 4. Environment Variables & Configuration

### 4.1 Core Application

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_ENV` | Yes | `development` | Environment: `development`, `staging`, `production` |
| `APP_NAME` | No | `PQCrypt Sentinel` | Display name |
| `SECRET_KEY` | **Yes** | — | JWT signing secret. 32+ random bytes. **Rotate on a schedule.** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | No | `7` | JWT refresh token lifetime |
| `CORS_ORIGINS` | No | `http://localhost:5173` | Comma-separated allowed origins |
| `API_WORKERS` | No | `4` | Uvicorn worker count |
| `LOG_LEVEL` | No | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |

### 4.2 Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | **Yes** | — | PostgreSQL connection string: `postgresql+asyncpg://user:pass@host:5432/pqcrypt` |
| `DB_POOL_SIZE` | No | `20` | SQLAlchemy connection pool size |
| `DB_MAX_OVERFLOW` | No | `10` | Max overflow connections above pool size |

### 4.3 Redis / Celery

| Variable | Required | Default | Description |
|---|---|---|---|
| `REDIS_URL` | **Yes** | — | Redis connection: `redis://host:6379/0` |
| `CELERY_BROKER_URL` | No | (from REDIS_URL) | Celery broker — usually same as Redis |
| `CELERY_RESULT_BACKEND` | No | (from REDIS_URL) | Celery result store |
| `CELERY_WORKER_CONCURRENCY` | No | `4` | Concurrent tasks per worker |
| `CELERY_BEAT_SCHEDULE` | No | (see below) | Cron schedule for periodic scans |

### 4.4 Scanner Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SCAN_THROTTLE_RATE` | No | `50` | Max probes per second per target (rate limiting) |
| `SCAN_TIMEOUT_SECONDS` | No | `10` | Per-endpoint scan timeout |
| `SCAN_DEFAULT_PORTS` | No | `443,8443,22,636,993,995,8883` | Comma-separated port list |
| `SCAN_RESULT_RETENTION_DAYS` | No | `730` | Evidence retention (2 years default) |
| `SCAN_LOG_RETENTION_DAYS` | No | `90` | Scan log retention |
| `TSHARK_PATH` | No | `tshark` | Path to tshark binary (for pyshark) |
| `NMAP_PATH` | No | `nmap` | Path to nmap binary |
| `OPENSSL_PATH` | No | `openssl` | Path to openssl binary |
| `PQSCAN_PATH` | No | `/usr/local/bin/pqcscan` | Path to pqcscan binary |
| `TESTSSL_PATH` | No | `/usr/local/bin/testssl.sh` | Path to testssl.sh |
| `SSH_AUDIT_PATH` | No | `/usr/local/bin/ssh-audit` | Path to ssh-audit |

### 4.5 SMTP / Notifications

| Variable | Required | Default | Description |
|---|---|---|---|
| `SMTP_HOST` | No | — | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USER` | No | — | SMTP username |
| `SMTP_PASSWORD` | No | — | SMTP password |
| `SMTP_FROM_ADDRESS` | No | — | From address for notification emails |
| `SLACK_WEBHOOK_URL` | No | — | Slack webhook for drift alerts |

### 4.6 Vault Integration (Phase 2)

| Variable | Required | Default | Description |
|---|---|---|---|
| `VAULT_URL` | No | — | HashiCorp Vault address |
| `VAULT_TOKEN` | No | — | Vault auth token |
| `VAULT_NAMESPACE` | No | — | Vault namespace (for Vault Enterprise) |
| `VAULT_PQC_PATH` | No | `secret/pqc` | Root path for scanner secrets in Vault |

### 4.7 Air-Gap / Offline Mode

| Variable | Required | Default | Description |
|---|---|---|---|
| `OFFLINE_MODE` | No | `false` | When true, disables CT log polling, telemetry, external API calls |
| `CT_LOG_URL` | No | `https://crt.sh` | CT log endpoint (disabled in offline mode) |
| `TELEMETRY_ENABLED` | No | `false` | When true, sends usage stats (disabled by default — data residency requirement) |

### 4.8 Celery Beat Scheduled Tasks (Default Schedule)

Defined in `celery_app.py` — these are the periodic scan schedules:

| Task | Schedule | Description |
|---|---|---|
| `run_ct_log_monitor` | Every 6 hours | Poll crt.sh for new certificates |
| `run_connector_sync` | Every 24 hours | Sync all active CMDB/cloud connectors |
| `run_expiry_check` | Every 12 hours | Alert on certs expiring within 90 days |
| `run_drift_check` | Every 24 hours | Compare current scan vs previous, alert on regressions |
| `purge_old_logs` | Weekly | Delete scan_logs older than retention period |

---

### 4.9 `.env.example` (Complete Template)

```bash
# ─── Core ───
APP_ENV=development
APP_NAME=PQCrypt Sentinel
SECRET_KEY=change-me-generate-with-openssl-rand-hex-32
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
API_WORKERS=4
LOG_LEVEL=INFO

# ─── Database ───
DATABASE_URL=postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10

# ─── Redis ───
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
CELERY_WORKER_CONCURRENCY=4

# ─── Scanner Tools (paths inside Docker container) ───
TSHARK_PATH=/usr/bin/tshark
NMAP_PATH=/usr/bin/nmap
OPENSSL_PATH=/usr/bin/openssl
PQSCAN_PATH=/usr/local/bin/pqcscan
TESTSSL_PATH=/usr/local/bin/testssl.sh
SSH_AUDIT_PATH=/usr/local/bin/ssh-audit

# ─── Scan Settings ───
SCAN_THROTTLE_RATE=50
SCAN_TIMEOUT_SECONDS=10
SCAN_DEFAULT_PORTS=443,8443,22,636,993,995,8883
SCAN_RESULT_RETENTION_DAYS=730
SCAN_LOG_RETENTION_DAYS=90

# ─── Notifications ───
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM_ADDRESS=
SLACK_WEBHOOK_URL=

# ─── Vault (Phase 2) ───
VAULT_URL=
VAULT_TOKEN=
VAULT_NAMESPACE=
VAULT_PQC_PATH=secret/pqc

# ─── Offline Mode ───
OFFLINE_MODE=false
CT_LOG_URL=https://crt.sh
TELEMETRY_ENABLED=false
```

---

## 5. Architecture Overview

> Full system architecture with data flow described in plain English. See section 5 of this document.

The architecture is a **modular monolith** — one deployable unit, clear internal boundaries. This is a deliberate choice: a single `docker-compose up` is a core product feature, and a 2-5 person team doesn't benefit from microservices overhead.

```
                    ┌─────────────────────────────────┐
                    │       Browser (React SPA)       │
                    │    shadcn/ui + Tailwind + TS    │
                    └──────────────┬──────────────────┘
                                   │ HTTPS (TLS 1.3)
                                   │
                    ┌──────────────▼──────────────────┐
                    │       Nginx (Reverse Proxy)     │
                    │   Serves React + API proxy      │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │     FastAPI Application Server  │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │   API Routers (thin)      │  │
                    │  │   scans / assets /        │  │
                    │  │   findings / reports /    │  │
                    │  │   connectors / auth       │  │
                    │  └───────────┬───────────────┘  │
                    │              │                  │
                    │  ┌───────────▼───────────────┐  │
                    │  │   Service Layer            │  │
                    │  │   (business logic,         │  │
                    │  │    no HTTP, no SQL)        │  │
                    │  └───────────┬───────────────┘  │
                    │              │                  │
                    │  ┌───────────▼───────────────┐  │
                    │  │   SQLAlchemy ORM           │  │
                    │  │   (asyncpg driver)         │  │
                    │  └───────────┬───────────────┘  │
                    │              │                  │
                    └──────────────┼──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │     PostgreSQL 16               │
                    │     (11 tables + indexes)       │
                    │     JSONB for flexible fields    │
                    └─────────────────────────────────┘

                    ┌─────────────────────────────────┐
                    │     Redis 7+                     │
                    │     (Celery broker + cache)      │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │     Celery Worker(s)            │
                    │     (scanner execution)         │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │   Scanner Engine           │  │
                    │  │   ┌─────┐ ┌─────┐ ┌─────┐ │  │
                    │  │   │ TLS │ │ SSH │ │Pcap │ │  │
                    │  │   │scan │ │scan │ │/PQC │ │  │
                    │  │   └─────┘ └─────┘ └─────┘ │  │
                    │  │   ┌─────────────────────┐ │  │
                    │  │   │ Analysis Engine      │ │  │
                    │  │   │ RiskScorer +         │ │  │
                    │  │   │ AlgoClassifier +    │ │  │
                    │  │   │ MoscaModel +        │ │  │
                    │  │   │ DiffEngine          │ │  │
                    │  │   └─────────────────────┘ │  │
                    │  └───────────────────────────┘  │
                    └─────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │  External Targets               │
                    │  (scanned systems)              │
                    │  TLS endpoints, SSH servers,    │
                    │  HSMs, cloud APIs, CMDBs        │
                    └─────────────────────────────────┘
```

### How a Scan Works (End-to-End)

1. **User action**: Security analyst clicks "Run Scan" on the dashboard, selects target IP range.
2. **API creates job**: `POST /api/v1/scans` creates a `scans` row with status `queued`. Returns scan_id immediately.
3. **Celery picks up task**: The Celery worker picks the task from Redis. Status changes to `running`.
4. **Discovery phase**: The scanner resolves targets — nmap port scan + DNS enumeration to find live endpoints.
5. **Probe phase**: For each live endpoint, the appropriate scanner runs:
   - Port 443/8443 → TLS scanner (sslyze + cryptography + pqcscan)
   - Port 22 → SSH scanner (paramiko + ssh-audit)
   - Passive: pyshark captures if SPAN port configured
6. **Analysis phase**: Raw scan output is parsed. Algorithms are classified. Certificates are parsed for PQC OIDs. Findings are generated.
7. **Scoring phase**: Risk score calculated per asset using HNDL exposure, business criticality, algorithm vulnerability, and regulatory deadline.
8. **Storage phase**: All results are appended — new `algorithms` rows, new `findings`, updated `migration_progress`.
9. **Notification phase**: If drift detected (asset regressed), send Slack/email alert.
10. **WebSocket push**: Scan detail page receives real-time progress updates. When scan completes, dashboard auto-refreshes.

---

## 6. Deployment Topology

### MVP: Single Docker Compose (1 VM, 8 CPU, 16 GB RAM)

```
                    ┌─────────────────────────────────────────────┐
                    │           Single Server / VM                  │
                    │         (8 CPU, 16 GB RAM, 200 GB disk)      │
                    │                                              │
                    │  ┌─────────────────────────────────────┐     │
                    │  │  docker-compose.yml                 │     │
                    │  │                                     │     │
                    │  │  ┌─────────┐ ┌──────┐ ┌─────────┐  │     │
                    │  │  │ Nginx   │ │ Redis│ │Postgres │  │     │
                    │  │  │ :80/:443│ │ :6379│ │  :5432  │  │     │
                    │  │  └────┬────┘ └──┬───┘ └────┬────┘  │     │
                    │  │       │         │         │        │     │
                    │  │  ┌────▼────┐    │  ┌─────▼────┐  │     │
                    │  │  │ FastAPI │◄───┘  │ Celery   │  │     │
                    │  │  │ :8000   │       │ Worker   │  │     │
                    │  │  └─────────┘       │ (+ Beat) │  │     │
                    │  │                    └──────────┘  │     │
                    │  │  ┌─────────────────────────────┐  │     │
                    │  │  │ React (static files)         │  │     │
                    │  │  │ served by Nginx             │  │     │
                    │  │  └─────────────────────────────┘  │     │
                    │  └─────────────────────────────────────┘     │
                    │                                              │
                    │  Volume mounts:                              │
                    │  - pgdata/         → PostgreSQL data          │
                    │  - redis-data/     → Redis persistence        │
                    │  - scan-results/   → Raw scan outputs         │
                    │  - reports/        → Generated reports        │
                    └──────────────────────────────────────────────┘
```

### Phase 3: Kubernetes (Large Enterprise)

```
                    ┌─────────────────────────────────────────────┐
                    │           Kubernetes Cluster                 │
                    │                                              │
                    │  ┌──────────┐  ┌─────────────────────────┐  │
                    │  │ Ingress   │  │      Services            │  │
                    │  │ (NGINX    │  │  api-svc     :8000      │  │
                    │  │  Contour) │  │  worker-svc  :celery    │  │
                    │  └─────┬────┘  │  frontend-svc :80       │  │
                    │        │       └─────────────────────────┘  │
                    │        │                                      │
                    │  ┌─────▼──────────────────────────────────┐  │
                    │  │  api-deployment (3 replicas)            │  │
                    │  │  worker-deployment (5+ replicas)        │  │
                    │  │  frontend-deployment (2 replicas)       │  │
                    │  └────────────────────────────────────────┘  │
                    │                                              │
                    │  ┌────────────────────────────────────────┐  │
                    │  │  StatefulSet: PostgreSQL (HA)           │  │
                    │  │  StatefulSet: Redis (HA / Sentinel)     │  │
                    │  └────────────────────────────────────────┘  │
                    │                                              │
                    │  ┌────────────────────────────────────────┐  │
                    │  │  PersistentVolumeClaims                 │  │
                    │  │  - pgdata (100 GB, SSD)                 │  │
                    │  │  - scan-results (500 GB, HDD)           │  │
                    │  │  - reports (50 GB, HDD)                 │  │
                    │  └────────────────────────────────────────┘  │
                    └──────────────────────────────────────────────┘
```

---

## 7. Security Model

### 7.1 Authentication (MVP)

```
POST /api/v1/auth/login
  Input:  { "email": "...", "password": "..." }
  Verify: bcrypt(password, stored_hash)
  Output: {
    "access_token": "<JWT, expires 1h>",
    "refresh_token": "<JWT, expires 7d>",
    "token_type": "bearer"
  }
```

- Passwords: bcrypt hash, cost factor 12.
- Access tokens: HS256 JWT, 1 hour expiry. Payload: `sub` (user id), `role`, `exp`.
- Refresh tokens: Longer-lived JWT, stored in httpOnly secure cookies (not localStorage).
- All API endpoints require `Authorization: Bearer <access_token>` header except `/health` and `/api/v1/auth/login`.

### 7.2 Authorization (RBAC)

Every endpoint uses dependency injection to check the current user's role:

| Role | What they can do |
|---|---|
| **admin** | Full access: manage users, connectors, scans, settings. Delete data. |
| **analyst** | Run scans, view/edit findings, create reports, manage connectors (read + test). |
| **viewer** | Read-only: dashboards, assets, findings, reports. Cannot run scans. |
| **api** | Scoped programmatic access via API keys. Scopes defined per key. |

Implementation: FastAPI dependency `require_role("admin")` used as a route decorator.

### 7.3 Credential Security

- **Never stored in the database.** Connector credentials exist in external vaults (HashiCorp Vault Phase 2, env vars in MVP).
- `credentials_ref` in the `connectors` table is just a path/label pointing to the vault location — not the credential itself.
- Scan workers fetch credentials at runtime from the vault just before use, never write them to logs or the evidence store.
- Scan output sanitization: before storing raw tool output in `findings.evidence` or `scans.results`, strip any embedded credentials (regex patterns for passwords, tokens, private keys).

### 7.4 Scanner Network Isolation (Phase 2)

The `scanner` worker container should run in a separate Docker network or Kubernetes namespace from the API. This limits blast radius if a scan target is malicious. The scanner worker has outbound network access; the API does not initiate scans directly.

### 7.5 Data Residency

- `OFFLINE_MODE=true` disables all external API calls (CT log, telemetry, vendor database updates).
- No data leaves the customer's network in the default configuration.
- No "phone home" — the product works entirely without internet access.

---

## 8. Key Design Decisions

### ADR-001: Modular Monolith, Not Microservices

**Decision:** Single deployable with clear internal module boundaries.

**Rationale:** The product requirement is a single `docker-compose up` command. Microservices add operational complexity (service mesh, inter-service auth, distributed tracing) that a 2-5 person team cannot absorb in 20 weeks. Internal boundaries (scanner/, services/, connectors/) are enforced by Python package structure, not runtime processes. These boundaries can become separate services later — Python packages are already importable from other processes.

### ADR-002: Integrate Open-Source Tools, Don't Rebuild

**Decision:** Wrap `sslyze`, `pyshark`, `paramiko`, `pqcscan`, `ssh-audit`, etc. as library imports and CLI subprocess calls.

**Rationale:** TLS and SSH protocol analysis is a 20+ year problem. The open-source tools represent millions of engineering hours. Reimplementing them introduces bugs in cryptography — which is the one domain where bugs can be catastrophic. The unique value of PQCrypt Sentinel is in the reconciliation layer: taking outputs from 6 different tools, deduplicating assets, scoring risk, tracking migration, and presenting it in a compliance-ready format.

### ADR-003: Append-Only Evidence Store

**Decision:** Scan results and algorithms are never updated or deleted. New scans create new rows.

**Rationale:** Enables scan-over-scan diff (the core of migration tracking), provides complete audit trail required for regulatory compliance (NIST, DORA, UK-NCSC, EU NIS2), eliminates write conflicts in concurrent scan workers, and preserves historical data for trend analysis. The cost is larger database size — mitigated by the 2-year retention policy.

### ADR-004: Tiered Access Model for Scanner Credentials

**Decision:** Every scan operation declares a required access tier (Tier 0-4). The scanner enforces credential-tier matching.

**Rationale:** Running a TLS probe requires no credentials (Tier 0 — unauthenticated). Scanning a CMDB requires a read-only service account (Tier 1). Querying TPM/Secure Boot requires local admin (Tier 2). Enumerating an HSM requires hardware access (Tier 3). Querying AWS KMS requires cloud control plane credentials (Tier 4). This prevents accidental use of high-privilege credentials for low-privilege operations, limits the blast radius of credential compromise, and makes the security model auditable.

### ADR-005: PostgreSQL as the Single Source of Truth

**Decision:** PostgreSQL is the primary data store. No secondary sync database.

**Rationale:** Adding Neo4j (for graph queries) or Elasticsearch (for search) creates sync complexity and operational overhead. PostgreSQL recursive CTEs handle graph traversal adequately up to ~10K assets. Full-text search via `pg_trgm` handles asset name/IP search. JSONB handles flexible scan output. Only add specialized stores when proven necessary — not prophylactically.

### ADR-006: Python Despite Performance Concerns

**Decision:** Python 3.12 for the backend despite its GIL and lower raw throughput vs Go/Rust.

**Rationale:** The bottleneck is I/O: network probes to TLS endpoints, CT log HTTP calls, cloud API queries — not CPU. Python's async (asyncio + asyncpg) handles I/O concurrency well. The Celery worker pool provides horizontal scaling for CPU-bound work. The developer productivity gain from Python's crypto library ecosystem (sslyze, pyshark, cryptography) vs the effort of building Go/Rust equivalents is roughly 3-6 months. For a 20-week MVP, Python is the right choice. Performance-critical sub-functions can be extracted to Rust later (using PyO3) if profiling proves necessary.

### ADR-007: On-Premise First, SaaS Later

**Decision:** MVP is self-hosted, on-premise, air-gap capable. Multi-tenant SaaS is Phase 4.

**Rationale:** The primary customers (financial services, government, defense, healthcare) require on-premise deployment for data residency. Global mid-market customers also prefer self-hosted to avoid sending crypto inventory data to third parties. Building SaaS-first would exclude your primary market. The Docker Compose deploy model serves both on-prem and cloud-hosted use cases — the only difference is whether the customer runs it or you do.

---

## Appendix: Rationale Against Common Alternatives

| Question | Answer |
|---|---|
| Why not Go for the backend? | Go is faster but lacks the crypto/security Python ecosystem. You'd need to reimplement or CGo-bind sslyze, pyshark, paramiko equivalents. 3-6 months of lost velocity. |
| Why not TypeScript backend (Node.js)? | Node has fewer mature async ORM and task queue options for this pattern. Python's asyncio + SQLAlchemy + Celery is a mature, well-documented triad. |
| Why not GraphQL? | REST is sufficient for 14 screen types. GraphQL adds N+1 risk and caching complexity. Defer to Phase 2 if frontend data fetching becomes complex. |
| Why not Terraform / IaC for deployment? | Docker Compose is the deployment surface for MVP. IaC (Terraform/Pulumi) is for cloud deployments, which are Phase 3+. |
| Why PostgreSQL over MongoDB? | Your data is inherently relational: assets → certificates → findings → algorithms. Joins on these are daily operations. PostgreSQL JSONB gives you the flexibility of document storage where you need it. |
| Why not a license key system for MVP? | MVP is self-hosted with local auth. License enforcement is a Phase 2 feature (user count, endpoint count limits). |

---

*End of Technical Architecture Document*
