# Technical Requirements Document (TRD)

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Engineering Team  
**Status:** Draft  

---

## 1. Overview

This document defines the technical architecture, stack decisions, infrastructure requirements, and engineering constraints for building the PQCrypt Sentinel PQC Discovery Platform. The system is designed as a self-hosted, agentless-first cryptographic discovery platform that deploys in under 1 hour and scales to enterprise environments with 100,000+ assets.

---

## 2. Frontend Stack

### Technology Choices

| Component | Technology | Rationale |
|---|---|---|
| **Framework** | React 18+ with TypeScript | Industry standard, large ecosystem, strong typing for complex data models |
| **UI Library** | shadcn/ui + Tailwind CSS | Accessible, composable components; avoids vendor lock-in of full UI frameworks |
| **Charting** | Recharts or Apache ECharts | Risk distribution, migration progress timelines, algorithm breakdowns |
| **Graph Visualization** | React Flow or D3.js force graph | Dependency/blast-radius visualization |
| **State Management** | Zustand or TanStack Query | Lightweight; server state managed via React Query |
| **Build Tool** | Vite | Fast HMR, native ESM, optimized builds |
| **Routing** | React Router v6 | Standard SPA routing |

### Frontend Requirements

- **Dashboard views:** Executive summary, operational findings, migration progress, scan coverage
- **Asset explorer:** Filterable, sortable table of all discovered crypto assets with drill-down
- **Findings detail:** Per-asset view showing algorithms, cert chain, PQC status, risk score, remediation
- **Dependency graph:** Interactive graph showing asset → cert → CA → business service relationships
- **Scan management:** Initiate scans, view history, compare scan results
- **CBOM export:** One-click CycloneDX JSON export
- **Responsive:** Desktop-first, tablet-compatible; mobile not required for MVP

---

## 3. Backend Stack

### Technology Choices

| Component | Technology | Rationale |
|---|---|---|
| **Language** | Python 3.12+ | Richest crypto/security tool ecosystem (cryptography, sslyze, nmap libs); fast prototyping |
| **Framework** | FastAPI | Async, high-performance, auto-generates OpenAPI docs, Pydantic validation |
| **Task Queue** | Celery with Redis broker | Distributed scan job execution, retry logic, scheduling |
| **Message Broker** | Redis 7+ | Celery broker, caching layer, session store |
| **ORM** | SQLAlchemy 2.0 | Mature, async support, migration tooling (Alembic) |
| **API Protocol** | REST (OpenAPI 3.1) | Broad client compatibility; GraphQL deferred to Phase 2+ |
| **WebSocket** | FastAPI WebSockets | Real-time scan progress updates to dashboard |

### Backend Architecture

```
┌─────────────────────────────────────────────────────┐
│                    API Layer (FastAPI)                │
│  /api/v1/scans  /api/v1/assets  /api/v1/findings    │
│  /api/v1/reports /api/v1/connectors /api/v1/auth     │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Service Layer (Business Logic)           │
│  ScanService  AssetService  FindingService           │
│  RiskService  ReportService  ConnectorService        │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Scanner Engine (Celery Workers)          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │  TLS    │ │  SSH    │ │pyshark  │ │  CT Log  │  │
│  │Scanner  │ │Scanner  │ │Passive  │ │  Monitor │  │
│  │(sslyze, │ │(paramiko│ │Monitor  │ │(crt.sh)  │  │
│  │pqcscan) │ │sshaudit)│ │(SPAN)   │ │          │  │
│  └─────────┘ └─────────┘ └─────────┘ └──────────┘  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │  Cert   │ │  Cloud  │ │  CMDB   │ │  SBOM    │  │
│  │ Parser  │ │Connector│ │Connector│ │  Ingest  │  │
│  │(crypto- │ │(boto3,  │ │(pysnow, │ │(Trivy,   │  │
│  │graphy)  │ │azure)   │ │netbox)  │ │CycloneDX)│  │
│  └─────────┘ └─────────┘ └─────────┘ └──────────┘  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Analysis Engine                         │
│  AlgorithmClassifier  RiskScorer  MoscaModel        │
│  DeduplicationEngine  RelationshipInferrer          │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Data Layer                              │
│  PostgreSQL (primary)  Redis (cache/queue)           │
│  Neo4j (Phase 3: graph)  Object Store (evidence)    │
└─────────────────────────────────────────────────────┘
```

---

## 4. Database

### Primary Database: PostgreSQL 16+

| Aspect | Decision | Rationale |
|---|---|---|
| **Engine** | PostgreSQL 16+ | JSONB support for flexible scan output, full-text search, mature, open-source |
| **Hosting** | Self-hosted in docker-compose | On-prem requirement; no external dependencies |
| **Migrations** | Alembic | Version-controlled schema changes |
| **Connection pool** | asyncpg via SQLAlchemy | Async performance for high-concurrency scan ingestion |

### Schema Design Principles

- **Append-only evidence store:** Scan results are never mutated; new scans produce new records
- **JSONB for flexible fields:** Algorithm details, cert metadata, scan output stored as JSONB
- **Normalized core entities:** Assets, certificates, findings, owners, business services as relational tables
- **Soft deletes:** All entities support archival, not hard deletion
- **Temporal tracking:** All records include `discovered_at`, `last_verified`, `scan_id` for time-series analysis

### Cache Layer: Redis 7+

- Celery task queue broker
- Session storage
- Dashboard widget caching (TTL: 5 min)
- Rate limiter state for scan pacing

### Graph Database: Neo4j (Phase 3)

- Dependency graph traversal (blast radius, impact analysis)
- Relationship inference from CMDB + scan data
- Deferred to Phase 3 due to operational complexity

---

## 5. Authentication & Authorization

### Authentication

| Method | Phase | Use Case |
|---|---|---|
| **Local username/password (bcrypt)** | MVP | Single-tenant, small teams |
| **SSO via OIDC/SAML** | Phase 2 | Enterprise integration (Okta, Entra ID, Keycloak) |
| **API keys (scoped)** | MVP | Programmatic access, CI/CD integration |

### Authorization: Role-Based Access Control (RBAC)

| Role | Permissions |
|---|---|
| **Admin** | Full access: manage users, connectors, scans, settings |
| **Security Analyst** | Run scans, view findings, create reports, manage tickets |
| **Viewer** | Read-only dashboards and reports |
| **API** | Programmatic access via API keys (scoped to specific operations) |

### Session Management

- JWT tokens with 1-hour expiry, refresh tokens with 7-day expiry
- Tokens stored in httpOnly cookies (not localStorage)
- All API endpoints require authentication except `/health` and `/api/v1/auth/login`

---

## 6. APIs

### Internal APIs (Frontend ↔ Backend)

All endpoints follow `/api/v1/` prefix with OpenAPI 3.1 auto-documentation.

| Resource | Endpoints | Description |
|---|---|---|
| `/scans` | POST (create), GET (list), GET /:id, GET /:id/results | Scan lifecycle |
| `/assets` | GET (list), GET /:id, GET /:id/findings | Discovered assets |
| `/findings` | GET (list), GET /:id, PATCH (update status) | Crypto findings |
| `/connectors` | CRUD | CMDB, cloud, CA integrations |
| `/reports` | POST (generate), GET (list), GET /:id (download) | CBOM, compliance reports |
| `/dashboard` | GET /summary, GET /risk-distribution, GET /progress | Dashboard widgets |
| `/settings` | GET, PATCH | Scanner config, credentials, notifications |
| `/auth` | POST /login, POST /refresh, POST /logout | Authentication |

### External APIs (Scanner → Target Systems)

| Target | Protocol | Authentication | Phase |
|---|---|---|---|
| TLS/SSH endpoints | TCP handshake | None (Tier 0) | MVP |
| CT logs (crt.sh) | HTTPS REST | None | MVP |
| DNS | DNS protocol | None | MVP |
| AD CS / Vault PKI | LDAP / REST API | Service account (Tier 1) | Phase 2 |
| AWS Config / KMS | AWS SDK | IAM read-only role (Tier 4) | Phase 2 |
| Azure Resource Graph / Key Vault | Azure SDK | Service principal (Tier 4) | Phase 2 |
| GCP Asset Inventory / KMS | GCP SDK | Service account (Tier 4) | Phase 2 |
| ServiceNow CMDB | REST API | Read-only service account (Tier 1) | Phase 2 |
| NetBox | REST API | API token (Tier 1) | Phase 2 |
| GitHub / GitLab | REST API | PAT with contents:read (Tier 6) | Phase 2 |
| K8s API | kubectl / REST | Read-only service account (Tier 2) | Phase 3 |
| HSM (PKCS#11) | Vendor SDK | Auditor partition (Tier 3) | Phase 3 |

---

## 7. Architecture Decisions

### 7.1 Monolith First, Modular Internally

**Decision:** Start as a modular monolith (single deployable with clear internal boundaries), not microservices.

**Rationale:**
- Single docker-compose deploy is a core product requirement
- Small team (2-5 engineers) doesn't benefit from microservices overhead
- Internal module boundaries (scanner, analysis, reporting) can be extracted later
- Simpler debugging, testing, and deployment

### 7.2 Integrate Open-Source Scanners, Don't Rebuild

**Decision:** Wrap existing open-source tools as scanner workers rather than reimplementing their logic.

**Core Python Libraries (direct import):**
| Library | Purpose | Integration Method |
|---|---|---|
| **pyshark** | Passive TLS/SSH capture via tshark, PCAP analysis | Python library (requires tshark on host) |
| **cryptography** (pyca) | X.509 cert parsing, PQC OID classification, key analysis | Python library import |
| **sslyze** | Deep TLS analysis (cipher suites, protocols, cert validation) | Python API (not CLI) |
| **paramiko** | SSH transport analysis, KEX/cipher enumeration | Python library import |
| **scapy** | Packet crafting for custom TLS probes with PQC key exchange groups | Python library import |
| **python-nmap** | Network endpoint discovery | Python wrapper around nmap CLI |
| **dnspython** | DNS enumeration for target discovery | Python library import |
| **CycloneDX Python lib** | CBOM generation in CycloneDX format | Python library import |

**CLI Tools (subprocess wrapper, JSON output):**
| Tool | Purpose | Integration Method |
|---|---|---|
| **pqcscan** (Rust) | ML-KEM/ML-DSA handshake detection | CLI binary, `--output-format json` |
| **testssl.sh** (Bash) | Comprehensive TLS grading | CLI script, `--jsonfile` output |
| **ssh-audit** (Python/Bash) | SSH algorithm audit | CLI, `-j` JSON output |
| **Trivy** (Go) | Container + SBOM scanning | CLI binary, `-f json` output |
| **Semgrep** (OCaml) | SAST crypto rules (hardcoded keys, weak crypto) | CLI binary, `--json` output |
| **ike-scan** (C) | IKEv2/IPsec probing | CLI binary, custom parsing |

**Rationale:** These tools represent years of battle-tested development. Rebuilding them wastes time and introduces bugs. Our value is in the reconciliation, risk scoring, and dashboard layer. pyshark is particularly valuable as it gives us passive network monitoring (SPAN port capture) with deep protocol dissection — a capability no competitor offers in an open-source-friendly way.

### 7.3 Append-Only Evidence Store

**Decision:** Scan results are immutable. New scans create new records; old records are never updated.

**Rationale:**
- Enables scan-over-scan diff for migration tracking
- Provides complete audit trail for compliance
- Simplifies concurrency (no write conflicts)
- Historical data is valuable for trend analysis

### 7.4 Credential Vault Integration

**Decision:** Never store credentials in the scanner's database. Integrate with external vaults.

| Phase | Vault | Rationale |
|---|---|---|
| MVP | Environment variables / encrypted config file | Simple, sufficient for single-tenant |
| Phase 2 | HashiCorp Vault / CyberArk | Enterprise-grade, JIT elevation, audit trail |
| Phase 3 | Customer-managed vault (bring your own) | Maximum security, compliance requirement |

### 7.5 Tiered Access Model

**Decision:** Every scan operation declares its required access tier. The scanner enforces that credentials match the tier.

| Tier | Access Level | Example |
|---|---|---|
| Tier 0 | Unauthenticated | TLS probes, CT logs, DNS |
| Tier 1 | Read-only service account | SSH audit, CMDB query, CA read |
| Tier 2 | Local admin / root | TPM queries, Secure Boot, AD CS audit |
| Tier 3 | Hardware / out-of-band | HSM enumeration, smart cards |
| Tier 4 | Cloud control plane | AWS Config, Azure Resource Graph, GCP KMS |

---

## 8. Deployment Plan

### 8.1 Docker Compose (MVP)

```yaml
# docker-compose.yml (simplified)
services:
  api:          # FastAPI application server
  worker:       # Celery scanner worker (can scale to N replicas)
  beat:         # Celery beat scheduler (periodic scans)
  postgres:     # PostgreSQL 16
  redis:        # Redis 7 (broker + cache)
  frontend:     # React app served by Nginx
```

**Deployment target:** Single VM or bare-metal server (8 CPU, 16GB RAM minimum)
**First scan:** Achievable within 1 hour of `docker-compose up`

### 8.2 Scaling Path

| Phase | Deployment | Scale Target |
|---|---|---|
| MVP | Single docker-compose | 1,000 endpoints |
| Phase 2 | Docker compose + worker scaling | 10,000 endpoints |
| Phase 3 | Kubernetes Helm chart | 100,000+ endpoints |
| Phase 4+ | Multi-region, multi-tenant | MSP scale |

### 8.3 Air-Gap Support

- All dependencies bundled in the Docker image (no internet pull at runtime)
- Offline CBOM export (no telemetry phone-home)
- Manual update path via image tar files
- No external API calls required for core scanning (CT log polling is optional)

---

## 9. Security Requirements

### 9.1 Application Security

| Requirement | Implementation |
|---|---|
| **Input validation** | Pydantic models enforce schema on all API inputs |
| **SQL injection prevention** | SQLAlchemy ORM (parameterized queries), no raw SQL |
| **XSS prevention** | React auto-escapes; CSP headers configured |
| **CSRF protection** | SameSite cookies + CSRF tokens on state-changing endpoints |
| **Rate limiting** | Redis-based rate limiter on auth and scan endpoints |
| **Dependency scanning** | Trivy + Dependabot in CI pipeline |
| **Secrets management** | No secrets in code; env vars or vault integration |

### 9.2 Scanner Security

| Requirement | Implementation |
|---|---|
| **Least privilege** | Tiered access model; never request admin when read-only suffices |
| **Credential isolation** | Credentials never written to database, logs, or evidence store |
| **Scan output sanitization** | Raw scan output sanitized before storage (no credential leakage) |
| **Network isolation** | Scanner workers run in isolated network segment |
| **Audit logging** | All scan operations, credential access, and admin actions logged |

### 9.3 Data Security

| Requirement | Implementation |
|---|---|
| **Encryption at rest** | PostgreSQL TDE or filesystem encryption (LUKS/BitLocker) |
| **Encryption in transit** | TLS 1.3 for all API communication |
| **Data residency** | All data stays on-premise; no telemetry or phone-home |
| **Backup** | PostgreSQL pg_dump scheduled backups |
| **Retention policy** | Configurable evidence retention (default: 2 years) |

---

## 10. Technical Decisions Summary

| Decision | Choice | Alternative Considered | Why This Choice |
|---|---|---|---|
| Backend language | Python | Go, Rust | Richest crypto tool ecosystem; team familiarity |
| Frontend framework | React + TypeScript | Vue, Svelte | Industry standard; hiring pool |
| Database | PostgreSQL | MongoDB, MySQL | JSONB + relational; mature; open-source |
| Task queue | Celery + Redis | RQ, Dramatiq | Most mature; distributed scaling; monitoring tools |
| Scanner approach | Integrate open-source | Build from scratch | Battle-tested tools; focus on unique value |
| Architecture | Modular monolith | Microservices | Single deploy requirement; small team |
| Auth | Local + OIDC (Phase 2) | Custom SSO | OIDC is enterprise standard; local for MVP speed |
| Graph DB | Neo4j (Phase 3) | PostgreSQL recursive CTEs | Better traversal performance at scale |
| Deployment | Docker compose | Kubernetes (Phase 3) | Simplicity for on-prem; air-gap compatible |
