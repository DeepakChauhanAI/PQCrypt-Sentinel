# Implementation Plan

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Engineering Team  
**Status:** Draft  

---

## 1. Overview

This document defines the phased implementation plan for building PQCrypt Sentinel from zero to a production-ready PQC discovery platform. The plan is divided into 8 phases over approximately 12 months, with an MVP achievable in 8-12 weeks.

---

## 2. Phase 0: Project Setup (Week 1-2)

### Objectives
- Establish development environment and tooling
- Define coding standards and CI/CD pipeline
- Set up project repository structure

### Deliverables

| Deliverable | Description |
|---|---|
| **Repository setup** | Monorepo with `backend/`, `frontend/`, `docs/`, `docker/` directories |
| **Docker Compose base** | `docker-compose.yml` with PostgreSQL, Redis, API, Worker, Frontend services |
| **CI/CD pipeline** | GitHub Actions: lint → test → build → deploy (staging) |
| **Pre-commit hooks** | Black (Python), ESLint (TypeScript), Ruff, MyPy |
| **Development docs** | README, CONTRIBUTING.md, local setup guide |
| **Database migrations** | Alembic initialized, baseline schema migration |
| **API skeleton** | FastAPI app with health endpoint, OpenAPI docs, CORS config |
| **Frontend skeleton** | Vite + React + TypeScript + Tailwind + shadcn/ui initialized |

### Technical Tasks

```
1. Initialize monorepo structure
2. Create Docker Compose with all services
3. Set up PostgreSQL with Alembic migrations
4. Set up Redis for Celery broker
5. Create FastAPI app skeleton with health endpoint
6. Create React app skeleton with routing
7. Set up GitHub Actions CI/CD
8. Configure pre-commit hooks (Black, Ruff, ESLint, MyPy)
9. Install system dependencies in Docker image:
   a. tshark (Wireshark CLI) — required by pyshark
   b. nmap — required by python-nmap
   c. openssl — required for cert operations
   d. testssl.sh — bundled as CLI tool
   e. ssh-audit — bundled as CLI tool
   f. pqcscan — Rust binary (cross-compiled or downloaded)
10. Write development environment setup documentation
11. Create seed data scripts for development
```

### Python Dependencies (requirements.txt)

```
# Core framework
fastapi==0.115.*
uvicorn[standard]==0.34.*
sqlalchemy[asyncio]==2.0.*
alembic==1.15.*
pydantic==2.11.*
celery[redis]==5.5.*
redis==5.3.*

# Authentication
python-jose[cryptography]==3.4.*
passlib[bcrypt]==1.7.*

# Scanner libraries
pyshark==0.6.*
cryptography==45.0.*
sslyze==6.1.*
paramiko==3.6.*
scapy==2.6.*
python-nmap==0.7.*
dnspython==2.7.*

# Cloud connectors
boto3==1.38.*
azure-identity==1.23.*
azure-mgmt-resourcegraph==10.0.*
google-cloud-asset==3.30.*
google-cloud-kms==3.8.*

# Reporting
cyclonedx-python-lib==9.5.*
weasyprint==65.0.*

# SAST
# semgrep installed as CLI binary, not pip package

# Utilities
httpx==0.28.*
python-multipart==0.0.*
```

---

## 3. Phase 1: Authentication & Core UI (Week 3-4)

### Objectives
- Implement user authentication (login, logout, JWT)
- Build core layout (sidebar, navigation, header)
- Create dashboard shell with placeholder widgets

### Deliverables

| Deliverable | Description |
|---|---|
| **Auth API** | POST `/api/v1/auth/login`, POST `/api/v1/auth/refresh`, POST `/api/v1/auth/logout` |
| **User model** | `users` table, bcrypt password hashing, JWT token generation |
| **RBAC middleware** | Role-based route protection (admin, analyst, viewer) |
| **Login page** | S1: Username/password form, error handling, redirect |
| **App shell** | Sidebar navigation, header with user menu, breadcrumb |
| **Dashboard shell** | S2: Placeholder cards for PQC readiness, risk distribution, top findings |
| **Settings pages** | S12: General settings, user management (S13) |

### Technical Tasks

```
1. Implement users table and SQLAlchemy model
2. Build auth endpoints (login, refresh, logout)
3. Implement JWT token generation and validation
4. Create bcrypt password hashing utilities
5. Build RBAC middleware and role decorators
6. Create React login page with form validation
7. Build app shell: sidebar, header, routing
8. Create dashboard page with placeholder widgets
9. Build settings page with general config
10. Build user management page (admin only)
11. Write auth integration tests
```

---

## 4. Phase 2: Database & Data Models (Week 4-5)

### Objectives
- Implement all core database tables
- Create SQLAlchemy models and Pydantic schemas
- Build Alembic migrations for all entities

### Deliverables

| Deliverable | Description |
|---|---|
| **All core tables** | assets, certificates, algorithms, findings, scans, connectors, scan_logs, asset_relationships, migration_progress, reports, api_keys |
| **SQLAlchemy models** | Full ORM models with relationships |
| **Pydantic schemas** | Request/response schemas for all API endpoints |
| **Alembic migrations** | Version-controlled schema migrations |
| **Seed data** | Development seed scripts for testing |

### Technical Tasks

```
1. Create Alembic migration for all tables
2. Implement SQLAlchemy models with relationships
3. Create Pydantic schemas for all entities
4. Write database seed scripts for development
5. Implement soft delete mixin
6. Implement timestamp mixin (created_at, updated_at)
7. Add database indexes per schema spec
8. Write model unit tests
9. Create database backup/restore scripts
```

---

## 5. Phase 3: Scanner Engine — TLS, SSH & Passive Monitoring (Week 5-7)

### Objectives
- Build the core scanner engine with TLS, SSH, and passive network scanning
- Integrate open-source tools: pyshark, cryptography, sslyze, paramiko, pqcscan, ssh-audit
- Implement scan job lifecycle (create, run, complete, fail)
- Build passive monitoring via pyshark (SPAN port capture)

### Deliverables

| Deliverable | Description |
|---|---|
| **Celery worker infrastructure** | Worker setup, task registration, error handling |
| **Scan job lifecycle** | Create → Queue → Run → Complete/Fail with status tracking |
| **TLS scanner worker** | Active TLS scanning via `cryptography` lib + `sslyze` Python API |
| **SSH scanner worker** | SSH audit via `paramiko` + `ssh-audit` CLI wrapper |
| **Passive network monitor** | pyshark-based SPAN port capture for TLS/SSH handshake observation |
| **PQCan integration** | CLI wrapper for `pqcscan` binary — PQC handshake detection |
| **testssl.sh integration** | CLI wrapper for comprehensive TLS grading (JSON output) |
| **Certificate parser** | Python `cryptography` lib for deep cert chain analysis + PQC OID classification |
| **PQC algorithm classifier** | OID matching for ML-KEM, ML-DSA, SLH-DSA, Falcon, hybrids |
| **Scan API** | POST/GET `/api/v1/scans`, GET `/api/v1/scans/:id` |
| **Scan management UI** | S8: Scan list, create modal, scan detail (S9) |

### Open-Source Libraries Used (Phase 3)

| Library | Install | Purpose |
|---|---|---|
| `pyshark` | `pip install pyshark` | Passive TLS/SSH capture via tshark, PCAP analysis |
| `cryptography` | `pip install cryptography` | X.509 cert parsing, signature algorithm OIDs, key analysis |
| `sslyze` | `pip install sslyze` | Deep TLS analysis (cipher suites, protocols, cert validation) |
| `paramiko` | `pip install paramiko` | SSH transport analysis, KEX/cipher enumeration |
| `scapy` | `pip install scapy` | Packet crafting for custom TLS probes with PQC groups |
| `python-nmap` | `pip install python-nmap` | Network discovery of TLS/SSH endpoints |
| `dnspython` | `pip install dnspython` | DNS enumeration for target discovery |

### CLI Tools Wrapped (Phase 3)

| Tool | Binary | JSON Output | Purpose |
|---|---|---|---|
| **pqcscan** | Rust binary | `--output-format json` | ML-KEM/ML-DSA handshake detection |
| **testssl.sh** | Bash script | `--jsonfile` | Comprehensive TLS grading |
| **ssh-audit** | Python/Bash | `-j` | SSH algorithm audit |

### Technical Tasks

```
1. Set up Celery workers with Redis broker
2. Implement scan job model and lifecycle
3. Install and configure pyshark (requires tshark on host)
4. Build passive TLS monitor:
   a. pyshark LiveCapture on SPAN interface
   b. TLS ClientHello/ServerHello parsing
   c. PQC key exchange group detection (X25519MLKEM768, etc.)
   d. Certificate extraction from handshake
5. Build active TLS scanner:
   a. cryptography lib: cert parsing, PQC OID classification
   b. sslyze Python API: cipher suite enumeration, protocol analysis
   c. python-nmap: endpoint discovery
6. Build SSH scanner:
   a. paramiko: SSH transport analysis, KEX enumeration
   b. ssh-audit CLI: comprehensive SSH config audit
7. Build PQCan integration (Rust binary, JSON output)
8. Build testssl.sh integration (Bash, JSON output)
9. Build PCAP file analyzer (offline pyshark FileCapture)
10. Implement certificate parser with PQC OID classification:
    a. ML-DSA OIDs (2.16.840.1.101.3.4.3.17-19)
    b. SLH-DSA OIDs (2.16.840.1.101.3.4.3.20-23)
    c. Falcon OIDs (1.3.6.1.4.1.62253.25642-43)
    d. Hybrid signature OIDs (2.16.840.1.114027.80.4.1-3)
    e. ML-KEM TLS groups (0x01FC-0x0200, 0x2B92-0x2B94)
11. Build scapy-based PQC group probe (craft ClientHello with ML-KEM groups)
12. Create scan API endpoints
13. Build scan management UI (list, create, detail)
14. Implement scan progress WebSocket updates
15. Write scanner integration tests
```

### Key pyshark Integration Points

```
Passive Monitoring (SPAN port):
  pyshark.LiveCapture → TLS handshake extraction → PQC group detection

PCAP Analysis (offline):
  pyshark.FileCapture → Batch TLS analysis → Certificate extraction

Active Probing (complement):
  scapy crafted ClientHello with PQC groups → Server response analysis
```

---

## 6. Phase 4: Analysis Engine & Risk Scoring (Week 7-8)

### Objectives
- Build the risk scoring engine
- Implement Mosca's Theorem / HNDL model
- Create the findings lifecycle

### Deliverables

| Deliverable | Description |
|---|---|
| **Algorithm classifier** | Maps every algorithm to PQC status (vulnerable/transitioning/hybrid/pqc_ready/safe) |
| **Risk scoring engine** | Multi-dimensional scoring: HNDL, exposure, criticality, algorithm, deadline |
| **Mosca's Theorem model** | Per-asset HNDL timeline: data longevity vs quantum timeline vs migration window |
| **Findings generator** | Auto-creates findings from scan results |
| **Findings API** | CRUD for findings, status updates, assignment |
| **Findings UI** | S6: Findings list with filters, S7: Finding detail |
| **Algorithm recommendation map** | Current algo → PQC replacement → hybrid transition |

### Technical Tasks

```
1. Implement algorithm classifier service
2. Build risk scoring engine (5 factors, weighted)
3. Implement Mosca's Theorem calculator
4. Create findings generator from scan results
5. Build findings API endpoints (CRUD, status, assign)
6. Implement algorithm recommendation map
7. Build findings list UI with filters
8. Build finding detail UI with evidence and remediation
9. Write risk scoring unit tests
10. Write findings integration tests
```

---

## 7. Phase 5: Dashboard & Reporting (Week 8-10)

### Objectives
- Build executive and operational dashboards
- Implement CBOM export (CycloneDX)
- Create compliance report generation

### Deliverables

| Deliverable | Description |
|---|---|
| **Executive dashboard** | S2: PQC readiness gauge, risk distribution, HNDL timeline, top findings, migration progress |
| **Operational dashboard** | S3: Scan queue, team backlogs, drift alerts, new discoveries, coverage gaps |
| **Dashboard API** | Aggregation endpoints for dashboard widgets |
| **CBOM export** | CycloneDX JSON output compliant with CBOM spec |
| **Report generator** | PDF/JSON/CSV report generation |
| **Reports UI** | S10: Report type selection, scope filtering, generation, download |
| **Asset explorer** | S4: Searchable/filterable asset table |
| **Asset detail** | S5: Full asset view with tabs (algorithms, certs, findings, dependencies, history) |

### Technical Tasks

```
1. Implement dashboard aggregation queries
2. Build executive dashboard with chart components
3. Build operational dashboard widgets
4. Implement CBOM export (CycloneDX Python lib)
5. Create report generation service (PDF via WeasyPrint)
6. Build reports page UI
7. Build asset explorer with search and filters
8. Build asset detail page with tabbed views
9. Implement WebSocket for real-time dashboard updates
10. Write dashboard API tests
```

---

## 8. Phase 6: Connectors — CMDB, Cloud, CA (Week 10-14)

### Objectives
- Build connector framework for external system integration
- Implement CMDB, cloud, and CA connectors
- Enable bidirectional data sync

### Deliverables

| Deliverable | Description |
|---|---|
| **Connector framework** | Base connector class, credential management, sync scheduling |
| **ServiceNow connector** | REST API integration, CI pull, relationship mapping |
| **NetBox connector** | REST API integration, device/VM pull |
| **AWS connector** | Config, KMS, ACM, EC2, ELB resource inventory |
| **Azure connector** | Resource Graph, Key Vault, App Service inventory |
| **GCP connector** | Asset Inventory, KMS, Certificate Manager |
| **AD CS connector** | LDAP query for issued certificates |
| **Vault PKI connector** | HashiCorp Vault PKI secrets engine |
| **CT log monitor** | crt.sh polling for public certificate transparency |
| **Connectors UI** | S11: Connector list, add/edit forms, test connection, sync status |
| **CMDB write-back** | Push findings back to ServiceNow as CIs |

### Technical Tasks

```
1. Design connector base class and interface
2. Implement credential management (encrypted storage)
3. Build connector scheduling (Celery beat)
4. Implement ServiceNow connector:
   a. Schema discovery
   b. CI pull (servers, software, certs, relationships)
   c. Incremental sync
5. Implement NetBox connector
6. Implement AWS connector (Config, KMS, ACM)
7. Implement Azure connector (Resource Graph, Key Vault)
8. Implement GCP connector (Asset Inventory, KMS)
9. Implement AD CS connector (LDAP)
10. Implement Vault PKI connector
11. Implement CT log monitor (crt.sh polling)
12. Build connector management UI
13. Implement CMDB write-back
14. Write connector integration tests
```

---

## 9. Phase 7: Migration Tracking & Drift Detection (Week 14-16)

### Objectives
- Build migration progress tracking
- Implement drift detection (regression alerts)
- Create migration dashboard

### Deliverables

| Deliverable | Description |
|---|---|
| **Migration progress model** | Per-asset readiness state tracking over time |
| **Scan-over-scan diff** | Compare two scans: new findings, resolved findings, algorithm changes |
| **Drift detection** | Alert when a migrated asset regresses to vulnerable algorithm |
| **Migration dashboard** | S14: Overall progress gauge, trend chart, by-algorithm breakdown, by-service table |
| **Notification system** | Email/Slack/webhook alerts for drift and scan completion |
| **Ticketing integration** | Jira/ServiceNow auto-ticket creation from findings |

### Technical Tasks

```
1. Implement migration_progress model and tracking
2. Build scan diff engine (compare two scan results)
3. Implement drift detection service
4. Build notification service (email, Slack, webhook)
5. Create migration dashboard UI
6. Implement ticketing integration (Jira REST API)
7. Implement ticketing integration (ServiceNow REST API)
8. Write drift detection tests
9. Write migration tracking tests
```

---

## 10. Phase 8: Testing, Security Hardening & Deployment (Week 16-20)

### Objectives
- Comprehensive testing (unit, integration, e2e)
- Security audit and hardening
- Production deployment preparation

### Deliverables

| Deliverable | Description |
|---|---|
| **Unit test suite** | 80%+ code coverage for backend services |
| **Integration test suite** | API endpoint tests, scanner integration tests |
| **E2E test suite** | Playwright tests for critical user flows |
| **Security audit** | OWASP Top 10 review, dependency scan, credential handling audit |
| **Performance testing** | Load test: 1000 endpoints scanned in < 4 hours |
| **Production Docker image** | Optimized, multi-stage build, no dev dependencies |
| **Deployment documentation** | Install guide, air-gap guide, troubleshooting |
| **Helm chart** (optional) | Kubernetes deployment for Phase 3 customers |
| **User documentation** | User guide, admin guide, API reference |

### Technical Tasks

```
1. Write unit tests for all services (80%+ coverage)
2. Write integration tests for all API endpoints
3. Write E2E tests for critical flows (login, scan, findings, reports)
4. Conduct security audit:
   a. OWASP Top 10 review
   b. Dependency vulnerability scan (Trivy, Snyk)
   c. Credential handling review
   d. SQL injection testing
   e. XSS testing
   f. CSRF testing
5. Performance testing:
   a. Scan 1000 endpoints, measure duration
   b. API response time benchmarks
   c. Database query optimization
6. Optimize Docker images (multi-stage, minimal base)
7. Write deployment documentation
8. Create Helm chart (optional)
9. Write user documentation
10. Create admin guide
11. Generate API reference from OpenAPI spec
```

---

## 11. Phase 9: Polish & Launch (Week 20-24)

### Objectives
- UI polish and UX improvements
- Beta testing with pilot customers
- Launch preparation

### Deliverables

| Deliverable | Description |
|---|---|
| **UI polish** | Responsive fixes, animation refinement, accessibility audit |
| **Onboarding wizard** | First-run experience: connect first target, run first scan, view results |
| **Help system** | In-app tooltips, contextual help, FAQ |
| **Beta program** | 5-10 pilot customers, feedback collection |
| **Launch readiness** | Marketing site, pricing page, documentation portal |
| **Monitoring** | Application logging, error tracking (Sentry), health checks |

### Technical Tasks

```
1. UI responsive fixes and polish
2. Accessibility audit (WCAG 2.1 AA)
3. Build onboarding wizard
4. Implement in-app help tooltips
5. Set up error tracking (Sentry)
6. Set up application logging (structured JSON)
7. Create marketing landing page
8. Create pricing page
9. Set up documentation portal
10. Onboard beta customers
11. Collect and prioritize feedback
12. Final bug fixes and stabilization
13. Production deployment
```

---

## 12. Timeline Summary

```
Week  1-2   ████ Phase 0: Project Setup
Week  3-4   ████ Phase 1: Authentication & Core UI
Week  4-5   ████ Phase 2: Database & Data Models
Week  5-7   ██████ Phase 3: Scanner Engine (TLS/SSH)
Week  7-8   ████ Phase 4: Analysis Engine & Risk Scoring
Week  8-10  ██████ Phase 5: Dashboard & Reporting
Week 10-14  ████████████ Phase 6: Connectors (CMDB/Cloud/CA)
Week 14-16  ██████ Phase 7: Migration Tracking & Drift
Week 16-20  ████████████ Phase 8: Testing & Security
Week 20-24  ████████████ Phase 9: Polish & Launch
```

### Milestone Targets

| Milestone | Week | Deliverable |
|---|---|---|
| **M1: Skeleton** | 2 | Running app with auth, empty dashboard |
| **M2: First Scan** | 7 | TLS/SSH scan produces findings |
| **M3: MVP** | 10 | Full dashboard, risk scoring, CBOM export |
| **M4: Connectors** | 14 | CMDB + Cloud + CA integration |
| **M5: Production** | 20 | Tested, secured, documented |
| **M6: Launch** | 24 | Beta customers, production deployment |

---

## 13. Team Structure (Recommended)

| Role | Count | Responsibility |
|---|---|---|
| **Backend Engineer** | 2 | Scanner engine, API, connectors, analysis |
| **Frontend Engineer** | 1-2 | Dashboard, UI components, charts |
| **DevOps / SRE** | 1 | CI/CD, Docker, deployment, monitoring |
| **Security Engineer** | 0.5 (part-time) | Security audit, credential handling, crypto expertise |
| **Product Manager** | 0.5 (part-time) | Requirements, prioritization, customer feedback |

**Total:** 4-6 people, 20-24 weeks to launch.

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Open-source tool integration complexity** | Medium | High | Start with Python-native tools (SSLyze, ssh-audit); wrap CLI tools as subprocess |
| **Performance at scale (10K+ endpoints)** | Medium | Medium | Celery worker scaling; database query optimization; pagination |
| **CMDB connector diversity** | Low | Medium | Adapter framework; start with ServiceNow (most common), add others incrementally |
| **PQC algorithm landscape changes** | Low | High | Modular algorithm classifier; database-driven OID mapping (not hardcoded) |
| **Customer credential security** | Low | Critical | Never store credentials in DB; vault integration; security audit |
| **Scope creep (feature requests)** | High | Medium | Strict MVP scope; defer to Phase 2+; say no to non-core features |
| **Team size / velocity** | Medium | High | Prioritize ruthlessly; integrate open-source to reduce build scope |

---

## 15. Technology Dependency Map

```
Phase 0 (Setup)
  └─ Docker, PostgreSQL, Redis, FastAPI, React, Vite
  └─ System: tshark, nmap, openssl, testssl.sh, ssh-audit, pqcscan

Phase 1 (Auth/UI)
  └─ Phase 0 + python-jose, passlib, shadcn/ui, Tailwind, React Router

Phase 2 (Database)
  └─ Phase 1 + SQLAlchemy, Alembic, Pydantic

Phase 3 (Scanner — Core)
  └─ Phase 2 + Celery
  └─ pyshark (passive TLS/SSH capture via tshark)
  └─ cryptography (X.509 cert parsing, PQC OID classification)
  └─ sslyze (deep TLS analysis — Python API)
  └─ paramiko (SSH transport analysis)
  └─ scapy (packet crafting for PQC group probes)
  └─ python-nmap (network discovery)
  └─ dnspython (DNS enumeration)
  └─ pqcscan CLI (PQC handshake detection)
  └─ testssl.sh CLI (comprehensive TLS grading)
  └─ ssh-audit CLI (SSH config audit)

Phase 4 (Analysis)
  └─ Phase 3 + Risk scoring logic, Mosca's Theorem, Vendor PQC readiness DB

Phase 5 (Dashboard)
  └─ Phase 4 + Recharts, cyclonedx-python-lib (CBOM), weasyprint (PDF)

Phase 6 (Connectors)
  └─ Phase 5 + boto3 (AWS KMS/ACM/Config), azure-mgmt (Azure), google-cloud (GCP)
  └─ pysnow (ServiceNow), pynetbox (NetBox), ldap3 (AD CS), hvac (HashiCorp Vault)

Phase 7 (Migration)
  └─ Phase 6 + Notification services (SMTP, Slack SDK)

Phase 8 (Testing)
  └─ All phases + pytest, Playwright, Trivy, Semgrep (CLI), Sentry

Key Integration Points:
  pyshark.LiveCapture  → Passive SPAN port monitoring (real-time)
  pyshark.FileCapture  → PCAP file analysis (offline)
  sslyze.ServerScanner → Active TLS cipher suite enumeration
  paramiko.Transport   → SSH algorithm negotiation
  cryptography.x509    → Certificate parsing + PQC OID matching
  scapy.TLSClientHello → Custom PQC group probes
  python-nmap.PortScan → Network endpoint discovery
  pqcscan CLI          → ML-KEM/ML-DSA handshake detection
```

---

## 16. MVP Feature Checklist

| Feature | Status | Phase |
|---|---|---|
| TLS active handshake scan | ☐ | Phase 3 |
| SSH audit | ☐ | Phase 3 |
| Hybrid PQC detection | ☐ | Phase 3 |
| Certificate chain deep parse | ☐ | Phase 3 |
| PQC algorithm classification | ☐ | Phase 4 |
| Multi-dim risk scoring | ☐ | Phase 4 |
| HNDL / Mosca's Theorem | ☐ | Phase 4 |
| Findings lifecycle | ☐ | Phase 4 |
| Executive dashboard | ☐ | Phase 5 |
| Asset explorer | ☐ | Phase 5 |
| Findings list/detail | ☐ | Phase 5 |
| CBOM export (CycloneDX) | ☐ | Phase 5 |
| Scan management UI | ☐ | Phase 3 |
| Docker Compose deploy | ☐ | Phase 0 |
| On-premise / air-gap | ☐ | Phase 8 |
| Authentication (local) | ☐ | Phase 1 |
| RBAC | ☐ | Phase 1 |
