# Feature Ticket List

**Product:** PQCrypt Sentinel  
**Version:** 1.0  
**Date:** June 2026  
**Status:** Draft  
**Source docs:** `01-Product-Requirements-Document.md`, `03-App-Flow-Document.md`, `06-Implementation-Plan.md`

---

## How to Use This Document

Each ticket is a self-contained build prompt. Copy the full ticket text and paste it into your AI coding tool. Acceptance criteria are the "done" definition — the ticket is closed only when every criterion passes.

Priority key:
- 🔴 **Must-have** — blocks anything else. Do not skip.
- 🟡 **Should-have** — important for MVP completeness. Defer only if time-critical.
- 🟢 **Nice-to-have** — Phase 2. Not required for launch.

---

## Phase 0: Project Setup (Weeks 1–2)

---

### TICKET P0-01: Initialize Monorepo Structure

**Priority:** 🔴 Must-have

**Task Description:**
Create the top-level project layout with `docker/`, `backend/`, `frontend/`, `docs/`, `.github/` directories. Set up the root README, `.gitignore`, and base `docker-compose.yml` skeleton.

**Acceptance Criteria:**
- [ ] `docker/` contains nginx.conf and Dockerfiles for api, worker, and frontend.
- [ ] `backend/`, `frontend/`, `docs/`, `.github/workflows/` directories exist.
- [ ] `docker-compose.yml` defines postgres, redis, api, worker, and frontend services (stubs are fine for now).
- [ ] Running `docker-compose config` succeeds (syntax valid).
- [ ] `.gitignore` covers `__pycache__`, `node_modules`, `.env`, `pgdata/`, `redis-data/`, `.pytest_cache/`, `dist/`.
- [ ] README has setup instructions and architecture overview.

**Dependencies:** None (first ticket).

---

### TICKET P0-02: Docker Compose — PostgreSQL + Redis + API skeleton

**Priority:** 🔴 Must-have

**Task Description:**
Build the docker-compose file so `docker-compose up` brings up PostgreSQL 16, Redis 7+, and a FastAPI app that returns `{"status": "ok"}` on `/health`. Use named volumes for pgdata and redis-data.

**Acceptance Criteria:**
- [ ] `docker-compose up -d` starts all three services.
- [ ] `GET http://localhost:8000/health` returns 200 with `{"status": "ok"}`.
- [ ] PostgreSQL is reachable at `localhost:5432`, database `pqcrypt` exists.
- [ ] Redis is reachable at `localhost:6379` and responds to `PING`.
- [ ] Services restart automatically on failure.
- [ ] docker-compose.yml has restart: unless-stopped on all services.
- [ ] API, worker, frontend, postgres, redis each have their own Dockerfile.

**Dependencies:** P0-01.

---

### TICKET P0-03: Backend scaffolding — FastAPI app factory + Alembic

**Priority:** 🔴 Must-have

**Task Description:**
Create the `backend/` Python package. Implement `app/main.py` as a FastAPI app factory, `app/config.py` using Pydantic Settings, and initialize Alembic with a baseline migration that creates no tables yet.

**Acceptance Criteria:**
- [ ] `backend/app/main.py` exports a `create_app()` factory that accepts `settings: Settings`.
- [ ] `/health` and `/api/v1/auth/docs` (OpenAPI) endpoints exist.
- [ ] CORS middleware configured with `CORS_ORIGINS` from env.
- [ ] `app/config.py` reads all env vars from Section 4 of `Technical-Architecture-Document.md`.
- [ ] `alembic/` folder initialized with `alembic init`.
- [ ] `alembic/env.py` configured for async SQLAlchemy with asyncpg driver.
- [ ] `alembic revision --autogenerate -m "baseline"` runs without error.

**Dependencies:** P0-01, P0-02.

---

### TICKET P0-04: Frontend scaffolding — Vite + React + TypeScript + Tailwind

**Priority:** 🔴 Must-have

**Task Description:**
Initialize the `frontend/` directory with Vite, React 18, TypeScript, Tailwind CSS, and React Router. Create the App shell: sidebar, header, and a placeholder Login + Dashboard page. Build and serve should produce static files served by Nginx.

**Acceptance Criteria:**
- [ ] `npm run dev` starts Vite dev server on port 5173.
- [ ] `npm run build` produces `dist/` without errors.
- [ ] App shell renders: Top header bar + left sidebar + page content area.
- [ ] Sidebar has navigation placeholders: Dashboard, Assets, Findings, Scans, Reports, Migration, Settings.
- [ ] Login placeholder route `/login` renders.
- [ ] Dashboard placeholder route `/` renders.
- [ ] React Router configured with lazy-loading support for page-level chunks.
- [ ] Tailwind CSS compiles without warnings.
- [ ] Dark mode background `#0d1117` applies to app root.

**Dependencies:** P0-01.

---

### TICKET P0-05: CI/CD pipeline + pre-commit hooks

**Priority:** 🔴 Must-have

**Task Description:**
Set up GitHub Actions for CI and a `.pre-commit-config.yaml` for local enforcement. CI should run on every PR: Black (Python), Ruff, MyPy (backend), ESLint + TypeScript check (frontend), pytest, and Docker build smoke test. Pre-commit runs the same checks on `git commit`.

**Acceptance Criteria:**
- [ ] `.github/workflows/ci.yml` runs Black, Ruff, MyPy, ESLint, TypeScript typecheck, pytest, and Docker build on PR.
- [ ] `.pre-commit-config.yaml` runs Black, Ruff, ESLint, and trailing-whitespace on `git commit`.
- [ ] `pre-commit install` succeeds locally.
- [ ] CI fails on lint error and untyped code.
- [ ] `requirements-dev.txt` and `backend/pyproject.toml` include dev dependencies: pytest, pytest-asyncio, httpx, ruff, mypy.

**Dependencies:** P0-03 (backend has code to lint), P0-04 (frontend has code to lint).

---

### TICKET P0-06: Install system scanner dependencies in worker Docker image

**Priority:** 🔴 Must-have

**Task Description:**
Update `docker/Dockerfile.worker` to install tshark (Wireshark CLI), nmap, openssl, and download pqcscan (Rust binary), testssl.sh, and ssh-audit into `/usr/local/bin/`. Verify each tool responds to `--version`.

**Acceptance Criteria:**
- [ ] `docker exec pqc-worker tshark --version` returns the Wireshark version string.
- [ ] `docker exec pqc-worker nmap --version` returns the nmap version.
- [ ] `docker exec pqc-worker openssl version` returns OpenSSL version.
- [ ] `docker exec pqc-worker pqcscan --version` returns the pqcscan version.
- [ ] `docker exec pqc-worker testssl.sh --version` returns testssl.sh version.
- [ ] `docker exec pqc-worker ssh-audit --version` returns ssh-audit version.
- [ ] All tools are available on `PATH` inside the worker container.

**Dependencies:** P0-02.

---

## Phase 1: Auth & Core UI (Weeks 3–4)

---

### TICKET P1-01: Users table + auth API login/logout/JWT

**Priority:** 🔴 Must-have

**Task Description:**
Implement the `users` table via Alembic, create SQLAlchemy model, implement bcrypt password hashing, JWT access+refresh token creation and validation, and four auth API endpoints: `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`.

**Acceptance Criteria:**
- [ ] `users` table in PostgreSQL with columns: id (UUID PK), email (unique), password_hash, full_name, role, is_active, last_login_at, created_at, updated_at, deleted_at.
- [ ] `POST /api/v1/auth/login` with correct credentials returns 200 with `{"access_token": "...", "refresh_token": "...", "token_type": "bearer"}`.
- [ ] Wrong password returns 401 with structured error JSON.
- [ ] Disabled account (is_active=false) returns 401.
- [ ] `POST /api/v1/auth/refresh` with valid httpOnly refresh cookie returns new access token.
- [ ] `POST /api/v1/auth/logout` invalidates refresh token server-side and clears cookie.
- [ ] `GET /api/v1/auth/me` returns the current user object.
- [ ] `last_login_at` is updated on every successful login.
- [ ] Password comparison uses bcrypt with cost factor 12.

**Dependencies:** P0-03 (backend scaffolding), P0-02 (PostgreSQL).

---

### TICKET P1-02: RBAC middleware — role decorators for all routes

**Priority:** 🔴 Must-have

**Task Description:**
Create FastAPI dependencies `require_roles("admin", "analyst", "viewer")` and `require_scopes(...)`. Apply them to a representative set of routes. Document the permission matrix in-code (as comments on each decorator call).

**Acceptance Criteria:**
- [ ] `get_current_user` dependency reads JWT from `Authorization: Bearer` header.
- [ ] `require_admin` raises 403 if user.role != "admin".
- [ ] `require_analyst_or_above` raises 403 if role is "viewer".
- [ ] `require_scope("scans:read")` checks API key scopes when auth method is API key.
- [ ] `require_any_role("admin", "analyst")` works for endpoints needing either.
- [ ] All endpoints raise 401 if no token is provided.
- [ ] Unit tests cover: admin can access admin route, analyst cannot, viewer cannot, missing token → 401.

**Dependencies:** P1-01.

---

### TICKET P1-03: Login page UI

**Priority:** 🔴 Must-have

**Task Description:**
Build the Login page at `/login` using shadcn/ui components. On submit, call `POST /api/v1/auth/login`, store access token in memory, refresh token in httpOnly cookie (set by API via Set-Cookie). On success, redirect to `/`. On failure, show error toast.

**Acceptance Criteria:**
- [ ] Page has email input, password input, "Sign In" button.
- [ ] Empty form submission shows inline validation errors.
- [ ] Successful login redirects to `/` (Dashboard).
- [ ] Failed login shows toast: "Invalid email or password".
- [ ] "Session expired" toast + redirect to `/login` when access token is rejected.
- [ ] Page has no decorative elements — functional only.
- [ ] Keyboard: Enter key on password field submits form.
- [ ] Loading state on button during API call (button disabled, spinner).

**Dependencies:** P0-04 (frontend scaffolding).

---

### TICKET P1-04: App shell — sidebar, header, routing

**Priority:** 🔴 Must-have

**Task Description:**
Build the persistent layout: collapsible sidebar (240px → 64px), top header with breadcrumb and user menu (dropdown: profile, logout). Implement route guards: unauthenticated users are redirected to `/login`. Authenticated users can access dashboard and settings.

**Acceptance Criteria:**
- [ ] Sidebar toggle button collapses sidebar to icon-only mode (64px).
- [ ] Sidebar re-expands on toggle.
- [ ] Sidebar items: Dashboard, Assets, Findings, Scans, Reports, Migration, Connectors, Settings, User Management (admin only).
- [ ] Header shows current user's name and role badge.
- [ ] User dropdown has "Sign Out" which calls `POST /api/v1/auth/logout` then redirects to `/login`.
- [ ] Navigating to `/` while unauthenticated redirects to `/login`.
- [ ] Navigating to `/login` while authenticated redirects to `/`.
- [ ] Sidebar collapsed/expanded state persists in localStorage.

**Dependencies:** P1-03.

---

### TICKET P1-05: Dashboard shell — placeholder cards

**Priority:** 🔴 Must-have

**Task Description:**
Build the Executive Dashboard at `/` with placeholder cards for PQC Readiness Score, Risk Distribution (donut), Top Vulnerable Assets table, and "Run your first scan" CTA. Use empty state design from the design brief. No real data yet — all placeholders.

**Acceptance Criteria:**
- [ ] PQC Readiness Score shows "—" or "N/A" in empty state.
- [ ] Risk Distribution donut shows 0 across all categories.
- [ ] Top Vulnerable Assets table shows "No scans have been run yet."
- [ ] "Run your first scan" button navigates to `/scans` with scan modal pre-opened.
- [ ] All cards use surface background `#161b22` with border `#30363d`.
- [ ] Layout matches the dashboard wireframe in `04-UI-UX-Design-Brief.md`.
- [ ] Responsive to sidebar collapse (cards reflow when sidebar is collapsed).

**Dependencies:** P1-04.

---

### TICKET P1-06: User Management page (admin only)

**Priority:** 🔴 Must-have

**Task Description:**
Build `/settings/users` — a table of all users with columns: Name, Email, Role, Last Login, Status, Actions. Admin can add user, edit role, disable/enable. Viewer and analyst see the table read-only.

**Acceptance Criteria:**
- [ ] GET `/api/v1/users` returns all non-deleted users (admin only).
- [ ] Table columns: Name, Email, Role (badge), Last Login (relative time), Status (active/disabled badge).
- [ ] "Add User" button (admin only) opens modal: Name, Email, Role dropdown, Temporary password.
- [ ] Creating user calls `POST /api/v1/users`. Password is hashed server-side.
- [ ] Role dropdown has options: Admin, Analyst, Viewer.
- [ ] Edit action: change role or disable user.
- [ ] Admin cannot delete themselves (error toast).
- [ ] Viewer role sees table but no "Add User" button, no edit actions.
- [ ] Role badge colors: Admin=red, Analyst=blue, Viewer=gray.

**Dependencies:** P1-02, P1-04.

---

## Phase 2: Database Models (Week 4–5)

---

### TICKET P2-01: Create all 11 core tables via Alembic

**Priority:** 🔴 Must-have

**Task Description:**
Write the Alembic migration that creates all 11 core tables: users, connectors, scans, assets, certificates, algorithms, findings, scan_logs, asset_relationships, migration_progress, reports — plus api_keys and sessions. Apply all indexes defined in `Backend-Schema-Document.md` Section 3.

**Acceptance Criteria:**
- [ ] `alembic upgrade head` creates all tables without errors.
- [ ] All 11 tables exist with correct column names, types, and defaults.
- [ ] All CHECK constraints on `role`, `status`, `pqc_status`, `asset_type`, `environment`, `pqc_readiness`, etc. are enforced.
- [ ] All indexes from schema document are created and verified via `\di` in psql.
- [ ] Partial indexes with `WHERE deleted_at IS NULL` are correct.
- [ ] `UUID PRIMARY KEY DEFAULT gen_random_uuid()` is used for all PKs.
- [ ] `TIMESTAMPTZ` used for all timestamps.
- [ ] `INET` type used for ip_address column.
- [ ] `TEXT[]` used for key_usage and san_dns arrays.

**Dependencies:** P0-03.

---

### TICKET P2-02: SQLAlchemy ORM models with relationships

**Priority:** 🔴 Must-have

**Task Description:**
Write SQLAlchemy 2.0 model classes for all 11 tables in `backend/app/models/`. Define relationships: asset → certificates (one-to-many), asset → algorithms (one-to-many via scan), scan → findings (one-to-many), asset → asset_relationships (self-referential). Include soft-delete mixin and timestamp mixin.

**Acceptance Criteria:**
- [ ] All models have `id`, `created_at`, `updated_at`, `deleted_at`.
- [ ] `Asset.certificates` relationship returns list of Certificate objects.
- [ ] `Scan.findings` relationship returns list of Finding objects for that scan.
- [ ] `Asset.relationships` returns both outgoing and incoming relationships.
- [ ] Soft-delete mixin: `query.filter_by(deleted_at=None)` works as default filter.
- [ ] Models can be imported without circular import errors.
- [ ] `relationship(back_populates=...)` used correctly (no lazy=dynamic unless needed).
- [ ] All foreign keys have `ondelete="SET NULL"` where appropriate.

**Dependencies:** P2-01.

---

### TICKET P2-03: Pydantic schemas for all API resources

**Priority:** 🔴 Must-have

**Task Description:**
Create Pydantic v2 schemas for all 11 resources in `backend/app/models/schemas.py`. Each resource needs: `Create` (input for POST), `Update` (input for PATCH, all optional), `Out` (response for GET). Include pagination schemas and error schemas.

**Acceptance Criteria:**
- [ ] Every `CREATE` schema excludes `id`, `created_at`, `updated_at`, `deleted_at` (server-generated).
- [ ] Every `Out` schema includes `id` as UUID and all read fields.
- [ ] `AssetOut` includes `certificates`, `algorithms`, `findings` as nested lists (or IDs only via `links`).
- [ ] `FindingOut` includes `asset_name` (denormalized) for frontend convenience.
- [ ] `ScanOut` includes `findings_count` and `assets_found` as integers.
- [ ] `ScanCreate` validates `scan_type` enum and `target` max length.
- [ ] Pagination: `Page[Schema]` generic with `page`, `page_size`, `total`, `items`.

**Dependencies:** P2-02.

---

## Phase 3: Scanner Engine (Weeks 5–7)

---

### TICKET P3-01: Celery worker infrastructure + Redis broker

**Priority:** 🔴 Must-have

**Task Description:**
Stand up Celery 5 with Redis broker in the worker container. Create one worker that can handle `execute_scan(scan_id)` tasks. Wire up Celery Beat scheduler. Both should be visible in the docker-compose logs. Add `flower` (Celery monitoring UI) on port 5555 (dev only, not exposed in production compose).

**Acceptance Criteria:**
- [ ] Worker starts and connects to Redis on `CELERY_BROKER_URL`.
- [ ] Worker picks up a test task: `add.delay(1, 2)` returns 3.
- [ ] Worker logs show "Ready to accept tasks" on startup.
- [ ] Result backend stores task results (visible in Flower).
- [ ] Celery Beat scheduler registers at least one periodic task (placeholder `ping`).
- [ ] Worker gracefully handles SIGTERM (finishes current task before shutting down).
- [ ] Failed tasks retry with exponential backoff (max 3 retries, 60s initial delay).

**Dependencies:** P0-02, P0-06 (worker Docker image has tshark, etc.).

---

### TICKET P3-02: Scan API — CRUD endpoints

**Priority:** 🔴 Must-have

**Task Description:**
Implement the scan lifecycle API in `backend/app/api/scans.py`: `POST /api/v1/scans` (create + queue), `GET /api/v1/scans` (list with pagination), `GET /api/v1/scans/{scanId}` (detail + results summary), `DELETE /api/v1/scans/{scanId}` (cancel). Update `scan.status` through the lifecycle: queued → running → completed / failed / cancelled.

**Acceptance Criteria:**
- [ ] POST with scan_type "full", target "10.0.0.0/24", no credentials returns 202 Accepted with scan ID.
- [ ] New scan row has status="queued", created_at=now, assets_found=0, findings_created=0.
- [ ] GET list returns paginated scans ordered by created_at desc.
- [ ] GET detail returns scan config, status, timing, and summary results.
- [ ] DELETE on running scan sets status="cancelled", sends Celery revoke.
- [ ] DELETE on completed scan returns 422 (cannot cancel finished scan).
- [ ] All scan mutations require analyst role or above.
- [ ] scan_logs appended continuously during execution are retrievable via GET.

**Dependencies:** P1-02 (RBAC), P2-03 (schemas), P3-01 (Celery).

---

### TICKET P3-03: TLS active scanner — sslyze + cryptography + PQC OID classification

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/scanners/tls_scanner.py`. For each target (host:port), run: (1) sslyze Python API for cipher suite and protocol enumeration, (2) `cryptography` library for X.509 cert parsing, (3) PQC OID classification on signature algorithm and public key. Return structured result with algorithm list, risk score, PQC status.

**Acceptance Criteria:**
- [ ] Scans `scanme.nmap.org:443` (public test service) returns certificate data and algorithm list.
- [ ] Output includes `tls_version`, `cipher_suite`, `sig_algorithm`, `pub_key_algorithm`, `pub_key_size`, `not_after`, `pqc_status`.
- [ ] RSA-2048 cert classified as `pqc_status = "vulnerable"`.
- [ ] ECDSA P-256 cert classified as `pqc_status = "vulnerable"`.
- [ ] If algorithm OID not in PQC or classical OID map → `pqc_status = "unknown"`.
- [ ] `scan_tls_endpoint` returns a `ScanResult` dataclass (defined in `base.py`).
- [ ] Tests use a mock certificate fixture (pre-generated PEM) to avoid network dependency in CI.

**Dependencies:** P3-01 (worker infrastructure), P0-06 (dependencies installed).

---

### TICKET P3-04: SSH scanner — paramiko + ssh-audit CLI

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/scanners/ssh_scanner.py`. For each host:port 22, run paramiko KEX/cipher enumeration and wrap `ssh-audit -j` for full SSH audit. Return structured SSH findings (algorithm list, PQC status, weak algorithm detection).

**Acceptance Criteria:**
- [ ] Connects to a public SSH test host (e.g., `ssh.mozilla.com` or a local test container) and returns algorithm list.
- [ ] Output includes `remote_kex_algorithms`, `remote_host_key_algorithms`, `remote_cipher_algorithms`.
- [ ] ssh-audit JSON output parsed and stored in `findings.evidence`.
- [ ] If `ssh-audit` binary missing: user-friendly error in scan logs ("ssh-audit not found at configured path"), scan status set to `failed` with actionable error message.
- [ ] Scan continues to next host on SSH connection failure (does not abort entire batch).
- [ ] PQC KEX keywords (mlkem, kyber, sntrup) detected and classified.

**Dependencies:** P3-01, P3-03 (similar scan result structure).

---

### TICKET P3-05: Certificate parser with PQC OID classification

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/scanners/cert_parser.py` as a shared module used by TLS scanner and cert ingestion. It must load PEM/DER certs, extract all relevant X.509 fields, classify signature algorithm OID, classify public key, detect PQC/hybrid OIDs, and return structured dict compatible with `certificates` table schema.

**Acceptance Criteria:**
- [ ] `parse_certificate(pem_bytes)` returns dict matching `CertificateCreate` schema fields.
- [ ] SHA-256 thumbprint computed and returned.
- [ ] PQC OID maps in `07-Open-Source-Integration-Guide.md` Section 2.2 embedded as module-level constants.
- [ ] Hybrid composite OIDs (2.16.840.1.114027.80.4.1, .4.2, .4.3) correctly detected with `is_hybrid=true`.
- [ ] `extract_sans` returns DNS and IP SANs.
- [ ] `is_ca` flag set correctly based on BasicConstraints extension.
- [ ] `key_usage` array populated from KeyUsage extension.
- [ ] Test fixtures: load test certs from `backend/tests/fixtures/certs/` directory.

**Dependencies:** P3-03.

---

### TICKET P3-06: PQC key exchange group probe — scapy

**Priority:** 🟡 Should-have

**Task Description:**
Implement `backend/app/scanners/pqcprobe.py` scapy-based function that crafts a TLS ClientHello advertising hybrid PQC key exchange groups (X25519MLKEM768, SecP256r1MLKEM768) and sends it to the target. Parse the ServerHello to detect if the server negotiated a PQC group.

**Acceptance Criteria:**
- [ ] `probe_pqc_kex(target_ip, port=443)` sends crafted ClientHello.
- [ ] Response parsed: ServerHello `handshake_extensions_key_share_group` extracted.
- [ ] Group 0x2B93 (X25519MLKEM768) correctly identified as hybrid PQC.
- [ ] Non-PQC group (e.g., X25519 = 0x001D) classified as vulnerable.
- [ ] Does not crash on timeout or non-TLS response (returns error result, not exception).
- [ ] Does not abort batch scan on single host failure.
- [ ] Integration test with a local TLS server (can use `openssl s_server`) confirming probe works end-to-end.

**Dependencies:** P3-03.

---

### TICKET P3-07: PQCan CLI wrapper

**Priority:** 🔴 Must-have

**Task Description:**
Implement `run_pqcscan(host, port)` in `backend/app/scanners/pqcprobe.py` as a subprocess wrapper for the pqcscan Rust binary. Parse JSON output and normalize into the platform's `ScanResult` schema.

**Acceptance Criteria:**
- [ ] `run_pqcscan("scanme.nmap.org", 443)` returns structured dict with `tls_version`, `cipher_suite`, `kex_group`, `is_pqc`, `certificate` summary.
- [ ] Binary not found → returns error with clear message, does not raise unhandled exception.
- [ ] Target unreachable → returns error with host/port, scan continues to next target.
- [ ] JSON parse failure → logs raw output, returns error result.
- [ ] Output includes `tool: "pqcscan"` and `tool_version` from subprocess.
- [ ] 30-second timeout enforced via `asyncio.create_subprocess_exec` with `asyncio.wait_for`.
- [ ] stdout and stderr both captured; stderr logged at INFO level.

**Dependencies:** P3-01, P0-06.

---

### TICKET P3-08: testssl.sh + ssh-audit CLI wrappers

**Priority:** 🟡 Should-have

**Task Description:**
Implement subprocess wrappers for testssl.sh and ssh-audit. Both should write JSON output to a temp file, parse it, normalize into the platform's schema, and clean up the temp file. For ssh-audit, parse the `-j` JSON output. For testssl.sh, extract PQC-relevant entries from the JSON file.

**Acceptance Criteria:**
- [ ] `run_testssl("scanme.nmap.org", 443)` returns findings list with protocol and cipher suite data.
- [ ] `run_ssh_audit("scanme.nmap.org", 22)` returns KEX, host key, and cipher algorithm lists.
- [ ] Temp files are cleaned up in `finally` block even on error.
- [ ] 60-second timeout per tool invocation.
- [ ] JSON parse error → log raw file content, return empty findings list.
- [ ] Binary not found → log CRITICAL, return error `SCAN_TOOL_MISSING`.

**Dependencies:** P3-01, P0-06.

---

### TICKET P3-09: ORCHESTRATOR — wire scanner results to database

**Priority:** 🔴 Must-have

**Task Description:**
Create `backend/app/services/scan_orchestrator.py` that orchestrates the full scan lifecycle: takes a `scan.id`, runs all registered scanners for the target, parses results, calls the asset service to upsert, calls the finding service to generate findings, writes to scan_logs, and updates scan status. This is the thread that ties all scanner pieces together.

**Acceptance Criteria:**
- [ ] Taking a `scan.id` with target "127.0.0.1" (local test) completes end-to-end.
- [ ] TLS scanner results upsert `assets` row (or update existing by IP:port).
- [ ] Certificate results upsert `certificates` row (dedup on thumbprint).
- [ ] Algorithm results upsert `algorithms` rows (append-only, new scan_id).
- [ ] Findings are created via `finding_service.generate_findings(scan_id)`.
- [ ] `scan_logs` written with progress messages every N processed hosts (configurable).
- [ ] On completion: `scan.status = "completed"`, `assets_found` set, `findings_created` set, `duration_seconds` calculated.
- [ ] On failure: `scan.status = "failed"`, `error_message` populated, partial results preserved.
- [ ] Called from Celery task `backend/workers/scan_worker.py`.

**Dependencies:** P2-02 (models), P3-03 (TLS scanner), P3-04 (SSH scanner), P3-07 (pqcscan), P3-08 (testssh/ssh-audit).

---

### TICKET P3-10: Passive network monitor — pyshark SPAN/PCAP capture

**Priority:** 🟡 Should-have

**Task Description:**
Implement `backend/app/scanners/passive_monitor.py` using pyshark. Two modes: (1) LiveCapture on a SPAN/mirror interface, filtering `tls.handshake.type == 1` (ClientHello) and `== 2` (ServerHello). (2) FileCapture for offline PCAP analysis. Extract PQC KEX groups, cipher suites, and certificates.

**Acceptance Criteria:**
- [ ] `analyze_pcap_file("tests/fixtures/sample.pcap")` returns structured dict with TLS handshakes found.
- [ ] ClientHello extracted: src_ip, dst_ip, dst_port, cipher_suites, supported_groups.
- [ ] ServerHello extracted: selected_cipher, selected_group.
- [ ] PQC group IDs (0x2B93, 0x2B92, 0x2B94) correctly classified as hybrid/pqc.
- [ ] Non-PQC groups classified as vulnerable.
- [ ] Mode rejects non-existent interface with clear error (not crash).
- [ ] PCAP file > 1GB: processes in batches, writes partial results every 10000 packets.
- [ ] Feature flag in scan config: `passive_mode: true/false` to enable/disable.

**Dependencies:** P3-09 (orchestrator), P0-06 (tshark in Docker image).

---

### TICKET P3-11: Network discovery — nmap + dnspython

**Priority:** 🟡 Should-have

**Task Description:**
Implement `backend/app/scanners/network_discovery.py`. `discover_tls_hosts(network_range)` runs nmap on ports 443, 8443, 636, 993, 995, 8883 with `-sV --script ssl-enum-ciphers`. `enumerate_dns_targets(domain)` resolves A, AAAA, CNAME, MX, SRV records using dnspython.

**Acceptance Criteria:**
- [ ] Scanning `127.0.0.1` (local loopback) with port 22 open finds the SSH service.
- [ ] DNS enumeration of `example.com` returns A and MX records (or empty lists on NXDOMAIN).
- [ ] nmap results filtered to HTTPS/LDAPS/IMAPS/SMTPS/MQTT services only.
- [ ] nmap binary missing → return error, do not crash.
- [ ] Network scan does not block while resolving — uses async subprocess.
- [ ] Discovery results are written to `scan_logs` for visibility.

**Dependencies:** P3-09, P0-06 (nmap binary).

---

### TICKET P3-12: Scan management UI — list, create, detail

**Priority:** 🔴 Must-have

**Task Description:**
Build the scan UI screens:
- S8 (`/scans`): Scan list table + "New Scan" button that opens creation modal.
- Scan creation modal: scan_type dropdown, target textarea, credential_profile dropdown, schedule toggle.
- S9 (`/scans/{scanId}`): Scan detail with status badge, progress bar, live log (WebSocket), results summary.

**Acceptance Criteria:**
- [ ] "New Scan" button on Dashboard (`/`) navigates to `/scans` with modal open.
- [ ] Scan type options: Full Scan, TLS Only, SSH Only, Targeted.
- [ ] Target textarea validates CIDR format before submit (frontend validation).
- [ ] Creating a scan polls `GET /api/v1/scans/{id}` for progress when WebSocket is unavailable.
- [ ] Scan detail shows: status badge (color-coded), start time, duration (or "still running"), assets found, findings created.
- [ ] Running scan shows animated progress bar ("Running" → blue pulse).
- [ ] Live log section auto-scrolls to latest entry.
- [ ] Completed scan shows results summary and "View Findings" button.
- [ ] Failed scan shows error message and "Retry Scan" button.

**Dependencies:** P3-02 (scan API), P1-04 (app shell).

---

## Phase 4: Analysis Engine & Risk Scoring (Weeks 7–8)

---

### TICKET P4-01: Algorithm classifier service

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/analysis/algo_classifier.py`. Module-level dictionaries for PQC signature OIDs, hybrid signature OIDs, PQC KEX group IDs, classical OIDs. Function `classify_algorithm(name, oid=None, algorithm_type=None)` returns `{pqc_status, is_quantum_vulnerable, is_pqc, is_hybrid}`.

**Acceptance Criteria:**
- [ ] "RSA-2048" → `{pqc_status: "vulnerable", is_quantum_vulnerable: true}`
- [ ] "ECDHE-P-256" → `{pqc_status: "vulnerable", is_quantum_vulnerable: true}`
- [ ] "ML-KEM-768" → `{pqc_status: "pqc_ready", is_quantum_vulnerable: false}`
- [ ] "X25519MLKEM768" → `{pqc_status: "hybrid", is_pqc: true, is_hybrid: true}`
- [ ] Unknown OID → `{pqc_status: "unknown", is_quantum_vulnerable: false}`
- [ ] OID map extracted from `07-Open-Source-Integration-Guide.md` Section 2.1.
- [ ] Module has no external dependencies beyond stdlib.
- [ ] Unit tests cover all entries in PQC_KEX_GROUPS dict + 5 classical cases.

**Dependencies:** None (pure logic).

---

### TICKET P4-02: Risk scoring engine

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/services/risk_service.py`. The risk score (0–100) is calculated from weighted factors as defined in PRD Section 4.3: HNDL sensitivity (30%), system exposure (20%), business criticality (20%), algorithm vulnerability (15%), regulatory deadline proximity (15%). Each factor mapped to a sub-score; final score is weighted average.

**Acceptance Criteria:**
- [ ] `calculate_risk_score(asset, cert, algorithms)` returns integer 0–100.
- [ ] Score = 95 when: internet-facing asset + RSA-2048 cert + regulatory deadline = 2030 (4 years away, close) + Tier 0 business criticality.
- [ ] Score = 10 when: internal-only asset + hybrid algorithm + no deadline pressure.
- [ ] Formula documented as inline comments on each factor's contribution.
- [ ] Result saved to `findings.risk_score` and used to sort top-N vulnerable assets on dashboard.
- [ ] Unit tests cover 3 scenarios: critical (score>80), medium (30-70), low (<30).

**Dependencies:** P4-01 (algorithm classifier).

---

### TICKET P4-03: Mosca's Theorem / HNDL timeline calculator

**Priority:** 🟡 Should-have

**Task Description:**
Implement `backend/app/analysis/mosca_model.py`. For each asset, calculate: (1) data longevity (how long the protected data must remain confidential, in years), (2) quantum timeline (estimated year when quantum computers can break RSA-2048, default: 2035 per NIST), (3) migration window = current year to quantum timeline. If migration window < data longevity = HNDL HIGH.

**Acceptance Criteria:**
- [ ] `calculate_hndl_exposure(data_longevity_years: int, quantum_timeline_year: int = 2035)` returns "high", "medium", "low", or "none".
- [ ] data_longevity=0, quantum=2035 → "none" (no long-lived data).
- [ ] data_longevity=50, quantum=2035 → "high" (50 years of data at risk, only 9 years to migrate).
- [ ] Result stored in `findings.hndl_exposure`.
- [ ] HNDL bar chart on executive dashboard groups assets by "years until quantum risk" (5, 10, 15, 20+).
- [ ] Configurable quantum timeline via env var `QUANTUM_TIMELINE_YEAR` (default 2035).

**Dependencies:** P4-02 (risk service).

---

### TICKET P4-04: Findings generator — create findings from scan results

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/services/finding_service.py`. After a scan completes, this service iterates over all discovered algorithms and certificates, calls the algorithm classifier and risk scorer, and creates `Finding` rows for each problem detected. Finding types: weak_algorithm, weak_key_size, cert_expiring, cert_expired, self_signed, pqc_downgrade, ssh_weak_kex, pkc_not_supported, etc.

**Acceptance Criteria:**
- [ ] After a TLS scan on a host with RSA-2048 cert, a `weak_algorithm` finding is created with severity at least "high".
- [ ] Certificate expiring within 5 years of 2030 NIST deadline gets `cert_expiring` finding (severity "medium").
- [ ] Certificate expiring within 1 year gets `cert_expiring` finding (severity "critical").
- [ ] Self-signed cert gets `self_signed` finding (severity "medium").
- [ ] Server offering both PQC and classical KEX groups gets `pqc_downgrade` finding (severity "high").
- [ ] Each finding has: `remediation` text (e.g., "Upgrade OpenSSL to 3.5+"), `recommended_algorithm` (e.g., "ML-DSA-65").
- [ ] Duplicate prevention: if the same finding type already exists for the same asset in current scan, it is not recreated — status is preserved.
- [ ] Findings list endpoint returns findings sorted by risk_score DESC.

**Dependencies:** P4-01, P4-02, P2-02 (Finding model).

---

### TICKET P4-05: Findings API + Findings UI

**Priority:** 🔴 Must-have

**Task Description:**
Build the findings API (`GET /api/v1/findings` with filters: severity, status, type, owner, asset) and the Findings UI (S6: list + S7: detail). The detail page shows: severity badge, evidence block, risk context, remediation, algorithm map, assignment, history timeline.

**Acceptance Criteria:**
- [ ] GET /findings returns paginated, filterable list.
- [ ] Filters: severity (critical/high/medium/low/info), status (open/in_progress/resolved/accepted/false_positive), type, owner.
- [ ] Status badges: Open=red, In Progress=yellow, Resolved=green, Accepted=gray.
- [ ] Finding detail page shows: header (severity badge, type, asset link), evidence (collapsible JSON), risk context (HNDL exposure), remediation text, algorithm map.
- [ ] "Change Status" dropdown: analyst+ can change open→in_progress→resolved/accepted.
- [ ] "Assign" button: admin+ can assign finding to any user.
- [ ] "Re-scan" button: triggers re-scan of the parent asset.
- [ ] "Mark as False Positive" marks status=accepted with optional reason.

**Dependencies:** P4-04 (findings API), P1-04 (app shell).

---

## Phase 5: Dashboard & Reporting (Weeks 8–10)

---

### TICKET P5-01: Dashboard aggregation API

**Priority:** 🔴 Must-have

**Task Description:**
Create `backend/app/api/dashboard.py` with three endpoints: `GET /api/v1/dashboard/summary` (executive KPIs), `GET /api/v1/dashboard/risk-distribution` (severity counts), `GET /api/v1/dashboard/progress` (migration trend over last 12 scans). All queries must use efficient SQL with indexes.

**Acceptance Criteria:**
- [ ] `GET /dashboard/summary` returns: `pqc_readiness_score` (0-100 float), `total_assets`, `vulnerable_count`, `hybrid_count`, `pqc_ready_count`, `critical_findings`, `high_findings`, `drift_alerts_count`.
- [ ] `GET /dashboard/risk-distribution` returns counts per severity level.
- [ ] `GET /dashboard/progress` returns array of `{scan_date, vulnerable, hybrid, pqc_ready}` for last 12 completed scans.
- [ ] All three endpoints respond in < 500ms on a database with 1000 assets.
- [ ] Cache layer: Redis TTL 5 minutes for dashboard endpoints (configurable via env).
- [ ] Queries use existing indexes — verify with `EXPLAIN ANALYZE` in docs.

**Dependencies:** P4-04 (findings table populated), P2-01 (indexes exist).

---

### TICKET P5-02: Executive dashboard UI

**Priority:** 🔴 Must-have

**Task Description:**
Build the Executive Dashboard (`/`) using Recharts. Render: circular gauge for PQC Readiness Score, donut chart for risk distribution, bar chart for HNDL timeline, table for top 10 vulnerable assets, line chart for migration progress, horizontal bars for scan coverage, drift alerts card.

**Acceptance Criteria:**
- [ ] Gauge shows percentage with color: red <30%, yellow 30-70%, green >70%.
- [ ] Donut chart segments match severity colors: critical=red, high=orange, medium=yellow, low=green, pqc-ready=emerald.
- [ ] HNDL bar chart groups assets by "years until quantum risk" buckets: 0-3, 4-7, 8-12, 13+.
- [ ] Top 10 table: scrollable rows showing asset name, algorithm, risk score (color), owner, action button.
- [ ] Migration progress line chart: x-axis = scan date, y-axis = % PQC-ready (latest N scans).
- [ ] Drift alerts card shows count with link to filtered findings list.
- [ ] All charts use Inter for labels, JetBrains Mono for algorithm names.
- [ ] Gauge and donut render without animation on first load (respects `prefers-reduced-motion`).
- [ ] Empty state: if no scans, show onboarding CTA.

**Dependencies:** P5-01, P1-05 (dashboard shell), P0-04 (Recharts installed).

---

### TICKET P5-03: Operational dashboard UI

**Priority:** 🟡 Should-have

**Task Description:**
Build Operational Dashboard (`/dashboard/ops`) showing: scan queue (active/completed/failed with status badges), team backlog (findings grouped by owner), drift alerts table, new discoveries count, coverage gaps (assets not scanned in 30+ days).

**Acceptance Criteria:**
- [ ] Scan queue table: columns for scan_id, type, target, status (badge), start time, duration, assets found, findings count.
- [ ] Status badges: Queued=gray, Running=blue (animated pulse), Completed=green, Failed=red.
- [ ] Team backlog grouped by assigned_to user (or "Unassigned" group).
- [ ] Each user row shows: name, open count, in_progress count.
- [ ] Clicking a user filters the Findings list by that user.
- [ ] Coverage gaps section lists assets where `last_verified_at` > 30 days ago.

**Dependencies:** P5-01.

---

### TICKET P5-04: CBOM export — CycloneDX JSON

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/services/report_service.py` with `generate_cbom(scope_filters)` using cyclonedx-python-lib. Iterate over filtered assets, add certificates and algorithms as BOM components with PQC-specific properties. Output valid CycloneDX JSON.

**Acceptance Criteria:**
- [ ] `POST /api/v1/reports` with `report_type="cbom"` enqueues a report generation task.
- [ ] Output follows CycloneDX 1.5 schema (validate against official JSON schema).
- [ ] Each asset = BOM component with `type: "application"` and PQC properties.
- [ ] Each certificate = BOM component with properties: `algorithm`, `key_size`, `pqc_status`, `not_after`.
- [ ] Each algorithm = BOM component with properties: `algorithm_name`, `algorithm_type`, `pqc_status`.
- [ ] Metadata includes: tool name "PQCrypt Sentinel", version, generation timestamp.
- [ ] Report status tracked in `reports` table: pending → generating → ready (or failed).
- [ ] Large exports (>1000 assets) do not OOM — streamed in batches.

**Dependencies:** P2-03 (schemas), P4-04 (findings/assets tables).

---

### TICKET P5-05: Reports page UI

**Priority:** 🔴 Must-have

**Task Description:**
Build Reports page (`/reports`) with: report type selector (CBOM, Executive, Compliance NIST/CISA/NCSC/DORA/UK-NCSC, Migration Progress), scope selector (all assets / filtered by service / owner), format selector (JSON/PDF/CSV), generate button, report history table with download links.

**Acceptance Criteria:**
- [ ] Report type dropdown: CBOM, Executive Summary, Compliance (NIST/CISA/NCSC/DORA/UK-NCSC), Migration Progress.
- [ ] Scope options: All Assets, Filter by Business Service, Filter by Owner.
- [ ] Format: JSON (CBOM), PDF (Executive/Compliance), CSV (raw data).
- [ ] "Generate Report" button shows loading state → progress → download link.
- [ ] Report history table: report_type badge, format, generated_at, size, download button.
- [ ] CBOM download triggers browser download of `.json` file.
- [ ] PDF report includes: executive summary, top 10 findings, risk distribution chart, migration progress chart (generated server-side via WeasyPrint).

**Dependencies:** P5-04 (report service).

---

### TICKET P5-06: Asset Explorer UI — table with filters

**Priority:** 🔴 Must-have

**Task Description:**
Build Asset Explorer (`/assets`) — a filterable, sortable, paginated table of all discovered crypto assets. Columns: Name, Type icon, IP/FQDN, Primary Algorithm, PQC Status (badge), Risk Score (color), Owner, Last Scanned. Include search bar and filter panel (collapsible sidebar).

**Acceptance Criteria:**
- [ ] Search bar: full-text across asset name, IP, FQDN (case-insensitive).
- [ ] Filter panel: Algorithm type, PQC status, Risk level, Owner, Business Service, Discovery source, Last scanned date range.
- [ ] Table sortable by clicking column headers (default: risk_score DESC).
- [ ] Pagination: 50 items per page, page controls at bottom.
- [ ] Bulk actions: select multiple rows → Assign owner, Change status, Export CSV.
- [ ] "Export CBOM" button: triggers CBOM generation for filtered set.
- [ ] Empty state: "No assets match your filters" with "Clear Filters" button.
- [ ] Click asset row → navigate to `/assets/{id}`.
- [ ] PQC Status badge: Vulnerable=red, Transitioning=yellow, Hybrid=blue, PQC-Ready=green.

**Dependencies:** P5-01 (asset API), P1-04 (app shell).

---

### TICKET P5-07: Asset Detail UI — tabbed view

**Priority:** 🟡 Should-have

**Task Description:**
Build Asset Detail page (`/assets/{id}`) with header (asset name, type icon, IP/FQDN, owner badge, risk gauge) and tabbed content: Overview, Algorithms, Certificates, Findings, Dependencies, History.

**Acceptance Criteria:**
- [ ] Header shows: asset name (H1), IP/FQDN, asset type badge, owner badge, risk score badge (color-coded).
- [ ] Overview tab: asset type, discovery source, first discovered, last scanned, business service, environment, metadata JSON viewer.
- [ ] Algorithms tab: table of all algorithms for this asset (from latest scan).
- [ ] Certificates tab: table of all certs with thumbprint, subject, issuer, sig alg, key size, expiry, PQC status.
- [ ] Findings tab: all findings for this asset, sortable by severity, status.
- [ ] Dependencies tab (Phase 3): force graph placeholder — show "Connect a CMDB for dependency data."
- [ ] History tab: timeline of scan results showing algorithm changes over time.
- [ ] "Re-scan" button: triggers immediate scan of this single asset.
- [ ] "Assign Owner" button: inline user search dropdown.
- [ ] "Create Ticket" button: placeholder (Phase 2 integration).

**Dependencies:** P5-06 (asset explorer).

---

## Phase 6: Connectors (Weeks 10–14)

---

### TICKET P6-01: Connector base class + scheduling framework

**Priority:** 🔴 Must-have

**Task Description:**
Create the base connector interface in `backend/app/connectors/base.py`. Define: `connect()`, `sync()`, `disconnect()`, `test_connection()`. Create `ConnectorManager` service that schedules connector sync jobs via Celery Beat. Base tests stub.

**Acceptance Criteria:**
- [ ] `BaseConnector` is an abstract class with `connect`, `sync`, `disconnect`, `test_connection` as abstractmethods.
- [ ] `ConnectorManager` takes a connector config, instantiates the right subclass, and calls `sync()`.
- [ ] Connector status tracked: pending → connected → error / disabled.
- [ ] `test_connection()` updates `connector.last_sync_at` on success.
- [ ] Failed syncs set `connector.status = "error"` and `connector.last_error = <message>`.
- [ ] Connector registration: adding a new connector type is a single file in `backend/app/connectors/` + one line in a registry dict.

**Dependencies:** P2-02 (Connector model).

---

### TICKET P6-02: CSV Import connector (MVP CMDB)

**Priority:** 🔴 Must-have

**Task Description:**
Implement CSV import as the first CMDB integration. Accept a CSV with columns: name, asset_type, ip_address, fqdn, port, owner_email, business_service, environment. Parse, deduplicate on (ip_address, port), upsert into assets table.

**Acceptance Criteria:**
- [ ] `POST /api/v1/connectors/csv_import` with multipart form-data CSV file.
- [ ] CSV parser handles UTF-8 with BOM.
- [ ] Columns: name (required), asset_type (required), ip_address (required), fqdn, port, owner_email, business_service, environment.
- [ ] Duplicate IP:port entries are skipped with a log message (not error).
- [ ] Owner email not found in users table: asset created without owner (no crash).
- [ ] Returns 200 with: `imported: N, skipped: M, errors: K`.
- [ ] Errors per row (wrong format, missing required fields) collected and returned in response body.
- [ ] Max file size: 50MB.

**Dependencies:** P6-01, P2-02 (Asset model).

---

### TICKET P6-03: Connectors management UI

**Priority:** 🔴 Must-have

**Task Description:**
Build Connectors page (`/settings/connectors`) with connector cards showing: connector name, type, status indicator (green/yellow/gray), last sync timestamp. "Add Connector" button opens type-specific form. "Test Connection" and "Sync Now" buttons per connector.

**Acceptance Criteria:**
- [ ] Connector list shows: name, type (rounded badge), status dot (green=connected, yellow=error, gray=not configured).
- [ ] "Add Connector" button: type selector → type-specific form fields (see App Flow doc S11 for field list per type).
- [ ] CSV Import form: file upload + preview of first 5 rows before confirming.
- [ ] "Test Connection" button: calls connector.test_connection(), shows spinner → success/error toast.
- [ ] "Sync Now" button: triggers immediate sync, status changes to "running" → "completed" / "error".
- [ ] ServiceNow connector form: instance URL, username, password, table prefix.
- [ ] NetBox connector form: URL, API token.
- [ ] AWS connector form: access key, secret key, region.
- [ ] All credential fields are type="password" with show/hide toggle.
- [ ] Credentials are not stored in the browser — submitted directly to API.

**Dependencies:** P6-02 (at least CSV working), P1-04 (app shell).

---

### TICKET P6-04: Certificate Transparency log monitor

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/scanners/ct_log_monitor.py`. Poll `https://crt.sh` API for certificates matching the organization's domains (configurable domain list). Parse response, extract new certs not yet in the `certificates` table, and upsert them.

**Acceptance Criteria:**
- [ ] `poll_ct_log(domains: list[str])` calls `https://crt.sh/?q={domain}&output=json`.
- [ ] New certs (thumbprint not in `certificates` table) are inserted.
- [ ] Duplicate certs (same thumbprint, different domain entry) use existing cert row.
- [ ] CT monitor runs as a Celery Beat task: every 6 hours.
- [ ] If `OFFLINE_MODE=true`, CT polling is skipped (no error).
- [ ] If crt.sh is unreachable: error logged, task retried on next schedule (no crash).
- [ ] Maximum batch: 10,000 certs per poll to avoid OOM.

**Dependencies:** P3-01 (Celery Beat), P2-02 (Certificate model).

---

## Phase 7: Migration Tracking & Drift Detection (Weeks 14–16)

---

### TICKET P7-01: Migration progress tracker — scan-over-scan diff engine

**Priority:** 🔴 Must-have

**Task Description:**
Implement `backend/app/analysis/diff_engine.py`. Given two scan IDs (current vs previous), compare: new assets appeared, removed assets, algorithms changed (e.g., RSA-2048 → ML-KEM-768), new findings, resolved findings, regressions (PQC-ready → vulnerable).

**Acceptance Criteria:**
- [ ] `compute_diff(prev_scan_id, curr_scan_id)` returns: `{new_assets, removed_assets, algo_changes, new_findings, resolved_findings, regressions}`.
- [ ] Algorithm change detected when same asset has different `algorithm_name` in consecutive scans.
- [ ] Regression detected when asset's `pqc_status` changed from `hybrid` or `pqc_ready` → `vulnerable`.
- [ ] Regression finding created: "Regression detected: {asset.name} reverted to {old_algo}".
- [ ] Diff result stored in `scans.results` JSONB under key `diff_from_previous`.
- [ ] Results viewable in S9 (Scan Detail) "Diff from previous" section.

**Dependencies:** P4-04 (findings engine).

---

### TICKET P7-02: Migration progress dashboard UI

**Priority:** 🟡 Should-have

**Task Description:**
Build Migration Progress page (`/migration`) with: overall progress gauge (overall % PQC-ready), trend line chart (6vulnerable → hybrid → PQC-ready over 12 scans), by-algorithm stacked bar, by-business-service table, by-deadline timeline, regression alerts table.

**Acceptance Criteria:**
- [ ] Overall progress: large gauge showing % of assets that are hybrid or PQC-ready.
- [ ] Trend line chart: x-axis = scan date, 3 lines: % vulnerable, % hybrid, % PQC-ready.
- [ ] By-algorithm: stacked bar showing RSA/ECC/ML-KEM/ML-DSA distribution.
- [ ] By-service table: service name, % migrated, findings count, owner.
- [ ] Regression alerts: table of assets where status went backward, with timestamp.
- [ ] All data from `migration_progress` table queried via dedicated API endpoint.
- [ ] CSV export of migration data available.

**Dependencies:** P7-01.

---

### TICKET P7-03: Drift detection — automated regression alerting

**Priority:** 🟡 Should-have

**Task Description:**
Implement a Celery Beat task that runs every 24 hours: takes the latest scan, compares it to the previous scan, identifies any regressions, and sends alerts (Slack webhook + email) to configured recipients.

**Acceptance Criteria:**
- [ ] Celery Beat task `run_drift_check` fires on schedule.
- [ ] If regressions found: POST to `SLACK_WEBHOOK_URL` (if configured) with summary.
- [ ] If SMTP configured: send email to `SMTP_FROM_ADDRESS` with regression details.
- [ ] Drift alert also shown in the Operational Dashboard's "Drift Alerts" card.
- [ ] No alert sent if `OFFLINE_MODE=true`.
- [ ] Task logs its run to `scan_logs` (not `scan_logs` for this — create `drift_logs` or reuse with phase field).
- [ ] Testable without real Slack/email: use a logging handler that captures alerts in dev mode.

**Dependencies:** P7-01.

---

## Phase 8: Testing, Security & Deployment (Weeks 16–20)

---

### TICKET P8-01: Unit test suite — backend ≥ 80% coverage

**Priority:** 🔴 Must-have

**Task Description:**
Write pytest unit tests for all pure-logic modules: `algo_classifier`, `risk_scorer`, `mosca_model`, `diff_engine`, `vendor_db`, `sanitize_output`. Target: 80%+ coverage on `backend/app/analysis/` and `backend/app/scanners/` modules that don't require network.

**Acceptance Criteria:**
- [ ] `pytest --cov=backend/app/analysis --cov=backend/app/scanners --cov-fail-under=80` passes.
- [ ] Test files mirror source: `test_algo_classifier.py`, `test_risk_scorer.py`, etc.
- [ ] All PQC OID map entries tested (at least one assert per OID family).
- [ ] Risk score tested at boundary values (0, 50, 100).
- [ ] Mosca's theorem tested with data_longevity = 0, 10, 50, 100.
- [ ] Credential sanitizer tested with fuzzed inputs.
- [ ] Tests run in CI (GitHub Actions) on every PR.

**Dependencies:** P4-01, P4-02, P4-03.

---

### TICKET P8-02: Integration test suite — API endpoints

**Priority:** 🔴 Must-have

**Task Description:**
Write integration tests using `httpx.AsyncClient` and a test database fixture (PostgreSQL test database or SQLite in-memory for non-Postgres-specific queries). Cover: auth flow (login → refresh → access protected endpoint), scan lifecycle (create → list → detail), findings CRUD, connector CRUD.

**Acceptance Criteria:**
- [ ] `test_auth.py`: login with wrong password → 401, login with correct password → 200 with tokens, access protected endpoint with valid token → 200, expired token → 401.
- [ ] `test_scans.py`: create scan → 202 with scan ID, list scans → 200 with list, get scan detail → 200.
- [ ] `test_findings.py`: update finding status as analyst → 200, as viewer → 403.
- [ ] `test_connectors.py`: create CSV connector → 201, list connectors → 200, test connection → 200.
- [ ] All tests use a shared `conftest.py` with database fixture (transaction rollback per test).
- [ ] No external network calls in tests (all mocked with `respx` or `unittest.mock`).

**Dependencies:** P2-02 (models), P1-02 (auth), P3-02 (scan API).

---

### TICKET P8-03: Docker multi-stage build optimization

**Priority:** 🔴 Must-have

**Task Description:**
Convert the three Dockerfiles to multi-stage builds: builder stage installs build dependencies, compiles frontend, installs Python wheels; runtime stage copies only the final artifacts. Target API image < 800MB, worker image < 2GB (heavier due to tshark/nmap).

**Acceptance Criteria:**
- [ ] `docker build` for api service: image size < 800MB.
- [ ] `docker build` for worker service: image size < 2GB.
- [ ] Frontend build artifacts (static HTML/CSS/JS) served by Nginx from the frontend Dockerfile.
- [ ] Builder stage uses Python slim + node LTS; runtime stage uses python:slim only.
- [ ] `.dockerignore` excludes node_modules, __pycache__, .git, .env, pgdata, test files from build context.
- [ ] `docker-compose up` builds all three images and starts the platform.

**Dependencies:** P0-06 (system binaries installed).

---

### TICKET P8-04: Production docker-compose with env vars + secrets

**Priority:** 🔴 Must-have

**Task Description:**
Write the production-ready `docker-compose.yml` at repo root. All secrets via environment variables or Docker secrets. Include health checks, resource limits, restart policies. Write companion `.env.example` with all required variables documented.

**Acceptance Criteria:**
- [ ] `docker-compose.yml` has `secrets:` section or `environment:` arrays (no hardcoded values).
- [ ] Each service has `healthcheck` (curl/wget for API, redis-cli ping for Redis, pg_isready for Postgres).
- [ ] `deploy.resources.limits` set on each service (CPU, memory).
- [ ] `restart: unless-stopped` on all services.
- [ ] Nginx serves React static files from `frontend/dist/` and proxies `/api/` to FastAPI.
- [ ] Running `docker compose up` from clean checkout starts the platform with `database/` auto-created.
- [ ] `.env.example` has every variable from Section 4 of Technical Architecture Document.

**Dependencies:** P0-02, P8-03.

---

### TICKET P8-05: Security audit — OWASP Top 10 review

**Priority:** 🔴 Must-have

**Task Description:**
Conduct and document a security audit covering all OWASP Top 10 (2021) categories against the application. Use Trivy for dependency scanning, Semgrep for SAST, manual review for auth and credential handling. Fix all HIGH and CRITICAL findings before launch.

**Acceptance Criteria:**
- [ ] Trivy scan on final Docker images: zero CRITICAL vulnerabilities, all HIGH remediated or accepted with documented rationale.
- [ ] `npm audit` and `pip audit` show no known vulnerabilities in production dependencies.
- [ ] Broken Access Control review: every endpoint checked for RBAC enforcement. Documented as "PASS" or list of fixes made.
- [ ] Cryptographic Failures review: SECRET_KEY generation verified, bcrypt cost factor confirmed, no secrets in git.
- [ ] Injection review: SQLAlchemy ORM used everywhere, no raw SQL in production code. Pre-commit Ruff rule enforces no `execute(text(...))` without review.
- [ ] Insecure Design review: tiered credential model reviewed and documented.
- [ ] Security Misconfiguration review: CORS origins restricted, debug mode off in production, error messages stripped of stack traces.
- [ ] Vulnerable and Outdated Components: all dependencies at latest stable versions.
- [ ] Identification and Authentication Failures: password policy (min 8 chars), bcrypt cost 12, rate limiting on login implemented and tested.
- [ ] Software and Data Integrity Failures: CI pipeline includes dependency pinning and SRI hashes.
- [ ] Security Logging and Monitoring Failures: structured JSON logging on, audit events capture auth and scan operations.
- [ ] Server-Side Request Forgery (SSRF): scanner workers validated to not send requests to internal metadata endpoints (169.254.169.254).

**Dependencies:** P8-03, P8-04 (production image exists).

---

## Phase 9: Polish & Launch (Weeks 20–24)

---

### TICKET P9-01: Onboarding wizard — first-run experience

**Priority:** 🟡 Should-have

**Task Description:**
Build a 3-step onboarding wizard that appears after first login if no scans have been run. Step 1: "Connect your first target" (CSV import or enter IP range). Step 2: "Run your first scan". Step 3: "View results" (redirects to executive dashboard).

**Acceptance Criteria:**
- [ ] Wizard triggered when: user is authenticated AND zero scans exist.
- [ ] Step 1: CSV import or manual IP/domain entry. Skip button for "I'll do this later."
- [ ] Step 2: simple scan creation form (scan type: "TLS Only", target: pre-filled from Step 1).
- [ ] Step 3: links to Executive Dashboard and shows "Run your first scan" CTA with status.
- [ ] Wizard can be dismissed and re-opened via settings.
- [ ] Wizard uses `localStorage` flag `onboarding_completed` to not re-show.

**Dependencies:** P6-02 (CSV import).

---

### TICKET P9-02: Notification service — email + Slack webhook

**Priority:** 🟡 Should-have

**Task Description:**
Implement `backend/app/services/notification_service.py`. Send email via SMTP and Slack messages via incoming webhook. Used for: scan completion alerts, drift regression alerts, expiry alerts. Make email/Slack optional (no crash if not configured).

**Acceptance Criteria:**
- [ ] `send_email(to, subject, body)` uses `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` env vars.
- [ ] `send_slack_message(text)` POSTs to `SLACK_WEBHOOK_URL`.
- [ ] Both functions silently no-op if their env vars are not set (MVP: no alert services configured by default).
- [ ] Drift alert message format: 🚨 PQC Regression detected: {asset.name} reverted from {old_algo} to {new_algo}. Scan: {scan_id}.
- [ ] Email template: plain-text only (HTML emails are Phase 2).
- [ ] Notification service injected into drift detection task (P7-03) and expiry check task.

**Dependencies:** P7-03.

---

### TICKET P9-03: Complete API documentation (OpenAPI + README)

**Priority:** 🔴 Must-have

**Task Description:**
Ensure FastAPI auto-generates complete OpenAPI 3.1 spec with all schemas, examples, and error responses documented. Write backend README with: local setup, env vars, running tests, Docker Compose commands, troubleshooting. Generate static API docs via `fastapi.openapi` route.

**Acceptance Criteria:**
- [ ] `/api/v1/auth/docs` (Swagger UI) renders all endpoints with request/response schemas.
- [ ] `/api/v1/auth/openapi.json` returns valid OpenAPI 3.1 JSON with all routes.
- [ ] Each endpoint has a docstring with: summary, description, request body schema, response schema, error codes.
- [ ] Authentication flow documented with example login request/response.
- [ ] Backend README covers: install, run, test, docker-compose, env vars, troubleshooting.
- [ ] API docs include example curl commands for each endpoint.

**Dependencies:** All API tickets (P1, P3, P4, P5, P6, P7).

---

### TICKET P9-04: Error boundary + global error handler

**Priority:** 🔴 Must-have

**Task Description:**
Implement a global exception handler in FastAPI that catches all unhandled exceptions and returns the structured error envelope. Add a React Error Boundary component that catches frontend render errors and shows a friendly fallback UI (with request ID for support).

**Acceptance Criteria:**
- [ ] `app.exception_handler(Exception)` returns structured 500 error with `code`, `message`, `detail`, `request_id`, `timestamp`.
- [ ] Validation errors (Pydantic) return 422 with field-level error details.
- [ ] HTTPException (auth errors, etc.) return the same envelope.
- [ ] Backend logs full traceback via `logging.exception()` before returning sanitized response.
- [ ] React Error Boundary catches render errors, shows "Something went wrong" with error ID.
- [ ] Frontend error handler captures JS errors via `window.onerror` and sends to backend `/api/v1/errors` (lightweight, no PII).
- [ ] No raw Python tracebacks reach the browser in any response.

**Dependencies:** P1-01 (auth API).

---

### TICKET P9-05: Final regression + launch readiness checklist

**Priority:** 🔴 Must-have

**Task Description:**
Run the complete checklist before launch. Fix any remaining blockers. Ensure docker-compose deploys cleanly on a fresh VM.

**Acceptance Criteria:**
- [ ] Fresh Ubuntu 22.04 VM: clone repo, `cp .env.example .env`, `docker-compose up`, open browser to `http://localhost` → Login page loads.
- [ ] Create admin account, log in, navigate all 14 screens without console errors.
- [ ] Run first scan: must produce at least 1 finding on a test target (scanme.nmap.org).
- [ ] Dashboard shows data after running a scan (no blank states).
- [ ] All 5 security docs reviewed: PRD, Technical Architecture, Security & Access, Frontend Spec, Feature Tickets.
- [ ] `.env.example` documented: every variable has a comment explaining purpose.
- [ ] `SECRET_KEY` must be regenerated for actual deployment (not the example value).
- [ ] Performance test: scan 100 local ports completes in under 2 minutes.
- [ ] Error handling tested: invalid scan target → 422 with clear message, not 500.

**Dependencies:** All Phase 0–8 tickets.

---

## Quick-Reference: Dependency Graph

```
P0-01  →  P0-02  →  P0-03  →  P1-01  →  P1-02
P0-01  →  P0-04  →  P1-03  →  P1-04  →  P1-05 (Dashboard shell)
                                P1-04  →  P1-06 (User Mgmt)
P0-02  →  P0-06  →  P3-01 (Celery)
P0-06  →  P3-03  →  P3-04  →  P5-01  →  P5-02 (Exec Dashboard)
             P3-05  →  P3-07  →  P3-08  →  P3-09 (Orchestrator)  ← critical path
P3-09  →  P3-10 (Passive)  /  P3-11 (Discovery) / P3-12 (Scan UI)
P4-01  →  P4-02  →  P4-03  →  P4-04 (Findings Engine)  ← risk path
P4-04  →  P5-01  →  P5-06 (Asset Explorer) / P4-05 (Findings UI)
P5-04  →  P5-05 (Reports UI)
P6-01  →  P6-02  →  P6-03 (Connectors UI)  ← CMDB path
P3-01  →  P6-04 (CT Log Monitor)
P4-02  →  P7-01 (Diff Engine)  →  P7-03 (Drift)  →  P7-02 (Migration UI)
```

---

## Summary: Must-Have vs Should-Have vs Nice-to-Have

| Ticket | Title | Priority | Phase |
|---|---|---|---|
| P0-01 | Monorepo structure | Must-have | 0 |
| P0-02 | Docker Compose skeleton | Must-have | 0 |
| P0-03 | Backend scaffolding + Alembic | Must-have | 0 |
| P0-04 | Frontend scaffolding | Must-have | 0 |
| P0-05 | CI/CD pipeline | Must-have | 0 |
| P0-06 | Scanner tool Docker image | Must-have | 0 |
| P1-01 | Auth API (login/logout/JWT) | Must-have | 1 |
| P1-02 | RBAC middleware | Must-have | 1 |
| P1-03 | Login UI | Must-have | 1 |
| P1-04 | App shell | Must-have | 1 |
| P1-05 | Dashboard shell | Must-have | 1 |
| P1-06 | User Management | Must-have | 1 |
| P2-01 | All 11 tables via Alembic | Must-have | 2 |
| P2-02 | SQLAlchemy models | Must-have | 2 |
| P2-03 | Pydantic schemas | Must-have | 2 |
| P3-01 | Celery worker infra | Must-have | 3 |
| P3-02 | Scan CRUD API | Must-have | 3 |
| P3-03 | TLS active scanner | Must-have | 3 |
| P3-04 | SSH scanner | Must-have | 3 |
| P3-05 | Cert parser + PQC OID | Must-have | 3 |
| P3-07 | PQCan CLI wrapper | Must-have | 3 |
| P3-09 | Scan orchestrator | Must-have | 3 |
| P3-12 | Scan UI (list/create/detail) | Must-have | 3 |
| P4-01 | Algorithm classifier | Must-have | 4 |
| P4-02 | Risk scoring engine | Must-have | 4 |
| P4-04 | Findings generator | Must-have | 4 |
| P4-05 | Findings API + UI | Must-have | 4 |
| P5-01 | Dashboard aggregation API | Must-have | 5 |
| P5-02 | Executive Dashboard UI | Must-have | 5 |
| P5-04 | CBOM export | Must-have | 5 |
| P5-05 | Reports UI | Must-have | 5 |
| P5-06 | Asset Explorer UI | Must-have | 5 |
| P6-01 | Connector base class | Must-have | 6 |
| P6-02 | CSV Import connector | Must-have | 6 |
| P6-03 | Connectors UI | Must-have | 6 |
| P6-04 | CT Log monitor | Must-have | 6 |
| P7-01 | Scan diff engine | Must-have | 7 |
| P8-01 | Unit tests (80% coverage) | Must-have | 8 |
| P8-02 | Integration tests | Must-have | 8 |
| P8-03 | Docker multi-stage build | Must-have | 8 |
| P8-04 | Production docker-compose | Must-have | 8 |
| P8-05 | Security audit | Must-have | 8 |
| P9-03 | API documentation | Must-have | 9 |
| P9-04 | Error boundary | Must-have | 9 |
| P9-05 | Launch readiness checklist | Must-have | 9 |
| P3-06 | scapy PQC group probe | Should-have | 3 |
| P3-08 | testssl.sh + ssh-audit wrap | Should-have | 3 |
| P3-10 | Passive pyshark monitor | Should-have | 3 |
| P3-11 | Network discovery (nmap) | Should-have | 3 |
| P4-03 | Mosca's/HNDL calculator | Should-have | 4 |
| P5-03 | Operational dashboard | Should-have | 5 |
| P5-07 | Asset Detail page | Should-have | 5 |
| P7-02 | Migration progress UI | Should-have | 7 |
| P7-03 | Drift detection alerts | Should-have | 7 |
| P9-01 | Onboarding wizard | Should-have | 9 |
| P9-02 | Email/Slack notifications | Should-have | 9 |

---

*End of Feature Ticket List — 55 tickets total: 42 Must-have, 10 Should-have, 0 Nice-to-have in MVP scope.*
