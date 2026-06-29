# PQC Scanner — Project Briefing (Intensive)

> **Purpose:** Single-pass context rebuild for any developer or AI session picking up this project cold.
> **Last updated:** 2026-06-06
> **Status:** Phases 1-5.4 complete; 10/10 priority security fixes shipped; coverage 63% (target 85%).

---

## 1. Mission

Build a **comprehensive on-prem Post-Quantum Cryptography (PQC) scanner** at `D:\Project Files\PQC_Scanner\` that:
- Discovers cryptographic assets across an entire enterprise inventory.
- Detects quantum-vulnerable algorithms (RSA, ECDSA, DH, AES-128, 3DES, TLS 1.0/1.1, MD5, SHA-1).
- Maps findings to a **7-layer infrastructure model** (L1 Network → L7 Endpoint).
- Computes a **5-dim weighted risk score** (HNDL 30, Exposure 20, Algorithm 20, Replaceability 15, Regulatory 15).
- Produces a **CycloneDX v1.7 Cryptographic Bill of Materials (CBOM)** for EO 14028 / CISA compliance.
- Renders a **React + TypeScript** dashboard with readiness, drift, layer coverage, and migration roadmap.

**Deployment target:** On-prem Docker Compose. **No external cloud dependencies.**

---

## 2. Tech Stack (Locked)

### Backend (`D:\Project Files\PQC_Scanner\backend\`)
- **Python 3.11** + **FastAPI 0.115+** (async)
- **SQLAlchemy 2.0 async** + **asyncpg** (PostgreSQL 16 in prod; SQLite+aiosqlite in tests)
- **Alembic** is **NOT** used — schema created via `Base.metadata.create_all` in `main.py` lifespan (known gap, see §10)
- **Celery** + **Redis** broker
- **pydantic v2** for schemas, `pydantic-settings` for config
- **cryptography ≥ 42** for X.509 parsing; **paramiko** for SSH; **cyclonedx-python-lib 11.x**
- **Optional:** sslyze, weasyprint, sslyze, scapy, pqcscan, ssh-audit (advanced scanners; gracefully skip when missing)

### Frontend (`D:\Project Files\PQC_Scanner\frontend\`)
- **React 18** + **TypeScript** + **Vite**
- **recharts** for charts; **react-router** for routing
- **No client-side cache** (no axios/swrv/tanstack-query) — known gap
- JWT in localStorage — known security gap (XSS exposure)

### Infra
- `docker-compose.yml`: postgres + redis + api + worker
- `nginx` reverse proxy; `frontend` served as static build

---

## 3. File Layout (must-know paths)

```
backend/
  app/
    main.py                    # FastAPI app + lifespan (Redis ping, create_all)
    config.py                  # Pydantic settings; QUANTUM_TIMELINE_YEAR=2034
    celery_app.py              # Celery app; no task_routes/ack_late — gap
    tasks.py                   # _run_async() helper; no asyncio.get_event_loop()
    db.py                      # AsyncSessionLocal; pool_size=5, max_overflow=10 (gap: too small)
    models/
      models.py                # SQLAlchemy: Asset, Certificate, Algorithm, Finding, Scan, ScanLog, Report, User
      schemas.py               # Pydantic: ScanIn/Out, FindingOut, etc.
    services/
      scan_orchestrator.py     # ScanOrchestrator.run_scan(); per-host savepoint; SSRF guard
      scan_host.py             # per-host scan routine (parallel port probes)
      finding_service.py       # generate_findings() — DEDUPE_KEY missing scan_id (gap)
      risk_service.py          # 5-dim risk + deprecation; 3DES in DISALLOWED_NOW
      layer_service.py         # L1-L7 layer mapping (BitLocker=L7; gap: should be L6)
      l1_finding_service.py    # OCSP/DNSSEC → Finding mapping
      report_service.py        # CBOM, SARIF, CSV, PDF; post_process_cbom
      dashboard.py             # /summary, /risk-distribution, /progress, /layer-coverage
    scanners/
      tls_scanner.py           # _do_tls_connect; verify_tls=True default (fixed)
      ssh_scanner.py           # KEX + host key detection
      ike_scanner.py           # IKEv2 probe; ML-KEM hybrid groups
      mail_scanner.py          # SMTP/STARTTLS/SMTPS
      cert_parser.py           # X.509 parse; pqc_status nested in pqc_details
      ocsp_dnssec_scanner.py   # L1 probes
      scapy_probe.py           # PQC group probe
      sslyze_scanner.py        # Advanced deep TLS scan
      safe_target.py           # SSRF guard; defaults now 0/0/0/0 (fixed)
      network_discovery.py     # nmap wrapper (gap: no --host-timeout)
      pyshark_capture.py       # Passive SPAN/pcap (gap: RuntimeError on import without tshark)
    connectors/
      base.py                  # BaseConnector
      ssh_connector.py         # RejectPolicy default; PQC_SSH_AUTO_ADD_HOST_KEY=1 opt-in (fixed)
      winrm_connector.py       # gap: no enforced ssl=True
      pkcs11_connector.py      # HSM/ADCS
      cloud_kms_connector.py   # AWS/Azure/GCP
      k8s_connector.py         # gap: API cert not classified
      tde_connector.py         # Oracle/SQL Server
      sast_connector.py        # Semgrep/Trivy (gap: no subprocess timeout)
      jwt_connector.py         # gap: alg=none not flagged
      winstore_connector.py    # L7 Windows Cert Store
      vault_helper.py          # ALLOW_ENV_FALLBACK=1 required (fixed); no log presence
    analysis/
      algo_classifier.py       # per-spec variant + 3DES + AES-128 Grover (fixed)
      mosca_model.py           # DEFAULT_QUANTUM_HORIZON_YEAR=2034 (fixed); MOSCA_HORIZON_YEAR env
    api/
      scans.py                 # create/list/get/delete/findings/l1-probe; dedup advisory lock
      assets.py                # CRUD
      findings.py              # CRUD; rescan
      reports.py               # CBOM/CSV/PDF (gap: PDF inline blocks event loop)
      scan_logs.py             # gap: no scan-level ACL
      dashboard.py             # /api/v1/dashboard/{summary,risk-distribution,progress,layer-coverage,health}
      connectors.py            # /run-connector (gap: long-running blocks event loop)
      auth.py                  # /login, /refresh, /logout
    auth/
      dependencies.py          # get_current_user; gap: no role/tenant claim
      jwt.py                   # HS256; gap: no kid/rotation
    utils/
      cache.py                 # RedisCache
      retry.py                 # @async_retry (gap: retries on IntegrityError)
  tests/                       # 451 passing, 2 skipped (asyncio mode=strict)
    conftest.py                # SQLite in-memory; Base.metadata.create_all=no-op
    test_security_fixes.py     # 26 tests for the 10 priority fixes
    test_orchestrator_run_scan.py  # 16 tests for the orchestrator
    test_report_service.py     # 20 tests for CBOM/SARIF/CSV/PDF
    test_api_dashboard_extra.py # 22 tests
    test_api_scans.py          # 11 tests
    ... (50+ test files)

frontend/
  src/
    pages/                     # Dashboard, Scans, Findings, Assets, Migration, Settings
    components/                # SeverityBadge (gap: missing info/unknown), charts
    api/client.ts              # gap: no retry, no 401 refresh, JWT in localStorage

docs/
  planning/
    implementation-plan.md     # 5-phase audit-fix plan (62 findings)
    todo-list.md               # 38-item checkbox list
  audit/
    AUDIT-2026-06-06.md        # Most recent audit (50+ findings; 10 priority)
  progress/
    PHASE-1.md ... PHASE-5.md
docker-compose.yml             # gap: no mem_limit, single worker, no concurrency env
```

---

## 4. Architecture (the 5+7+5 model)

### 5 Mechanisms (M1-M5)
| ID | Mechanism | File | Status |
|----|-----------|------|--------|
| M1 | Active TLS/SSH handshake probing | `scanners/tls_scanner.py`, `ssh_scanner.py`, `cert_parser.py` | ✅ |
| M2 | Passive SPAN/pcap | `scanners/pyshark_capture.py` | ⚠️ RuntimeError on import without tshark |
| M3 | Agentless SSH/WinRM | `connectors/ssh_connector.py`, `winrm_connector.py` | ✅ |
| M4a | PKCS#11 HSM | `connectors/pkcs11_connector.py` | ✅ |
| M4b | KMIP | same | ✅ (bug-fix only, v1.0) |
| M4c | Cloud KMS (AWS/Azure/GCP) | `connectors/cloud_kms_connector.py` | ✅ |
| M4d | ADCS | `connectors/pkcs11_connector.py` | ✅ |
| M4e | TDE (Oracle V$, SQL dm_database_encryption_keys) | `connectors/tde_connector.py` | ✅ |
| M4f | K8s (TLS secrets, etcd, API cert) | `connectors/k8s_connector.py` | ✅ |
| M5 | SAST (Py/Java/Go AST + manifests) | `connectors/sast_connector.py` | ✅ |

### 7 Layers (L1-L7)
| Layer | Name | Examples |
|-------|------|----------|
| L1 | Network | TLS, SSH, VPN/IKEv2, DNSSEC, OCSP, SMTP STARTTLS |
| L2 | PKI | Root CA, Intermediate CAs, TLS Server Certs, Code-signing, TSA |
| L3 | HSM/KMS | General HSMs, Payment HSMs (3DES), Cloud KMS |
| L4 | Application | JWT Algorithms, Container Images, API Crypto |
| L5 | Data | TDE Algorithms, Backup Encryption, Column-level Encryption |
| L6 | Infrastructure | SSH Host Keys, Kerberos RC4, Windows CNG/Schannel, **BitLocker (gap: mapped to L7, should be L6)** |
| L7 | Endpoint | Windows Cert Store, BitLocker, Firmware Signing |

### 5-dim Risk Model (locked 2026-06-05)
```
risk_score = 0.30 * HNDL_exposure      (Mosca X+Y>Z)
           + 0.20 * exposure            (network reach, authn required)
           + 0.20 * algorithm_score     (PQC-status, key size, deprecation year)
           + 0.15 * replaceability      (ease of replacement)
           + 0.15 * regulatory          (FIPS, PCI, HIPAA, GDPR)
```
`Business Criticality` was dropped from the original 6-dim model.

### Risk Engine
- **NIST IR 8547 deprecation timeline:** `services/risk_service.py:DEPRECATION_BY_YEAR`
- **RSA-3072 → 2030 deadline** (NIST SP 800-131A Rev.2)
- **Mosca HNDL model:** `analysis/mosca_model.py:DEFAULT_QUANTUM_HORIZON_YEAR=2034`; env override `MOSCA_HORIZON_YEAR`
- **TLS verify off by default** is now `True` (fixed); opt-in via `Scan.config["strict_tls"]=False`

### CBOM v1.7 (ECMA-424)
- `cyclonedx-python-lib 11.x` + `services/report_service.py:post_process_cbom` (line 58)
- Property ordering: `_CRYPTO_PROPERTIES_ORDER` (line 38-58)
- CBOM includes `cryptoProperties.algorithmProperties.{primitive, variant, nistQuantumSecurityLevel, classicalSecurityLevel, certificationLevel, parameterSetIdentifier}` and `cryptoProperties.pqcSafe`
- Fields populated: `oid` ✅; `curve` ✅; `nistQuantumSecurityLevel` ✅; `pqcSafe` ✅; `variant` per-spec ✅

---

## 5. Stakeholder Decisions (LOCKED — do not change without sign-off)

| Decision | Value | Date |
|----------|-------|------|
| Risk model | 5-dim: HNDL 30 / Exposure 20 / Algorithm 20 / Replaceability 15 / Regulatory 15 | 2026-06-05 |
| L1 batched with L4 JWT in Phase 3.7 | yes | 2026-06-05 |
| RSA-3072 → 2030 deadline | yes | 2026-06-05 |
| TLS verify default | **True** (was False, flipped 2026-06-06) | 2026-06-06 |
| SSRF default (loopback/private/link-local) | **deny** (was allow, flipped 2026-06-06) | 2026-06-06 |
| Vault env-var fallback | **deny** (was silent, now requires `ALLOW_ENV_FALLBACK=1`) | 2026-06-06 |
| KMIP v1.0 | fix bug only, mark `experimental: true` | 2026-06-05 |
| Mosca horizon | 2034 (was 2035) | 2026-06-06 |
| SSH host key policy | `RejectPolicy` (was `AutoAddPolicy`; opt-in via `PQC_SSH_AUTO_ADD_HOST_KEY=1`) | 2026-06-06 |
| Per-host scan session | `async with AsyncSessionLocal() as host_session:` + `begin_nested()` savepoint | 2026-06-06 |
| Celery asyncio | `asyncio.run()` via `_run_async()` helper (was `asyncio.get_event_loop()`) | 2026-06-06 |

---

## 6. Conventions (must follow)

### Code style
- **No comments** unless explicitly asked.
- Match surrounding style; use existing libraries.
- Async-first; no sync I/O in async paths.
- Pydantic v2 syntax (`model_config`, `field_validator`).

### Backend
- `app/services/*` for business logic; `app/api/*` for FastAPI routes.
- `app/scanners/*` for probe implementations.
- `app/connectors/*` for inventory connectors.
- DB models in `app/models/models.py`; Pydantic schemas in `app/models/schemas.py`.
- Connector pattern: `vault_helper.get_vault_secret` → upsert Asset → return status dict.

### Test
- Test dir: `D:\Project Files\PQC_Scanner\backend\tests\`
- Cmd: `cd "D:\Project Files\PQC_Scanner\backend"; python -m pytest tests/`
- Use `conftest.py` shared fixtures (`fastapi_app`, `client`, `mock_user`, `mock_db`, `auth_override`).
- `_make_scalar_one_or_none(value)`, `_make_scalars_all(items)`, `_make_result(items)` helpers.
- `SimpleNamespace` for fake ORM rows.

### Mypy
- Cmd: `cd "D:\Project Files\PQC_Scanner\backend"; python -m mypy app/ --ignore-missing-imports --no-strict-optional`
- **7 errors remain, all 3rd-party stubs** (scapy.all, sslyze, sqlalchemy sessionmaker). Zero in our code.
- Do not silence them; track as `app/db.py:10` + `app/scanners/sslyze_scanner.py:{40,41,50,52,53,54}`.

### Coverage
- **Current: 63%** (5910 stmts, 2190 missed)
- **Target: 85%**
- Cmd: `cd "D:\Project Files\PQC_Scanner\backend"; python -m pytest tests/ --cov=app --cov-report=term -q`
- Big gaps (post 5.4 + security fixes):
  - `app/services/report_service.py` 72% (153 stmts uncovered)
  - `app/connectors/*` 9-18% (cloud_kms 10%, pkcs11 9%, tde 10%, sast 18%, vault_helper 17%, k8s 11%, ssh 12%, winrm 14%)
  - `app/api/dashboard.py` 47%
  - `app/api/reports.py` 56%
  - `app/api/assets.py` 53%
  - `app/api/scan_logs.py` 45%
  - `app/services/scan_orchestrator.py` 55%
  - `app/tasks.py` 20%
  - `app/scanners/ct_log_scanner.py` 42%
  - `app/scanners/ike_scanner.py` 59%
  - `app/scanners/mail_scanner.py` 70%
  - `app/scanners/ocsp_dnssec_scanner.py` 67%

---

## 7. Test Status (as of 2026-06-06)

| Suite | Count | Status |
|-------|-------|--------|
| `tests/test_security_fixes.py` | 26 | NEW — covers 10 priority audit fixes |
| `tests/test_orchestrator_run_scan.py` | 16 | NEW — full run_scan happy + sad paths |
| `tests/test_report_service.py` | 20 | NEW — CBOM, SARIF, CSV, PDF |
| `tests/test_api_dashboard_extra.py` | 22 | NEW — layer mapping, cache, _determine_layer_for_asset |
| `tests/test_api_scans.py` | 11 | NEW — create/dedup/list/get/delete/findings |
| `tests/test_algo_classifier.py` | 40 | full coverage of `classify_algorithm` |
| `tests/test_cert_parser.py` | 24 | X.509 parse paths |
| `tests/test_*` (existing) | 292 | prior phases |
| **TOTAL** | **451** | **+ 2 skipped** |

Test runtime: ~92s for the full suite.

---

## 8. Audit — Completed (10/10 priority)

1. ✅ `tls_scanner._do_tls_connect` — `verify_tls=True` default
2. ✅ `algo_classifier` — per-spec `variant`/`parameterSetIdentifier`; 3DES detection; AES-128 Grover halving
3. ✅ `report_service` — `nistQuantumSecurityLevel` + `pqcSafe` already populated (verified)
4. ✅ `safe_target` — SSRF defaults flipped to 0/0/0
5. ✅ `vault_helper` — `ALLOW_ENV_FALLBACK=1` opt-in; no log presence
6. ✅ `tasks.execute_scan` — `asyncio.run()` via `_run_async()` helper
7. ✅ `risk_service` — 3DES confirmed in `DISALLOWED_NOW_PATTERNS` (audit was wrong)
8. ✅ `ssh_connector` — `RejectPolicy` + `PQC_SSH_AUTO_ADD_HOST_KEY=1` opt-in
9. ✅ `scan_orchestrator` — `async with` already correct; added `begin_nested()` savepoint per host
10. ✅ `mosca_model` — `DEFAULT_QUANTUM_HORIZON_YEAR=2034`; env override `MOSCA_HORIZON_YEAR`

---

## 9. Audit — Remaining (deferred, do NOT regress)

### High-priority (security/reliability)
- `scanners/tls_scanner.py:probe` — extend supported_groups to include X25519MLKEM768 (0x6399), SecP256r1MLKEM768 (0x2B94), P256MLKEM512; emit hybrid flag
- `analysis/algo_classifier.py:PQC_SIGNATURE_OIDS` — drop legacy Falcon aliases (1.3.6.1.4.1.62253.*); keep FIPS 204/205 final OIDs
- `scanners/sslyze_scanner.py:run` — convert eager `from sslyze import ...` to lazy import with try/except
- `scanners/pyshark_capture.py:import` — convert RuntimeError to lazy loader / `functools.cache` + warn
- `connectors/sast_connector.py:_run_tool` — add `timeout=30` to `subprocess.run`; mark scan partial on `TimeoutExpired`
- `connectors/winrm_connector.py:transport` — require `ssl=True` for all WinRM; assert target cert subject
- `connectors/tde_connector.py:_fetch` — wrap sync `cx_Oracle`/`pymssql` in `await asyncio.to_thread(...)`; cap row count
- `connectors/k8s_connector.py:api_cert` — run `cert_parser.parse()` and add a risk dimension
- `connectors/jwt_connector.py:alg` — assert `alg in {RS256, ES256, EdDSA, PS256}`; flag `alg=none` as critical
- `scanners/ocsp_dnssec_scanner.py:_fetch_ocsp` — wrap URL in `safe_target.is_safe`; add `timeout=5`, `stream=True`, `max_content=1MB`
- `scanners/network_discovery.py:scan` — pass `--max-retries 1 --host-timeout 30s` to nmap
- `api/scans.py:create_scan` — add `netaddr.IPNetwork` expansion; Redis token-bucket rate limit; RBAC decorator
- `api/findings.py:list` — add `limit/offset`; eager-load `selectinload(Finding.asset)`
- `api/dashboard.py:summary` — add Redis cache (60s TTL)
- `api/scan_logs.py:create_scan_log` — add `scan.owner_id == current_user.id` ACL check
- `auth/jwt.py:create_token` — switch HS256 → RS256/EdDSA, expose JWKS, support `kid` rotation
- `auth/dependencies.py:get_current_user` — add `role + tenant_id` claims; enforce in deps
- `scanners/cert_parser.py:parse` — add OCSP/CRL revocation check; emit `sig_algorithm_oid` + `pqcSafe` on Algorithm row
- `scanners/ssh_scanner.py:probe` — flag `sntrup761x25519-sha512@openssh.com` as hybrid PQC; deprecate `curve25519-sha256@libssh.org`; fix RSA-1024 vs RSA-4096 host-key detection
- `scanners/ike_scanner.py:probe` — add IKEv2 ML-KEM hybrid groups (32 = ML-KEM-768)
- `scanners/mail_scanner.py:smtp` — detect STARTTLS stripping; verify cipher after STARTTLS
- `services/finding_service.py:create` — include `scan_id` in `dedupe_key` to prevent re-scan suppression
- `services/l1_finding_service.py:revoked` — align severity score with `risk_service.critical_score`
- `services/layer_service.py:ASSET_TO_LAYER` — fix BitLocker mapping L7 → L6 per NIST SP 800-111
- `utils/retry.py:async_retry` — restrict retry to `(ConnectionError, TimeoutError, OSError)`; exclude `IntegrityError`
- `config.py:redact_sensitive` — extend `SENSITIVE_PATTERNS` with `Bearer `, `private_key`, `BEGIN RSA`; redact in scan_host
- `connectors/sast_connector.py:go_ast` — walk `find . -name go.mod` for monorepos
- `api/connectors.py:run_connector` — dispatch long-running connectors (SAST) to Celery
- `api/reports.py:create_report` — enqueue PDF/HTML gen as Celery task; return 202 + Location
- `celery_app.py:conf` — set `task_acks_late=True`, `worker_prefetch_multiplier=1`
- `db.py:engine` — bump `pool_size=20`, `max_overflow=40`
- `main.py:startup` — `await redis.ping()` with 5s timeout
- `main.py:cors` — restrict `CORS_ALLOWED_ORIGINS` via env
- `models/models.py:Scan` — add `Index('ix_scan_dedup', 'dedup_key', 'scan_type', 'created_at')` (note: no `dedup_key` column exists; add it)
- `models/models.py:Asset` — add `pqc_readiness` denormalized column; recompute trigger
- `main.py:lifespan` — replace `Base.metadata.create_all` with Alembic; run migrations in entrypoint
- `api/reports.py` + `api/connectors.py` — move PDF/HTML rendering to Celery

### Medium-priority (feature gaps)
- Active Directory / Entra ID connector (NT hash, Kerberos RC4)
- Android Keystore / iOS Secure Enclave connector
- Sigstore / cosign verification
- SAML XML signature inspection
- TPM 2.0 / PCR policy parser
- CRL/OCSP-stapling revocation enforcement
- CRQC parameter-set size verification (ML-DSA-44 vs 65 vs 87) in CBOM
- IKEv1 + BGP/TLS-TCP/QUIC scanners (L3 Network)
- macOS / Azure Arc / Intune agentless
- Starlark/Rego/Kubernetes-manifest SAST rule packs
- OAuth/OIDC/SAML token introspection
- LUKS/dm-crypt/BitLocker-from-host

### Frontend
- `api/client.ts:fetch` — add `ky` or `swrv` for retry + 401 refresh; move JWT to httpOnly cookie
- `pages/Scans.tsx:createScan` — client-side `netaddr` + zod validation
- `pages/Findings.tsx` — add `react-window` virtualization
- `components/SeverityBadge.tsx` — extend color map for `info` and `unknown`
- `docker-compose.yml:api` — add `mem_limit`, `cpus`; pass `--concurrency=4` to celery worker

---

## 10. Quick-Start for a New Session

1. **Read this file end-to-end.** Then read `summary.md` in the project root for the most recent session log.
2. **Run tests first** to establish baseline:
   ```bash
   cd "D:\Project Files\PQC_Scanner\backend"; python -m pytest tests/ -q
   ```
   Expect 451 passed, 2 skipped in ~92s.
3. **Pick work from §9 (Audit — Remaining).** Sort by:
   - SECURITY or RELIABILITY tag
   - Single-file scope
   - Has a corresponding conftest fixture or existing test pattern
4. **Write tests first.** Use the `_make_*` helpers and `conftest.py` fixtures.
5. **Run mypy** after each non-trivial change: `python -m mypy app/ --ignore-missing-imports --no-strict-optional`. Expect 7 errors (3rd-party stubs only).
6. **Update §7 and §8** at end of session.

---

## 11. The Iron Rules

1. **Never commit.** User explicitly asks.
2. **Never change a LOCKED decision (§5).** Bring it up first.
3. **Never revert a security fix from §8.** They are tracked individually in `test_security_fixes.py`.
4. **Never use `asyncio.get_event_loop()`.** Use `_run_async()` from `app.tasks`.
5. **Never default SSRF or TLS-verification to permissive.** Defaults are deny-by-default in 2026-06-06 release.
6. **Never use `os.environ.get("PQC_ALLOW_*")` with default "1"** in `safe_target.py`. Defaults are 0.
7. **Never log credential presence** in `vault_helper.py` or any connector.
8. **Never use `Base.metadata.create_all` outside `main.py` lifespan.** (Alembic migration is the long-term fix.)
9. **Every new file** under `app/` needs at least one smoke test.
10. **Coverage target is 85%.** Don't go below current (63%) when picking work.
