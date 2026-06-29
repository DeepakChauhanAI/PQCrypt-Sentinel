# PQC Scanner — Todo List

**Generated**: 2026-06-05
**Total items**: 38 (10 P0, 8 P1, 8 P2, 8 P3, 4 P4)
**Source**: Audit findings from `docs/audit/2026-06-05-audit.md` and the implementation plan in `docs/planning/implementation-plan.md`.

## Conventions

- **P0** = Critical security/correctness, blocks deployment
- **P1** = PQC engine correctness
- **P2** = CBOM compliance & API completeness
- **P3** = Performance & reliability
- **P4** = Code quality & tests

Each item has a verification step that should be run before marking complete.

---

## Phase 1 — Critical Security & Correctness (P0)

- [ ] **1.1** Restore auth on `create_scan` endpoint — add `current_user: User = Depends(get_current_user)`; record `scan.created_by` — `backend/app/api/scans.py:90-94`
  - Verify: pytest with no auth header returns 401.

- [ ] **1.2** Fix SSH KEX PQC false negative — set `transport._preferred_kex` to include `sntrup761x25519-sha512@openssh.com` and `mlkem768x25519-sha512@openssh.com` before `start_client` — `backend/app/scanners/ssh_scanner.py:37-80`
  - Verify: mock paramiko test asserts `pqc_status="pqc_ready"` for PQC-capable server.

- [ ] **1.3** Make TLS verification configurable — add `verify=False` param to `scan_tls_endpoint`/`scan_mail_endpoint`; opt-in via `Scan.config["strict_tls"]` — `backend/app/scanners/tls_scanner.py:35-39`, `backend/app/scanners/mail_scanner.py:64-66`
  - Verify: test that strict mode raises on self-signed cert.

- [ ] **1.4** Fix CBOM dependency type vocabulary — map `cert-*` → `required`, `algo-*` → `direct`, `key-*` → `provided`, `protocol-*` → `prerequisite` — `backend/app/services/report_service.py:302-334`
  - Verify: generated CBOM validates against CycloneDX 1.7 JSON schema.

- [ ] **1.5** Populate CBOM variant, cipherSuites, protocol version from real scan data — add `tls_version`/`cipher_suite` to `Certificate`; propagate through `post_process_cbom` — `backend/app/services/report_service.py:153-300`, `backend/app/models/models.py`
  - Verify: test that variant contains key size, not family name.

- [ ] **1.6** Fix KMIP `ssl_version` string bug — replace with `ssl.PROTOCOL_TLSv1_2` constant; mark connector `experimental: true` in `list_connectors` — `backend/app/connectors/pkcs11_connector.py:213`
  - Verify: mock KMIP client construction succeeds.

- [ ] **1.7** Correct IKE DH group PQC classification — brainpool/curve25519 standalone → `safe`; P-256/P-384/P-521 → `vulnerable`; hybrid → `hybrid`; ML-KEM → `pqc_ready` — `backend/app/scanners/ike_scanner.py:16-47`
  - Verify: test asserts group 34→`safe`, group 19→`pqc_ready`, group 14→`vulnerable`.

- [ ] **1.8** Fix scan dedup race condition — add partial unique index on `(target, scan_type)`; catch `IntegrityError` to return existing scan — `backend/app/api/scans.py:90-128`
  - Verify: concurrent integration test produces only one row for same target.

- [ ] **1.9** Cleanup duplicate code in scan orchestrator — remove duplicate `_LOCAL_TLS_PORTS`/`_LOCAL_SSH_PORTS` defs, second "Final scan completion" block, dead `tls_block_start = None` — `backend/app/services/scan_orchestrator.py:20-27, 960-1022`
  - Verify: pytest passes; integration scan completes.

- [ ] **1.10** Fix ssh_scanner missing MAC algorithms — capture `transport.remote_mac_algos`; expose in `SSHScanResult.mac_algorithms` — `backend/app/scanners/ssh_scanner.py:48-49`
  - Verify: new test asserts `mac_algorithms` field is populated.

---

## Phase 2 — PQC Engine Correctness (P1)

- [ ] **2.1** Add replaceability as 5th risk dimension — rename HNDL→Data Sensitivity (HNDL); drop Business Criticality; new weight split (30/20/20/15/15) — `backend/app/services/risk_service.py`
  - Verify: risk score range 5–25 maintained; replaceability tested.

- [ ] **2.2** Expand 3DES/TDEA pattern coverage — add `tdea`, `des-ede3`, `des_ede3`, `des-ede`, `des-cbc3`, `tripledes`, `3-des` — `backend/app/services/risk_service.py:11-50`
  - Verify: `is_disallowed_now("DES_EDE3_CBC")` → True.

- [ ] **2.3** Add AES + symmetric quantum security levels — AES-128→L1, AES-192→L3, AES-256→L5 (NIST IR 8547 §5) — `backend/app/services/report_service.py:186-211`, `backend/app/analysis/algo_classifier.py`
  - Verify: test asserts AES-256 component has `nistQuantumSecurityLevel=5`.

- [ ] **2.4** Fix `pqc_status` override (unknown → safe) — change `if pqc_status == "vulnerable"` to `if pqc_status in ("vulnerable", "unknown")` — `backend/app/scanners/cert_parser.py:184-188`
  - Verify: RSA-PSS sig + Ed25519 pubkey → `safe`.

- [ ] **2.5** Update RSA-3072 deadline to 2030 — RSA-3072→2030, RSA-4096→2030 (NIST SP 800-131A Rev.2) — `backend/app/analysis/algo_classifier.py:236-253`
  - Verify: `get_deprecation_deadline_year("RSA-3072", 3072)` → 2030.

- [ ] **2.6** Add replaceability inference from asset metadata — HSM/KMS/CA→2; firmware/locked legacy→5; default→3 — `backend/app/services/risk_service.py`
  - Verify: production HSM returns replaceability 2.

- [ ] **2.7** Persist raw Mosca fields on `Finding` — add `data_longevity_years`/`quantum_timeline_year`/`migration_window_years` to `evidence` JSONB — `backend/app/models/models.py:257-306`, `backend/app/services/finding_service.py:60-80`
  - Verify: `finding.evidence["data_longevity_years"]` populated.

- [ ] **2.8** Surface IKE PQC groups in probe — add DH group 38 (ML-KEM-768) and 40 (ML-KEM-512) to offered transforms — `backend/app/scanners/ike_scanner.py:163-176`
  - Verify: mock socket test asserts transform list contains group 38/40.

---

## Phase 3 — CBOM Compliance & API Completeness (P2)

- [ ] **3.1** Add missing scan-scoped endpoints — `GET /scans/{id}/status`, `GET /scans/{id}/cbom`, `GET /scans/{id}/report` — `backend/app/api/scans.py`
  - Verify: OpenAPI spec includes endpoints; integration test asserts 200 on completed, 400 on pending.

- [ ] **3.2** Fix `algorithmRef` cross-reference mismatch — resolve to actual `Algorithm.id`, not cert ID — `backend/app/services/report_service.py:138, 266, 295`
  - Verify: CBOM has `algorithmRef: "algo-<uuid>"` where uuid is Algorithm row ID.

- [ ] **3.3** Deduplicate protocol components — one `protocol-{asset_id}` per asset, not per cert — `backend/app/services/report_service.py:276-300`
  - Verify: 5-cert chain produces 1 protocol component.

- [ ] **3.4** Add `notValidBefore`/`notValidAfter` per CBOM spec — rename from `notBefore`/`notAfter` — `backend/app/services/report_service.py:141-149`
  - Verify: CycloneDX 1.7 schema validator accepts the document.

- [ ] **3.5** Tag each new asset with its layer ID — extract `_determine_layer_for_asset` to `app/utils/layer_classifier.py`; call at every asset creation — `backend/app/services/scan_orchestrator.py` (asset creation blocks)
  - Verify: HSM asset returns `layer_id="L3"`.

- [ ] **3.6** CT log: parse the actual certificate — fetch cert blob via `https://crt.sh/?d=<sha256>`, parse with `cert_parser.parse_certificate()` — `backend/app/scanners/ct_log_scanner.py:33-52`
  - Verify: known SHA-256 from crt.sh returns populated `sig_algorithm`.

- [ ] **3.7** Implement missing L1/L4/L5/L6/L7 connectors — DNSSEC, OCSP, JWT, backup encryption, Kerberos, CNG/Schannel, Windows cert store, firmware — `backend/app/scanners/` and `backend/app/connectors/`
  - Verify: 17+ connectors in `test_connectors.py`; DNSSEC+OCSP+JWT shipped in L1+L4 batch.

- [ ] **3.8** Remove dead code — unused `algo_by_name` map at `report_service.py:43-49`
  - Verify: pytest passes.

---

## Phase 4 — Performance & Reliability (P3)

- [ ] **4.1** Parallelize host/port scanning — `asyncio.gather` over port list per host; semaphore (5) over host list — `backend/app/services/scan_orchestrator.py:541-958`
  - Verify: 10 hosts × 5 ports completes ≥3x faster.

- [ ] **4.2** Move blocking SDK calls to executor — wrap PKCS#11, KMIP, boto3, ldap3, GCP SDK in `asyncio.to_thread(...)` — `backend/app/connectors/pkcs11_connector.py:65,78,216,372`, `backend/app/connectors/cloud_kms_connector.py:52-95,155-194,255-294`, `backend/app/connectors/sast_connector.py`
  - Verify: pytest-asyncio test confirms event loop not blocked.

- [ ] **4.3** Aggregate dashboard layer coverage in SQL — `GROUP BY` query, no full-table load — `backend/app/api/dashboard.py:336-388`
  - Verify: query plan shows index scan on 100k Asset rows.

- [ ] **4.4** Add retry/circuit-breaker for transient failures — `@retry(attempts=3, backoff=exponential, exceptions=(httpx.TransportError,))` decorator — `backend/app/services/retry.py` (new)
  - Verify: mock that raises twice then succeeds returns success.

- [ ] **4.5** Fix Redis client lifecycle — move creation into FastAPI `lifespan` context manager — `backend/app/api/dashboard.py:22`
  - Verify: app shutdown does not log "unclosed client" warnings.

- [ ] **4.6** Fix DNS hostname SSRF bypass — resolve hostname before SSRF check; reject if resolution fails — `backend/app/services/scan_orchestrator.py:422-510`
  - Verify: `metadata.google.internal` rejected.

- [ ] **4.7** DNS rebinding mitigation — re-resolve after connect; abort if IP changed — `backend/app/services/scan_orchestrator.py`
  - Verify: mock DNS returns 203.0.113.5 then 127.0.0.1 → scan aborted.

- [ ] **4.8** Tighten exception handling in host loop — add `asyncio.CancelledError` and `Exception` to caught tuple — `backend/app/services/scan_orchestrator.py:945-958`
  - Verify: one failing host doesn't abort whole scan.

---

## Phase 5 — Code Quality & Tests (P4)

- [ ] **5.1** Add `json` import to top of `sast_connector.py` (currently inside function body).

- [ ] **5.2** Type-annotate `risk_service.py` signatures — replace `Optional[Any]` with proper models.

- [ ] **5.3** Extract `KeyUsage` parsing helper in `finding_service.py:42-107` (reduces 6× repetition).

- [ ] **5.4** Fix `api/scans.py` duplicate imports — remove duplicate block at lines 20-33.

- [ ] **5.5** Add Pytest fixtures and coverage — `conftest.py` with `mock_db`/`mock_user`/`mock_celery`; target 85% line coverage in `services/`/`connectors/`/`scanners/`.

- [ ] **5.6** Refactor `scan_orchestrator.py` host loop — extract `_process_tls_host()`, `_process_ssh_host()`, `_process_ike_host()`, `_process_mail_host()`. 1000-line method → ~150 lines.

- [ ] **5.7** Vendor database versioning — use `packaging.version.parse` for proper semver in `vendor_pqc_db.py:58-72`.

- [ ] **5.8** Document the CIS benchmark deviation — add docstring to `disallowed_now` for `TLS 1.1` per NIST SP 800-52 Rev.2.

---

## Deferred to v1.1 (out of v1.0 scope)

- [ ] Full KMIP 1.2/1.3/2.0 implementation (~6 days) — see `docs/planning/implementation-plan.md` §"DEFERRED TO v1.1"
- [ ] L5 backup encryption connector
- [ ] L6 Kerberos RC4 detection
- [ ] L6 Windows CNG/Schannel registry parsing
- [ ] L7 Windows cert store, BitLocker, firmware signing

---

## Status Tracking

| Phase | Items | Done | In Progress | Remaining |
|---|---|---|---|---|
| Phase 1 (P0) | 10 | 0 | 0 | 10 |
| Phase 2 (P1) | 8 | 0 | 0 | 8 |
| Phase 3 (P2) | 8 | 0 | 0 | 8 |
| Phase 4 (P3) | 8 | 0 | 0 | 8 |
| Phase 5 (P4) | 8 | 0 | 0 | 8 |
| **Total** | **42** | **0** | **0** | **42** |
