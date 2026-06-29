# PQC Scanner — Audit & Implementation Plan

**Generated**: 2026-06-05
**Scope**: 62 audit findings (10 P0, 18 P1, 14 P2, 12 P3, 8 P4)
**Strategy**: 5 sequential phases, each with its own test gate.

## Stakeholder Decisions (locked 2026-06-05)

| # | Decision |
|---|---|
| 1 | **5-dim risk model** matching audit spec: HNDL (= data_sensitivity), Exposure, Algorithm Risk, Regulatory Obligation, **Replaceability (NEW)**. Drop Business Criticality. |
| 2 | L1 (DNSSEC/OCSP) **batched in Phase 3.7** with L4 JWT connector. |
| 3 | RSA-3072 → **2030** deadline (NIST SP 800-131A Rev.2). |
| 4 | TLS verify **off by default**, opt-in via `Scan.config["strict_tls"]`. |
| 5 | KMIP: **fix bug only** in v1.0, defer full implementation to v1.1, mark experimental. |

## Phase Dependency Graph

```
Phase 1 ── blocks deployment
   │
   ├──> Phase 2 (depends on 1.5: TLS/cipher data must flow to CBOM first)
   │       │
   │       └──> Phase 3 (CBOM compliance builds on classifier)
   │
   └──> Phase 4 (perf independent, can start after 1.9)
           │
           └──> Phase 5 (cleanup last)
```

**Estimated effort**: Phase 1: 3-4d | Phase 2: 3-4d | Phase 3: 4-5d | Phase 4: 2-3d | Phase 5: 1-2d → **15-18 working days total**

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| CycloneDX schema validator rejection (3.4) | Low | High | Run a 1.7 JSON schema in CI; fail the build on any violation. |
| WeasyPrint native deps unavailable in CI | Medium | Medium | Already handled by HTML fallback at `report_service.py:657-665`. |
| SSH KEX algorithm ordering breaks compatibility (1.2) | Low | Medium | Add the new algos *first* in the list so OpenSSH servers pick them if supported. |
| Migration window / deadline column migration (2.7) | Low | Low | Default JSONB column is additive; no destructive migration. |
| PKCS#11 vendor library load risk | Low | Low | Pin library path validation; document supported HSM vendors. |

---

# PHASE 1 — Critical Security & Correctness (P0)

**Goal**: Block all paths that produce false data, leak access, or fail outright.
**Test gate**: Full pytest suite + new tests for SSH PQC KEX offer, KMIP startup, IKE classification, scan auth.

## 1.1 — Restore auth on scan creation
- **File**: `backend/app/api/scans.py:90-94`
- **Change**: Add `current_user: User = Depends(get_current_user)` to `create_scan`; record `scan.created_by = current_user.id`.
- **Verify**: pytest with no auth header returns 401.

## 1.2 — Fix SSH KEX PQC false negative
- **File**: `backend/app/scanners/ssh_scanner.py:37-80`
- **Change**: Before `transport.start_client`, set `transport._preferred_kex = ("sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha512@openssh.com", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256")`.
- **Verify**: New test with a mock paramiko transport offering `mlkem768x25519-sha512@openssh.com` returns `pqc_status="pqc_ready"`.

## 1.3 — Make TLS verification configurable
- **Files**: `backend/app/scanners/tls_scanner.py:35-39`, `backend/app/scanners/mail_scanner.py:64-66`
- **Change**: Accept a `verify=False` parameter (default off per stakeholder decision). Add `verify_mode=ssl.CERT_REQUIRED` path. For SMTPS, call `context.load_default_certs()`. Opt-in via `Scan.config["strict_tls"]`.
- **Verify**: Test that strict mode raises on a self-signed cert.

## 1.4 — Fix CBOM dependency type vocabulary
- **File**: `backend/app/services/report_service.py:302-334`
- **Change**: Map internal labels → CycloneDX 1.7 controlled vocabulary:
  - `cert-*` → `required`
  - `algo-*` → `direct`
  - `key-*` → `provided`
  - `protocol-*` → `prerequisite`
- **Verify**: Generated CBOM validates against the CycloneDX 1.7 JSON schema.

## 1.5 — Populate CBOM variant, cipherSuites, protocol version
- **Files**: `backend/app/services/report_service.py:153-300`, `backend/app/models/models.py`
- **Change**:
  - Add `tls_version` and `cipher_suite` columns to `Certificate` (or store in `Asset.asset_metadata`).
  - Pass these into `post_process_cbom` via `assets_map`.
  - In the protocol record, set `version: cert.tls_version`, `cipherSuites: [cert.cipher_suite]`.
  - In algo/cert variant, store `"RSA-2048"`, `"EC-P256"`, `"Ed25519"`, etc.
- **Verify**: Test that variant contains key size, not family name.

## 1.6 — Fix KMIP connector `ssl_version` string
- **File**: `backend/app/connectors/pkcs11_connector.py:213`
- **Change**: Replace `ssl_version="PROTOCOL_TLSv1_2"` with `ssl_version=ssl.PROTOCOL_TLSv1_2` (or omit and let python-kmip default). Mark connector as `experimental: true` in `list_connectors` response.
- **Verify**: Mock KMIP client test passes construction.

## 1.7 — Correct IKE DH group PQC classification
- **File**: `backend/app/scanners/ike_scanner.py:16-47`
- **Change**:
  - Brainpool curves (31, 32, 33) and standalone curve25519/curve448 (34, 35) → `safe` (not quantum-vulnerable in isolation).
  - P-256/P-384/P-521 (28, 29, 30) → `vulnerable`.
  - Hybrid groups 36, 37 → `hybrid`.
  - ML-KEM (38, 39, 40) → `pqc_ready`.
  - Add comment block citing NIST IR 8547.
- **Verify**: New test for group 34 returns `safe`, group 19 returns `pqc_ready`, group 14 returns `vulnerable`.

## 1.8 — Dedup race condition
- **File**: `backend/app/api/scans.py:90-128`
- **Change**: Add partial unique index `CREATE UNIQUE INDEX … ON scans(target, scan_type) WHERE status IN ('queued', 'running', 'completed')` and catch `IntegrityError` to return the existing scan.
- **Verify**: Concurrent integration test — two simultaneous POSTs for same target produce only one row.

## 1.9 — Cleanup duplicate code in scan orchestrator
- **File**: `backend/app/services/scan_orchestrator.py:20-27, 960-1022`
- **Change**: Remove duplicate `_LOCAL_TLS_PORTS` / `_LOCAL_SSH_PORTS` definitions; remove the second "Final scan completion" block; remove dead `tls_block_start = None` at line 561.
- **Verify**: pytest passes; orchestrator still completes a scan in the integration path.

## 1.10 — Fix ssh_scanner missing MAC algorithms
- **File**: `backend/app/scanners/ssh_scanner.py:48-49`
- **Change**: Add `macs = list(transport.remote_mac_algos or [])`; expose in `SSHScanResult.mac_algorithms`.
- **Verify**: New test asserts `mac_algorithms` field is populated.

---

# PHASE 2 — PQC Engine Correctness (P1)

**Goal**: Risk scoring and algorithm classification match NIST IR 8547 + Grovers.
**Test gate**: `test_risk_service.py` extended; `test_classifier.py` created from a curated table of 50+ algorithms.

## 2.1 — Add the missing 5th dimension (replaceability)
- **File**: `backend/app/services/risk_service.py`
- **Change**: Add `replaceability_score` (1–5) sourced from `asset.asset_metadata.replaceability` (or default 3 for unknown). New weight split for 5-dim model:
  | Axis | Weight | Maps to current |
  |---|---|---|
  | Data Sensitivity (HNDL) | 30% | HNDL Sensitivity (renamed) |
  | Exposure | 20% | System Exposure (Business Criticality folded in) |
  | Algorithm Risk | 20% | Algorithm Vulnerability (renamed) |
  | Replaceability | 15% | NEW |
  | Regulatory Obligation | 15% | Regulatory Deadline Proximity (renamed) |
- **Verify**: Risk score output range 5–25 maintained; replaceability tested.

## 2.2 — Expand 3DES/TDEA pattern coverage
- **File**: `backend/app/services/risk_service.py:11-50`
- **Change**: Add `"tdea"`, `"des-ede3"`, `"des_ede3"`, `"des-ede"`, `"des-cbc3"`, `"tripledes"`, `"3-des"`.
- **Verify**: `is_disallowed_now("DES_EDE3_CBC")` → True.

## 2.3 — Add AES + symmetric quantum security levels
- **Files**: `backend/app/services/report_service.py:186-211`, `backend/app/analysis/algo_classifier.py`
- **Change**: AES-128 → NIST Level 1, AES-192 → Level 3, AES-256 → Level 5 (per NIST IR 8547 §5). Add `aes_quantum_security_level` computation.
- **Verify**: New test asserts AES-256 algo component has `nistQuantumSecurityLevel=5`.

## 2.4 — Fix `pqc_status` override (unknown → safe)
- **File**: `backend/app/scanners/cert_parser.py:184-188`
- **Change**: Change `if pqc_status == "vulnerable"` to `if pqc_status in ("vulnerable", "unknown")`.
- **Verify**: Test with RSA-PSS sig + Ed25519 pubkey → `safe`.

## 2.5 — Update RSA-3072 deadline to 2030
- **File**: `backend/app/analysis/algo_classifier.py:236-253`
- **Change**: RSA-3072 deadline 2030; RSA-4096 → 2030 (legacy interop). Document in docstring.
- **Verify**: `get_deprecation_deadline_year("RSA-3072", 3072)` → 2030.

## 2.6 — Add replaceability inference from asset metadata
- **File**: `backend/app/services/risk_service.py`
- **Change**: For HSM/KMS/CA asset types, default replaceability = 2 (cheap); for firmware/locked legacy = 5 (hard). Persist `asset.asset_metadata.replaceability` from connectors.
- **Verify**: Production HSM returns replaceability 2.

## 2.7 — Persist raw Mosca fields on `Finding`
- **File**: `backend/app/models/models.py:257-306`, `backend/app/services/finding_service.py:60-80`
- **Change**: Add `data_longevity_years`, `quantum_timeline_year`, `migration_window_years` JSONB column to `Finding` (or expand `evidence` JSONB). Update `finding_service.add_finding` to store them.
- **Verify**: `finding.evidence["data_longevity_years"]` populated.

## 2.8 — Surface IKE PQC groups from server response
- **File**: `backend/app/scanners/ike_scanner.py:163-176`
- **Change**: Probe must include DH group 38 (ML-KEM-768) and 40 (ML-KEM-512) in the offered transform list. Servers that PQC-negotiate will respond with INVALID_KE_PAYLOAD pointing to the PQC group.
- **Verify**: Mock socket test asserts transform list contains group 38/40.

---

# PHASE 3 — CBOM Compliance & API Completeness (P2)

**Goal**: All audit-required CBOM fields, endpoints, and report formats.
**Test gate**: `cyclonedx-python-lib` round-trip test; integration test for `/scans/{id}/cbom`.

## 3.1 — Add missing scan-scoped endpoints
- **File**: `backend/app/api/scans.py`
- **Change**: Add `GET /api/v1/scans/{id}/status` (returns `{status, progress, error_message}` only), `GET /api/v1/scans/{id}/cbom` (returns the most recent ready CBOM for that scan), `GET /api/v1/scans/{id}/report` (returns the most recent report for that scan).
- **Verify**: OpenAPI spec includes the three new endpoints; integration test asserts 200 on completed scan, 400 on pending.

## 3.2 — Fix `algorithmRef` cross-reference mismatch
- **File**: `backend/app/services/report_service.py:138, 266, 295`
- **Change**: `algorithmRef` for keys must point to the actual `Algorithm` record ID, not the cert ID. Resolve via `asset.algorithms` lookup.
- **Verify**: Generated CBOM has `algorithmRef: "algo-<uuid>"` where `<uuid>` is the Algorithm row ID, not the cert.

## 3.3 — Deduplicate protocol components
- **File**: `backend/app/services/report_service.py:276-300`
- **Change**: One `protocol-{asset_id}` per asset (not per cert). Aggregate all certs under one protocol with `cryptoRefArray` listing each cert's algo-ref.
- **Verify**: A 5-cert chain produces 1 protocol component.

## 3.4 — Add `serialNumber` and `notValidBefore/After` per CBOM spec
- **File**: `backend/app/services/report_service.py:141-149`
- **Change**: Map to CycloneDX field names: `notValidBefore` and `notValidAfter` (currently using `notBefore`/`notAfter`).
- **Verify**: CycloneDX schema validator accepts the document.

## 3.5 — Tag each new asset with its layer ID
- **File**: `backend/app/services/scan_orchestrator.py` (asset creation blocks)
- **Change**: Add `asset.asset_metadata["layer_id"] = _determine_layer_for_asset(asset)` at every asset creation. The layer detection logic already exists in `api/dashboard.py:296-319`; extract to `app/utils/layer_classifier.py`.
- **Verify**: New test for an HSM asset returns `layer_id="L3"`.

## 3.6 — CT log: parse the actual certificate
- **File**: `backend/app/scanners/ct_log_scanner.py:33-52`
- **Change**: crt.sh returns a `pinned_sha-256` field; fetch the actual cert blob via `https://crt.sh/?d=<sha256>`, parse with `cert_parser.parse_certificate()`, store thumbprint and `sig_algorithm`.
- **Verify**: Test with a known SHA-256 from crt.sh returns a populated `sig_algorithm`.

## 3.7 — Implement missing L1/L4/L5/L6/L7 coverage
- **Files (new)**:
  - `backend/app/scanners/dnssec_scanner.py` — DNSSEC DNSKEY/DS record classification.
  - `backend/app/scanners/ocsp_scanner.py` — OCSP response signature classification.
  - `backend/app/connectors/jwt_connector.py` (L4) — JWT signing-algorithm detection.
  - `backend/app/connectors/backup_encryption_connector.py` (L5) — backup file classification.
  - `backend/app/connectors/kerberos_connector.py` (L6) — Kerberos ticket encryption type.
  - `backend/app/connectors/cng_registry_connector.py` (L6) — Windows CNG/Schannel registry.
  - `backend/app/connectors/windows_cert_store_connector.py` (L7) — Windows cert store enumeration.
  - `backend/app/connectors/firmware_connector.py` (L7) — firmware signing algorithm.
- **Verify**: New `test_connectors.py` entries assert 17+ connectors are listed. DNSSEC and OCSP shipped in L1 batch; JWT (L4) in same batch since both are auth-path scanners.

## 3.8 — Remove dead code
- **File**: `backend/app/services/report_service.py:43-49`
- **Change**: Remove the unused `algo_by_name` map.
- **Verify**: pytest passes.

---

# PHASE 4 — Performance & Reliability (P3)

**Goal**: Eliminate blocking I/O in async paths, fix race conditions, add timeouts.
**Test gate**: Integration test with 10 simultaneous scans completes within 60s.

## 4.1 — Parallelize host/port scanning
- **File**: `backend/app/services/scan_orchestrator.py:541-958`
- **Change**: For each host, run `asyncio.gather` over the port list with `return_exceptions=True`. For multiple hosts, use `asyncio.gather` over a host semaphore (e.g. 5 concurrent hosts).
- **Verify**: Time 10 hosts × 5 ports — expect ≥3x speedup.

## 4.2 — Move blocking SDK calls to executor
- **Files**: `backend/app/connectors/pkcs11_connector.py:65,78,216,372`, `backend/app/connectors/cloud_kms_connector.py:52-95,155-194,255-294`, `backend/app/connectors/sast_connector.py` (subprocess).
- **Change**: Wrap PKCS#11, KMIP, boto3, ldap3, GCP SDK calls in `asyncio.to_thread(…)`.
- **Verify**: pytest-asyncio test that the connector returns without blocking the event loop.

## 4.3 — Aggregate dashboard layer coverage in SQL
- **File**: `backend/app/api/dashboard.py:336-388`
- **Change**: Replace the full-table load with a `GROUP BY` aggregate query (subquery on Asset + Algorithm join).
- **Verify**: Query plan shows index scan, not seq scan, on 100k Asset rows.

## 4.4 — Add retry/circuit-breaker for transient failures
- **File (new)**: `backend/app/services/retry.py`
- **Change**: `@retry(attempts=3, backoff=exponential, exceptions=(httpx.TransportError,))` decorator. Apply to boto3, ldap3, redis, ct_log scanner.
- **Verify**: Mock that raises twice then succeeds — decorator returns the success.

## 4.5 — Fix Redis client lifecycle
- **File**: `backend/app/api/dashboard.py:22`
- **Change**: Move `redis_client` creation into FastAPI's `lifespan` context manager. Close on shutdown.
- **Verify**: App shutdown does not log "unclosed client" warnings.

## 4.6 — Fix DNS hostname SSRF bypass
- **File**: `backend/app/services/scan_orchestrator.py:422-510`
- **Change**: Resolve the hostname to an IP *before* the SSRF check, then validate the IP. If hostname resolution fails, refuse the scan.
- **Verify**: Test that `metadata.google.internal` is rejected.

## 4.7 — DNS rebinding mitigation
- **File**: `backend/app/services/scan_orchestrator.py`
- **Change**: After connecting, re-resolve the hostname and verify the IP is still in the allowlist. If it has changed, abort the scan for that target.
- **Verify**: Mock DNS that returns 203.0.113.5 then 127.0.0.1 → scan aborted.

## 4.8 — Tighten exception handling in host loop
- **File**: `backend/app/services/scan_orchestrator.py:945-958`
- **Change**: Add `asyncio.CancelledError` and `Exception` to the caught tuple so a per-host crash doesn't abort the whole scan.
- **Verify**: Inject one failing host, others complete.

---

# PHASE 5 — Code Quality & Tests (P4)

**Goal**: Eliminate the remaining 8 P4 issues.
**Test gate**: pytest coverage > 85%; mypy --strict on new code; ruff clean.

## 5.1 — Add `json` import to top of `sast_connector.py`
- Move `import json` to module level.

## 5.2 — Type-annotate `risk_service.py` signatures
- Replace `Optional[Any]` with proper models or `Dict[str, Any]`.

## 5.3 — Add `replaceAll` for repeated `add_finding` calls
- The `finding_service.py:42-107` helper is called 6 times with similar shape — keep as is but extract `KeyUsage` parsing into a small helper.

## 5.4 — Fix `api/scans.py` duplicate imports
- Remove the duplicate block (lines 20-33).

## 5.5 — Add Pytest fixtures and coverage
- Add `conftest.py` with `mock_db`, `mock_user`, `mock_celery` fixtures.
- Target: 85% line coverage in `services/`, `connectors/`, `scanners/`.

## 5.6 — Refactor `scan_orchestrator.py` host loop
- Extract `_process_tls_host()`, `_process_ssh_host()`, `_process_ike_host()`, `_process_mail_host()`. The 1000-line method becomes ~150 lines.

## 5.7 — Vendor database versioning
- `vendor_pqc_db.py:58-72` does prefix matching — use `packaging.version.parse` for proper semver.

## 5.8 — Document the CIS benchmark deviation
- `disallowed_now` for `TLS 1.1` per NIST SP 800-52 Rev.2 — add a docstring with the source.

---

# DEFERRED TO v1.1 (out of v1.0 scope)

| Item | Effort | Reason |
|---|---|---|
| Full KMIP 1.2/1.3/2.0 negotiation, error handling, connection pool, mock server tests | ~6 days | On-prem deployments use PKCS#11; KMIP is more cloud-centric. Stub-only in v1.0 with bug fixed and `experimental: true` flag. |
| L5 backup encryption connector | TBD | Lower priority than L1/L4/L6/L7. |
| L6 Kerberos RC4 detection | TBD | Needs LDAP/SMB integration. |
| L6 Windows CNG/Schannel registry | TBD | Windows-specific, requires WinRM or registry hive parsing. |
| L7 Windows cert store, BitLocker, firmware signing | TBD | Windows-specific. |

---

# Open Questions

None. All 5 stakeholder decisions locked 2026-06-05.
