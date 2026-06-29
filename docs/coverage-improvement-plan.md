# PQC Scanner Test Coverage Improvement Plan

**Current coverage:** 84.25% (8,247 / 9,789 statements)  
**Target coverage:** > 90% (> 8,810 statements)  
**Gap to close:** ~563 statements  
**Last updated:** 2026-06-29

---

## Executive Summary

All 782 tests pass after fixing the two assertion mismatches. The remaining 1,542 missed statements are concentrated in ~20 files. Closing the top 12 gaps alone adds ~550 covered statements, enough to push the project past 90%. The work is divided into 4 phases, each yielding incremental, verifiable coverage gains.

### Recommended order
1. **New connectors** (`git_secrets_connector`, `vault_scanner`) — high impact, low risk.
2. **API glue** (`app/api/connectors.py`, `dashboard.py`, `scans.py`, `assets.py`) — most missed statements.
3. **Scanners** (`ike_scanner`, `network_discovery`, `mail_scanner`, `pyshark_capture`) — medium effort.
4. **Polish** (`risk_service`, `tasks`, `safe_target`, `scan_orchestrator`) — smaller gains, easy wins.

---

## Phase 1 — New Connectors (Target: +150 statements)

### 1.1 `backend/app/connectors/git_secrets_connector.py`
- **Current:** 22% (23 / 105 statements)
- **Missed:** 82
- **Approach:**
  - Unit-test `_scan_file()` with mock file objects containing PEM keys, cert blocks, and AWS keys.
  - Mock `subprocess.run` for `git log`/`git diff` calls to test history scanning and failure paths.
  - Test `_looks_like_secret()` edge cases: base64 blobs, hex keys, multiline PEM.
  - Test `sync()` with a temp directory, verifying asset creation and deduplication.
- **Expected gain:** +75
- **Notes:** No external deps to mock beyond `git` CLI and filesystem.

### 1.2 `backend/app/connectors/vault_scanner.py`
- **Current:** 21% (20 / 94 statements)
- **Missed:** 74
- **Approach:**
  - Mock `httpx.AsyncClient` to simulate KV v1/v2 list responses and recursive traversal.
  - Test token expiry / permission denied paths (4xx/5xx responses).
  - Test `_detect_crypto_material()` with PEM cert/key strings and JWT patterns.
  - Test that non-crypto secrets are skipped and crypto secrets produce `Asset` rows.
- **Expected gain:** +65
- **Notes:** Keep tests async; avoid real Vault connections.

### 1.3 `backend/app/connectors/csv_connector.py`
- **Current:** 67% (63 / 94 statements)
- **Missed:** 31
- **Approach:**
  - Add tests for malformed CSV rows, missing required columns, and type coercion failures.
  - Test deduplication of rows with the same `name`/`environment`.
  - Test `IntegrityError` rollback path and `asset_metadata` JSON parsing.
- **Expected gain:** +25

**Phase 1 total expected gain:** ~150 covered statements → coverage ~85.8%

---

## Phase 2 — API Glue (Target: +330 statements)

### 2.1 `backend/app/api/connectors.py`
- **Current:** 74% (676 / 912 statements)
- **Missed:** 236
- **Approach:**
  - Add unit tests for **every sync endpoint** currently only exercised through integration tests:
    - `/sync/azure-key-vault`
    - `/sync/gcp-kms`
    - `/sync/pkcs11-hsm`
    - `/sync/kmip-kms`
    - `/sync/adcs-ldap`
    - `/sync/oracle-tde`
    - `/sync/sqlserver-tde`
    - `/sync/kubernetes`
    - `/sync/jwt`
    - `/sync/windows-cert-store`
    - `/sync/saml`
  - Mock the connector classes with `patch("app.api.connectors.<Connector>")`.
  - Test permission-denied paths (`viewer` role).
  - Test malformed payload validation (Pydantic errors).
  - Test `sync` results where `status == "error"` update the `Scan` record correctly.
- **Expected gain:** +150
- **Notes:** This is the single largest coverage win in the project.

### 2.2 `backend/app/api/dashboard.py`
- **Current:** 62% (129 / 207 statements)
- **Missed:** 78
- **Approach:**
  - Test `/dashboard/layer-coverage` with mocked service calls.
  - Test cache-hit paths using `patch("app.api.dashboard.get_cache")` returning valid data.
  - Test error branches where `get_cache`/`set_cache` raise Redis exceptions.
  - Test `/dashboard/progress` with empty datasets and missing scan groups.
- **Expected gain:** +60

### 2.3 `backend/app/api/scans.py`
- **Current:** 81% (158 / 194 statements)
- **Missed:** 36
- **Approach:**
  - Test `POST /scans` with invalid target strings and unsupported `scan_type`.
  - Test retry and abort endpoints with non-existent scan IDs.
  - Test pagination / filtering edge cases (`limit=0`, invalid sort column).
  - Test WebSocket `/ws/scans/{id}` connection and message broadcasting.
- **Expected gain:** +30

### 2.4 `backend/app/api/assets.py`
- **Current:** 73% (91 / 125 statements)
- **Missed:** 34
- **Approach:**
  - Test list filters: `environment`, `pqc_status`, `search`, `sort_by`.
  - Test the "unknown" PQC-status fallback branch (already fixed; ensure covered).
  - Test asset detail endpoint with missing asset.
  - Test re-scan trigger endpoint.
- **Expected gain:** +25

### 2.5 `backend/app/api/reports.py`
- **Current:** 56% (45 / 80 statements)
- **Missed:** 35
- **Approach:**
  - Test report download with missing files and failed reads.
  - Test unsupported `report_type`/`format` combinations.
  - Test listing reports with status filters.
  - Test delete report endpoint.
- **Expected gain:** +30

### 2.6 `backend/app/api/findings.py`
- **Current:** 88% (110 / 125 statements)
- **Missed:** 15
- **Approach:**
  - Test bulk update endpoint with invalid finding IDs.
  - Test severity filter edge cases.
- **Expected gain:** +10

**Phase 2 total expected gain:** ~330 covered statements → coverage ~88.2%

---

## Phase 3 — Scanner Modules (Target: +130 statements)

### 3.1 `backend/app/scanners/ike_scanner.py`
- **Current:** 59% (116 / 196 statements)
- **Missed:** 80
- **Approach:**
  - Unit-test `_parse_vendor_id()`, `_build_sa_payload()`, and `_build_notify_payload()` with known byte sequences.
  - Mock UDP socket to test handshake success, timeout, and malformed responses.
  - Test fallback to aggressive mode and transform parsing.
- **Expected gain:** +50
- **Notes:** Heavy binary parsing; use captured byte samples.

### 3.2 `backend/app/scanners/network_discovery.py`
- **Current:** 76% (116 / 152 statements)
- **Missed:** 36
- **Approach:**
  - Test `discover_network()` with mocked ICMP/TCP probes.
  - Test CIDR parsing errors and empty result sets.
  - Test `scan_port()` timeout and connection-refused paths.
- **Expected gain:** +28

### 3.3 `backend/app/scanners/pyshark_capture.py`
- **Current:** 81% (160 / 198 statements)
- **Missed:** 38
- **Approach:**
  - Test import guard path when `pyshark`/`tshark` is missing.
  - Mock `pyshark.FileCapture` and `LiveCapture` to test packet processing.
  - Test error handling when capture file is invalid.
- **Expected gain:** +25

### 3.4 `backend/app/scanners/mail_scanner.py`
- **Current:** 70% (61 / 87 statements)
- **Missed:** 26
- **Approach:**
  - Mock `smtplib.SMTP` and `starttls()` to test STARTTLS banner parsing.
  - Test connection timeout and unsupported ports.
  - Test certificate extraction from the TLS socket.
- **Expected gain:** +20

### 3.5 `backend/app/scanners/code_sign_scanner.py`
- **Current:** 77% (67 / 87 statements)
- **Missed:** 20
- **Approach:**
  - Test PE/Authenticode parsing with mock binary data.
  - Test missing signature paths.
- **Expected gain:** +15

### 3.6 `backend/app/scanners/ct_log_scanner.py`
- **Current:** 42% (13 / 31 statements)
- **Missed:** 18
- **Approach:**
  - Mock `requests.get` for Certificate Transparency log queries.
  - Test network failure and empty log responses.
- **Expected gain:** +14

### 3.7 `backend/app/scanners/ssh_scanner.py`
- **Current:** 89% (124 / 140 statements)
- **Missed:** 16
- **Approach:**
  - Test `connect()` with `paramiko.AuthenticationException`.
  - Test command execution failures and timeout paths.
- **Expected gain:** +12

### 3.8 `backend/app/scanners/cert_parser.py`
- **Current:** 89% (84 / 94 statements)
- **Missed:** 10
- **Approach:**
  - Test malformed PEM handling and unsupported signature algorithms.
  - Test Ed25519/Ed448 public key parsing.
- **Expected gain:** +8

**Phase 3 total expected gain:** ~130 covered statements → coverage ~89.5%

---

## Phase 4 — Services & Utilities (Target: +80 statements)

### 4.1 `backend/app/services/risk_service.py`
- **Current:** 79% (111 / 140 statements)
- **Missed:** 29
- **Approach:**
  - Add unit tests for `calculate_risk_score()` with edge cases: empty findings, hybrid algorithms, PQC-ready assets.
  - Test `get_severity()` boundary values.
  - Test missing/unknown algorithm defaults.
- **Expected gain:** +22

### 4.2 `backend/app/services/scan_host.py`
- **Current:** 87% (218 / 251 statements)
- **Missed:** 33
- **Approach:**
  - Test `_get_host_ip_and_fqdn()` with unresolvable hosts.
  - Test target classification failure paths.
  - Test scan cancellation mid-run.
- **Expected gain:** +20

### 4.3 `backend/app/services/scan_orchestrator.py`
- **Current:** 95% (501 / 527 statements)
- **Missed:** 26
- **Approach:**
  - Test scheduler lock contention and duplicate-run prevention.
  - Test Celery task failure callbacks.
  - Test scan result persistence when worker raises.
- **Expected gain:** +18

### 4.4 `backend/app/tasks.py`
- **Current:** 72% (61 / 85 statements)
- **Missed:** 24
- **Approach:**
  - Test `execute_report()` failure path.
  - Test `execute_scan()` retry logic and soft/hard timeout handling.
  - Test `execute_scheduled_scan()` with empty target list.
- **Expected gain:** +18

### 4.5 `backend/app/scanners/safe_target.py`
- **Current:** 76% (87 / 114 statements)
- **Missed:** 27
- **Approach:**
  - Test each `UnsafeTargetError` branch: loopback, RFC1918, link-local, multicast, invalid CIDR, port range.
  - Test DNS resolution returning multiple safe/unsafe IPs.
- **Expected gain:** +20

### 4.6 `backend/app/utils/target_classifier.py`
- **Current:** 90% (95 / 106 statements)
- **Missed:** 11
- **Approach:**
  - Test malformed target strings and unknown prefixes.
  - Test IPv6 target classification.
- **Expected gain:** +8

### 4.7 `backend/app/models/schemas.py`
- **Current:** 92% (286 / 310 statements)
- **Missed:** 24
- **Approach:**
  - Add tests instantiating every Pydantic model with invalid data to exercise validators.
  - Focus on `ReportCreate`, `ScanCreate`, and dashboard schemas.
- **Expected gain:** +15

### 4.8 `backend/app/models/models.py`
- **Current:** 97% (204 / 210 statements)
- **Missed:** 6
- **Approach:**
  - Test the few uncovered `__repr__` / helper branches.
- **Expected gain:** +4

**Phase 4 total expected gain:** ~80 covered statements → coverage ~90.3%

---

## Summary of Expected Gains

| Phase | Focus | Expected Statements Covered | Cumulative Coverage |
|---|---|---|---|
| Baseline | — | 8,247 | 84.25% |
| 1 | New connectors | +150 | ~85.8% |
| 2 | API glue | +330 | ~88.2% |
| 3 | Scanners | +130 | ~89.5% |
| 4 | Services & utilities | +80 | ~90.3% |
| **Total** | | **+690** | **> 90%** |

The plan over-estimates by ~20% to account for overlap and hard-to-reach branches. Even with 80% realization, the project reaches 90%+.

---

## Implementation Guidelines

1. **Use existing fixtures.** Extend `conftest.py` rather than creating new DB/session mocks where possible.
2. **Mock external services.** boto3, httpx, paramiko, pyodbc, cx_Oracle, ldap3, kubernetes, etc., should never be called during tests.
3. **Parametrize happy and sad paths.** Each function worth testing should have at least one success and one failure case.
4. **Run coverage after every PR.** `cd backend && python -m pytest tests/ -q --tb=no` should show incremental gains.
5. **Do not chase 100% per file.** Files already at 97%+ are low priority; target files below 80% first.

---

## Quick-Start Checklist for First Sprint

- [ ] Write `test_git_secrets_connector.py` (target: +75)
- [ ] Write `test_vault_scanner.py` (target: +65)
- [ ] Add `/sync/*` endpoint tests in `test_api_connectors.py` (target: +80)
- [ ] Add dashboard cache/error-path tests (target: +40)
- [ ] Add scanner tests for `ike_scanner.py` and `network_discovery.py` (target: +60)

Completing the first sprint alone should lift coverage to ~87%.
