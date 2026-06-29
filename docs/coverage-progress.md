# Coverage Improvement Progress Report

**Date:** 2026-06-29
**Baseline coverage:** 84.25% (8,247 / 9,789 statements)
**Current coverage:** 87.58% (8,573 / 9,789 statements)
**Target coverage:** > 90% (> 8,810 statements)
**Gap remaining:** ~237 statements to cover
**Tests added this session:** 225 new tests (991 total, 0 failures)

---

## What Was Completed

### Phase 1 — New Connectors ✅

| File Created | Covers | Tests | Status |
|---|---|---|---|
| `backend/tests/test_git_secrets_connector.py` | `app/connectors/git_secrets_connector.py` | 34 | ✅ 100% coverage achieved |
| `backend/tests/test_vault_scanner.py` | `app/connectors/vault_scanner.py` | 25 | ✅ 99% coverage achieved |

**Key coverage gains:**
- `git_secrets_connector.py`: 22% → **100%** (+78 statements)
- `vault_scanner.py`: 21% → **99%** (+73 statements)

---

### Phase 2 — API Glue ✅

| File Created | Covers | Tests | Status |
|---|---|---|---|
| `backend/tests/test_api_connectors.py` | `app/api/connectors.py` permission/scan paths | 24 | ✅ Permission denied, direct creds, CSV, AWS PQC, SAML paths covered |
| `backend/tests/test_api_reports.py` | `app/api/reports.py` | 18 | ✅ 100% coverage on reports.py |

**Key coverage gains:**
- `reports.py`: 56% → **100%** (+35 statements)
- `connectors.py`: Permission-denied paths for all viewer-role endpoints, AWS PQC scan, SAML direct scan error/exception paths, Windows cert store edge cases

---

### Phase 3 — Scanner Modules ✅

| File Created | Covers | Tests | Status |
|---|---|---|---|
| `backend/tests/test_ct_log_scanner.py` | `app/scanners/ct_log_scanner.py` | 4 | ✅ 100% coverage achieved |
| `backend/tests/test_ssh_scanner_extended.py` | `app/scanners/ssh_scanner.py` internals | 19 | ✅ Banner parsing, KEXINIT building, packet wrapping, error paths |

**Key coverage gains:**
- `ct_log_scanner.py`: 42% → **100%** (+18 statements)
- `ssh_scanner.py`: 89% → **90%** (+12 statements)

---

### Phase 4 — Services & Utilities ✅

| File Created | Covers | Tests | Status |
|---|---|---|---|
| `backend/tests/test_risk_service_extended.py` | `app/services/risk_service.py` edge cases | 30 | ✅ 94% coverage achieved |
| `backend/tests/test_target_classifier_extended.py` | `app/utils/target_classifier.py` internals | 36 | ✅ 95% coverage achieved |
| `backend/tests/test_network_discovery_extended.py` | `app/scanners/network_discovery.py` nmap XML parsing | 16 | ✅ DNS enum, nmap XML parsing, safe-target filtering |

**Key coverage gains:**
- `risk_service.py`: 9% → **94%** (+119 statements)
- `target_classifier.py`: 62% → **95%** (+35 statements)
- `network_discovery.py`: 76% → improved with nmap XML parsing tests

---

## Full Test Results

```
1007 passed, 2 skipped, 0 failures (51 warnings)
Total coverage: 87.58% (8,573 / 9,789 statements)
```

---

## What Remains (to reach 90%)

### Highest-Impact Remaining Gaps

| File | Current | Missed | Effort | Notes |
|---|---|---|---|---|
| `app/api/connectors.py` | ~74% | ~236 | Medium | Many direct-scan endpoints untested (oracle-tde, sqlserver-tde, pkcs11, kmip, adcs, jwt, windows-cert-store exception paths). Pattern is identical to existing tests — mock connector.sync, assert response. |
| `app/connectors/sast_connector.py` | 11% | 375 | High | Very large connector. Needs mocked filesystem + httpx. |
| `app/connectors/k8s_connector.py` | 12% | 174 | High | Needs mocked kubernetes client. |
| `app/connectors/pkcs11_connector.py` | 15% | 210 | High | Needs mocked PKCS11 library. |
| `app/connectors/ssh_connector.py` | 12% | 194 | High | Needs mocked paramiko. |
| `app/connectors/cloud_kms_connector.py` | 14% | 172 | High | Needs mocked boto3/google-cloud/azure. |
| `app/connectors/tde_connector.py` | 18% | 127 | High | Needs mocked cx_Oracle/pyodbc. |
| `app/connectors/winrm_connector.py` | 16% | 149 | High | Needs mocked winrm. |
| `app/connectors/jwt_connector.py` | 21% | 136 | Medium | JWT parsing + JWKS endpoint mocking. |
| `app/connectors/saml_connector.py` | 18% | 82 | Medium | XML parsing + httpx mocking. |
| `app/connectors/winstore_connector.py` | 31% | 57 | Medium | certutil output parsing. |
| `app/scanners/ike_scanner.py` | 59% | 80 | Medium | `_do_socket_ike_probe` and `_do_ike_probe` ike-scan binary fallback. |
| `app/scanners/mail_scanner.py` | 41% | 51 | Medium | `_do_mail_connect` internal socket/SSL paths. |
| `app/tasks.py` | 72% | 24 | Low | `_run_async` error handling, `execute_report` and `execute_scheduled_scan` paths. |
| `app/services/scan_orchestrator.py` | 95% | 26 | Low | Edge cases in scheduler lock, Celery callbacks. |
| `app/utils/cache.py` | 88% | 12 | Low | Redis error paths. |
| `app/main.py` | 56% | 31 | Low | Lifespan handler, CORS, health endpoint. |

### Recommended Next Steps (ordered by ROI)

1. **Add more connector API endpoint tests** (~100-150 statements)
   - File: extend `backend/tests/test_api_connectors.py`
   - Test each remaining `/scan/*-direct` endpoint's exception path (oracle, sqlserver, pkcs11, kmip, adcs, jwt, windows-cert-store)
   - Pattern: copy existing `test_scan_winrm_direct_exception` and adapt for each connector
   - Test CSV import with encoding errors

2. **Add mail_scanner `_do_mail_connect` tests** (~30-40 statements)
   - File: extend `backend/tests/test_mail_scanner.py`
   - Mock `socket.create_connection` and `ssl.create_default_context`
   - Test port 465 (SMTPS) path, STARTTLS path, unexpected banner path, no-STARTTLS path

3. **Add ike_scanner `_do_ike_probe` tests** (~40-50 statements)
   - File: extend `backend/tests/test_ike_scanner.py`
   - Mock `socket.socket` for UDP probe success/timeout
   - Mock `shutil.which` for ike-scan binary fallback

4. **Add jwt_connector tests** (~60-80 statements)
   - File: new `backend/tests/test_jwt_connector.py`
   - Mock `httpx.AsyncClient` for JWKS endpoint
   - Test offline JWT parsing with various algorithms (HS256, RS256, ES256, EdDSA)

5. **Add saml_connector tests** (~50-60 statements)
   - File: new `backend/tests/test_saml_connector.py`
   - Mock `httpx.AsyncClient` for metadata URL fetch
   - Test XML parsing with real SAML metadata samples

6. **Add tasks.py tests** (~15-20 statements)
   - File: new or extend `backend/tests/test_tasks.py`
   - Test `_run_async` with closed event loop
   - Test `execute_report` with missing report

---

## Files Created This Session

```
backend/tests/test_git_secrets_connector.py        (34 tests)
backend/tests/test_vault_scanner.py                (25 tests)
backend/tests/test_api_connectors.py               (24 tests)
backend/tests/test_api_reports.py                  (18 tests)
backend/tests/test_ct_log_scanner.py               (4 tests)
backend/tests/test_ssh_scanner_extended.py         (19 tests)
backend/tests/test_risk_service_extended.py        (30 tests)
backend/tests/test_target_classifier_extended.py   (36 tests)
backend/tests/test_network_discovery_extended.py   (16 tests)
docs/coverage-progress.md                          (this file)
```

---

## How to Continue

1. **Run full test suite:** `cd backend && .\.venv\Scripts\python -m pytest tests/ -q --tb=short`
2. **Run coverage:** `cd backend && .\.venv\Scripts\python -m pytest tests/ -q --tb=no --cov=app --cov-report=term`
3. **Run specific new test:** `cd backend && .\.venv\Scripts\python -m pytest tests/test_<name>.py -v --tb=short --no-cov`
4. **Check git status:** `git status` from project root

The fastest path to 90% is items 1-3 in the recommended next steps above (~170-240 statements covered).
