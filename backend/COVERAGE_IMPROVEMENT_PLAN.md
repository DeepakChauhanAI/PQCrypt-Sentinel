# Coverage Improvement Plan: 90% → 95%

## Final State (as of 2026-06-30)

| Metric | Value |
|--------|-------|
| **Total coverage** | **95.87%** (9,385 / 9,789 statements) |
| Missing statements | 404 |
| Total tests | 1,504 (1,104 original + 400 new); 1,499 passed, 5 skipped |
| Failures | 0 |
| Test framework | pytest + pytest-asyncio + unittest.mock + FastAPI TestClient |
| Coverage tool | pytest-cov / coverage.py 7.13.4 |
| `pytest.ini` | `--cov-fail-under=95` enforced |

## What Was Accomplished

### 9 new test files written (+257 tests)

| Test File | Module | Before | After | Tests |
|-----------|--------|--------|-------|-------|
| `test_algo_classifier_extended.py` | `app/analysis/algo_classifier.py` | 81% | 89% | ~90 |
| `test_aws_pqc_scanner_extended.py` | `app/connectors/aws_pqc_scanner.py` | 73% | 96% | 24 |
| `test_dashboard_extended.py` | `app/api/dashboard.py` | 62% | 64% | ~15 |
| `test_main_extended.py` | `app/main.py` | 56% | 81% | ~6 |
| `test_rate_limit.py` | `app/middleware/rate_limit.py` | 61% | **100%** | ~10 |
| `test_schemas_extended.py` | `app/models/schemas.py` | 92% | 99% | 18 |
| `test_config_extended.py` | `app/config.py` | 83% | **100%** | 19 |
| `test_scan_logs.py` | `app/api/scan_logs.py` | 45% | **100%** | 4 |
| `test_safe_target_extended.py` | `app/scanners/safe_target.py` | 76% | 99% | 16 |

### Fully-covered modules (no further action needed)
- `app/api/reports.py` — 100%
- `app/api/scan_logs.py` — 100%
- `app/api/scan_groups.py` — 99%
- `app/connectors/cloud_kms_connector.py` — 98%
- `app/connectors/k8s_connector.py` — 99%
- `app/connectors/pkcs11_connector.py` — 99%
- `app/connectors/saml_connector.py` — 97%
- `app/connectors/sast_connector.py` — 95%
- `app/connectors/ssh_connector.py` — 99%
- `app/connectors/tde_connector.py` — 99%
- `app/connectors/vault_helper.py` — 100%
- `app/connectors/vault_scanner.py` — 99%
- `app/connectors/winrm_connector.py` — 99%
- `app/middleware/rate_limit.py` — 100%
- `app/config.py` — 100%
- `app/scanners/ct_log_scanner.py` — 100%
- `app/scanners/mail_scanner.py` — 100%
- `app/scanners/sslyze_scanner.py` — 100%
- `app/scanners/tls_scanner.py` — 100%
- `app/services/finding_service.py` — 99%
- `app/tasks.py` — 99%
- `app/utils/retry.py` — 100%

## Remaining Gaps to 95%

Need **~226 more statements** covered (715 → ~489 missing).

| File | Missing | Coverage | Difficulty | Strategy |
|------|---------|----------|-----------|----------|
| `app/api/dashboard.py` | 74 | 64% | Medium | Mock DB + Redis; test safe_count branch (line 124), risk_distribution iteration (lines 194-208), progress scan processing (lines 222-269), layer coverage pqc_status/risk_score (lines 419-477), overall_coverage_pct (lines 495-503), clear_dashboard_cache exception (lines 59-60) |
| `app/api/connectors.py` | 71 | 92% | Medium | Add tests for remaining connector endpoint branches (lines 489-490, 994, 1102, 1252, etc.) |
| `app/services/report_service.py` | 48 | 93% | Medium-Hard | Mock DB + filesystem; test generate_cbom (lines 382+), generate_sarif_report (lines 960+), generate_csv (lines 1118+), generate_pdf (lines 1161+), generate_compliance (lines 1274+), dispatcher (lines 1332-1430) |
| `app/analysis/algo_classifier.py` | 49 | 89% | Easy-Medium | Test fallback cipher-suite paths (lines 208-213), ECC curve variants (lines 421-463), deprecation timeline fallbacks (lines 597-598, 630, 646, 663, 693, 699, 751, 766-768, 773, 801, 804-809, 813-817, 820-826, 838-844) |
| `app/scanners/pyshark_capture.py` | 38 | 81% | Hard | Mock pyshark/live capture; test parsing branches |
| `app/api/scans.py` | 36 | 81% | Medium | Test update/cancel/retry paths, pagination, filtering (lines 46-59, 92-93, 115-127, 237, 239, 312, 317, 376-391) |
| `app/services/scan_host.py` | 33 | 87% | Medium-Hard | Mock scanner functions; test error paths (lines 118, 123-134, 209-210, 252-255, 304-309, 353-354, 440-441, 493-494, 504-537, 550, 559) |
| `app/connectors/csv_connector.py` | 31 | 67% | Medium | Mock file I/O; test CSV parsing edge cases |
| `app/connectors/aws_pqc_scanner.py` | 16 | 96% | Medium | Test KMS/ACM exempt status paths (lines 125-126, 632-633, 640-641, 661-663, 771, 800, 802, 804, 987, 989, 991) |
| `app/main.py` | 13 | 81% | Hard | Test lifespan Redis failure (lines 58-71), shutdown (lines 76-77), health degraded (line 103) |
| `app/utils/cache.py` | 12 | 88% | Medium | Test Redis connection edge cases |
| `app/models/schemas.py` | 4 | 99% | Easy | 4 remaining validators (lines 102, 116, 157, 191) |
| `app/scanners/cert_parser.py` | 10 | 89% | Hard | Mock OpenSSL/x509 parsing |
| `app/scanners/ssh_scanner.py` | 14 | 90% | Medium | Mock SSH scanner edge cases |
| `app/utils/target_classifier.py` | 5 | 95% | Easy | 5 remaining branches |

## Continuation Session Accomplishments

This section records the work done after the original session was terminated by a context-length error.

### Additional test files created

| Test File | Module | Coverage After | Tests |
|-----------|--------|----------------|-------|
| `test_csv_connector.py` (new) | `app/connectors/csv_connector.py` | 98% | 9 |

### Existing test files extended

| Test File | Module | New coverage / notes |
|-----------|--------|----------------------|
| `test_report_service.py` | `app/services/report_service.py` | **100%** — added `_render_compliance_html`, html fmt, scope-filter, and meta-extraction tests |
| `test_jwt_connector.py` | `app/connectors/jwt_connector.py` | 89% — added credential and key-size edge-case tests |
| `test_code_sign_scanner.py` | `app/scanners/code_sign_scanner.py` | 97% — added PKCS#7 blob and PEM error-path tests |
| `test_api_connectors_extended.py` | `app/api/connectors.py` | 92% — added viewer-role permission checks, direct-scan error-status branches, CSV upload error paths |
| `test_dashboard_extended.py` | `app/api/dashboard.py` | **100%** — added unknown-layer skip path |
| `test_aws_pqc_scanner_extended.py` | `app/connectors/aws_pqc_scanner.py` | 99% — added `_parse_key_size` fallback tests |
| `test_algo_classifier_extended.py` | `app/analysis/algo_classifier.py` | 99% — added hybrid KEX group and SECP variant tests |

### Source/config changes

- `backend/pytest.ini`: raised `--cov-fail-under` from `85` to `95` and added `--cov-report=html`.

### Notes on remaining 468 missed statements

A small number of the originally-listed lines are now known to be unreachable in the current implementation (e.g., `resolve_curve_status` SECP fallbacks after the `ck_clean` substring match, and `_parse_key_size` digit fallbacks after the regex match). They were left intact to avoid behavioural changes; the coverage target is still met.

## Recommended Next Steps

### Quick wins (can add ~80-120 statements with ~20 tests)

1. **`app/analysis/algo_classifier.py`** (+30-40 stmts)
   - Test `_classify_cipher_suite` with OpenSSL short names (lines 208-213)
   - Test ECC curve parsing variants (P-192, P-224, lines 421-463)
   - Test deprecation fallback timeline (lines 597-598, 630, 646, 663, 693, 699, 751, 766-768, 773)
   - These are pure functions, no mocks needed

2. **`app/api/dashboard.py`** (+20-30 stmts)
   - Test `_worst_pqc_status()` with "safe" input (line 79)
   - Test `/summary` with safe_count > 0 (line 124)
   - Test `/risk-distribution` body iteration (lines 194-208)
   - Test `/progress` scan processing loop (lines 222-269)
   - Test `/layer-coverage` with pqc_status breakdown (lines 419-457)

3. **`app/connectors/aws_pqc_scanner.py`** (+10-15 stmts)
   - Test ACM cert with `Status != "ISSUED"` (lines 125-126)
   - Test KMS key with `KeyState != "Enabled"` (lines 632-633)
   - Test S3 `aws:kms:dsse` path (lines 640-641, 661-663)

4. **`app/models/schemas.py`** (+4 stmts)
   - Test `ScanOut.coerce_uuid_to_str` (line 102)
   - Test `ScanLogCreate.normalize_level` (lines 114-116)
   - Test `AlgorithmOut.coerce_uuid_to_str` (lines 130-132)
   - Test `CertificateOut.coerce_uuid_to_str` (lines 155-157)

### Medium effort (can add ~80-100 statements)

5. **`app/services/report_service.py`** (+30-40 stmts)
   - Mock DB + filesystem; test pure post-processing functions
   - `_ecma424_order_recursive`, `_reorder_crypto_properties`, `post_process_cbom`
   - Test `generate_sarif_for_sast_findings` (pure function)

6. **`app/api/connectors.py`** (+30-40 stmts)
   - Add tests for remaining API branches, 404/422 error paths, pagination

7. **`app/scanners/pyshark_capture.py`** (+15-20 stmts)
   - Mock pyshark/tshark; test version detection and parsing edge cases

### Harder targets (require more mocking)

8. **`app/services/scan_host.py`** (+20-25 stmts) — mock all scanner calls
9. **`app/services/scan_orchestrator.py`** (+10-15 stmts remaining) — already 95%, fill final gaps
10. **`app/api/scans.py`** (+20-25 stmts) — mock DB for update/cancel paths

## Updated pytest.ini

After reaching 95%, update `backend/pytest.ini`:

```ini
[pytest]
asyncio_mode = strict
addopts = --cov=app --cov-report=term-missing --cov-report=html --cov-fail-under=95
```

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Tests timeout (>5min) | Run with `pytest -x --timeout=300`; split into parallel runs |
| Mock complexity for connectors | Use `SimpleNamespace` + `AsyncMock` patterns from existing connector tests |
| Coverage measurement includes test files | Verify `--cov=app` doesn't include `tests/` directory |
| Import-time side effects in `algo_classifier.py` | Module runs `load_registry_file()` at import; ensure registry file exists or mock at import |
| Circular imports | Follow existing pattern: import inside test functions, not at module level |

## Test Patterns to Follow

Based on existing test conventions in `tests/`:

1. **Imports**: Use `from app.module import function` inside test functions (not at module top)
2. **Async tests**: Use `asyncio.run()` for async functions, not `@pytest.mark.asyncio`
3. **Mocks**: Use `unittest.mock.AsyncMock` for DB sessions, `MagicMock` for sync objects
4. **Fixtures**: Reuse `mock_db`, `mock_user`, `client`, `auth_override` from `conftest.py`
5. **SimpleNamespace**: Use for mock ORM objects (Asset, Scan, Finding, etc.)
6. **Dependency overrides**: Override `get_session` and `get_current_user` on the FastAPI app
7. **No real DB**: All tests must work with mocked sessions — never hit a real database
8. **No real network**: Mock all external services (Vault, AWS, Azure, GCP, K8s, SSH, WinRM)
