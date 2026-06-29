# Open-Source Feature Implementation Plan

**Product:** PQCrypt Sentinel PQC Discovery Platform
**Version:** 1.0
**Date:** June 2026
**Author:** Engineering Team
**Status:** Draft
**Depends On:** `Project Documents/06-Implementation-Plan.md`, `Project Documents/07-Open-Source-Integration-Guide.md`

---

## 1. Purpose

This document specifies the concrete implementation work required to close the gap between the current codebase and the full feature set described in the **Open-Source Integration Guide**. It is a task-level addendum to the existing `06-Implementation-Plan.md` and should be executed within **Phase 3: Scanner Engine — TLS, SSH & Passive Monitoring** (Week 5–7), with CLI wrapper work extending into Phase 8 as host-dependency tasks.

---

## 2. Recap: What Is Already Implemented

| Library / Tool | File | Coverage |
|---|---|---|
| `cryptography` | `backend/app/scanners/cert_parser.py` | Full cert parsing, PQC/hybrid OID classification, key analysis |
| `paramiko` | `backend/app/scanners/ssh_scanner.py` | KEX, host-key, cipher enumeration; PQC keyword matching |
| `dnspython` | `backend/app/scanners/network_discovery.py` | A / AAAA / CNAME / MX / SRV resolution |
| `boto3` | `backend/app/connectors/cloud_kms_connector.py` | AWS KMS + ACM inventory |
| `azure-identity` / `azure-keyvault` | `backend/app/connectors/cloud_kms_connector.py` | Azure Key Vault inventory |
| `google-cloud-kms` | `backend/app/connectors/cloud_kms_connector.py` | GCP KMS inventory |
| `cyclonedx-python-lib` | `backend/app/services/report_service.py` | Two-pass CycloneDX 1.6 CBOM generation |
| `python-nmap` (partial) | `backend/app/scanners/network_discovery.py` | Binary invoked via `asyncio.create_subprocess_exec`, XML parsed manually |

All of the above is already wired into `backend/app/services/scan_orchestrator.py` and produces persisted `Asset`, `Certificate`, and `Algorithm` records.

---

## 3. What Is Missing

### 3.1 Python Libraries — Not Imported Anywhere

| Library | Requires (host) | Gap |
|---|---|---|
| `pyshark` | `tshark` (Wireshark CLI) | No passive capture or PCAP analysis module exists |
| `sslyze` | None (pure Python) | Active TLS scanner uses only `ssl`/`socket`; no cipher-suite matrix output |
| `scapy` | None (pure Python, may need Npcap on Windows) | No packet-crafting module exists |

### 3.2 CLI Wrappers — Not In Code At All

| CLI Tool | Language | JSON Output | Gap |
|---|---|---|---|
| `pqcscan` | Rust | `--output-format json` | No subprocess wrapper |
| `testssl.sh` | Bash | `--jsonfile <path>` | No subprocess wrapper |
| `ssh-audit` | Python/Bash | `-j` | No subprocess wrapper |
| `ike-scan` | C | Custom text parse | Binary not invoked; `ike_scanner.py` manually crafts IKEv2 |
| `Trivy` | Go | `-f json` | Not in requirements, no wrapper |
| `Semgrep` | Python/OCaml | `--json` | Not in requirements, no wrapper |

---

## 4. File Tree: New Files To Create

```
backend/
└── app/
    ├── scanners/
    │   ├── sslyze_scanner.py          # NEW — deep TLS analysis via sslyze Python API
    │   ├── pyshark_capture.py         # NEW — passive + offline PCAP capture
    │   ├── scapy_probe.py             # NEW — crafted TLS ClientHello with PQC groups
    │   └── vendor_pqc_db.py           # NEW — Section 4 of Integration Guide ported to code
    ├── services/
    │   └── cli_scanner_service.py     # NEW — generic subprocess wrapper for all CLI tools
    └── requirements.txt               # MODIFY — add sslyze constraint if not already pinned
```

---

## 5. Task Breakdown

### Task 1 — `backend/app/scanners/sslyze_scanner.py`

**Goal:** Replace the thin `ssl`/`socket` probe in `tls_scanner.py` with a full SSLyze scan that exposes per-protocol cipher suites, certificate validation, and compression attacks.

**Key decisions:**
- Match the existing `TLSScanResult` interface so `scan_orchestrator.py` can import and drop this in with a one-line swap.
- Reuse `cert_parser.parse_certificate()` for certificate analysis — feed it the PEM that sslyze returns.
- Wrap the synchronous `Scanner().get_results()` call in the existing `_SSL_EXECUTOR` `ThreadPoolExecutor`, exactly as `tls_scanner.py:10` does.
- On Windows, `sslyze` requires no extra host binary. No special guard needed beyond standard exception handling.

**Fields to populate (minimal to existing schema):**
- `tls_version` → highest supported version returned by sslyze
- `cipher_suite` → list of accepted cipher suites per TLS version
- `cert_data` → parsed via `cert_parser.parse_certificate()`
- `supported_versions` → `[1.3, 1.2, 1.1, 1.0]` booleans

**Implementation notes:**
- Use `ScanCommand.CERTIFICATE_INFO`, `ScanCommand.TLS_1_3_CIPHER_SUITES`, `ScanCommand.TLS_1_2_CIPHER_SUITES`, `ScanCommand.TLS_1_1_CIPHER_SUITES`, `ScanCommand.TLS_1_0_CIPHER_SUITES`.
- `sslyze` 5.x is already in `requirements.txt:17`; confirm the exact API surface before coding (check `sslyze.scanner.Scanner` and `ScanCommand` enum names in the installed version).

---

### Task 2 — `backend/app/scanners/pyshark_capture.py`

**Goal:** Implement passive TLS/SSH monitoring (SPAN/mirror port) and offline PCAP analysis.

**Two public functions:**
1. `capture_tls_handshakes(interface: str, duration_seconds: int = 60) -> List[Dict]`
   - `pyshark.LiveCapture(interface=..., display_filter="tls.handshake.type == 1 or tls.handshake.type == 2", decode_as={"tcp.port==443": "tls"})`
   - Extract ClientHello (type 1) and ServerHello (type 2) fields using the patterns from Section 2.1 of the Integration Guide.
   - Return a list of normalised dicts (not `TLSScanResult`; this is a discovery/observation mode, not a targeted scan).

2. `analyze_pcap_file(pcap_path: str) -> Dict`
   - `pyshark.FileCapture(input_file=pcap_path, display_filter="tls", decode_as={"tcp.port==443": "tls"})`
   - Aggregate: total handshakes, PQC kex detected, vulnerable kex, certificates extracted, cipher suite set.
   - Must call `cap.close()` at the end (and on every early return) to release file handles.

**Windows guard:**
- `pyshark` requires `tshark.exe` on PATH. Add a startup check using `shutil.which("tshark")`. If missing, raise `RuntimeError("tshark not found — install Wireshark and add to PATH")` at module load time so the orchestrator can log a skip-and-continue event rather than crash mid-scan.

**Host dependency:**
- Add `tshark` to the Docker image build and to the Windows development setup docs in `README.md`.

---

### Task 3 — `backend/app/scanners/scapy_probe.py`

**Goal:** Craft a TLS ClientHello advertising ML-KEM hybrid key exchange groups and probe whether a target server accepts them.

**One public function:**
- `probe_tls_with_pqc_groups(target_ip: str, port: int = 443) -> Dict`

**Implementation notes:**
- Build `TLSClientHello` with `ext=TLS_Ext_SupportedGroups(groups=[0x2B93, 0x2B92, 0x001D, 0x0017])` and modern cipher suites (`0x1301`, `0x1302`, `0x1303`, `0xC02B`, `0xC02F`).
- Send via ` sr1(IP(dst=target_ip)/TCP(dport=port, flags='S'), timeout=5)`.
- A full implementation completes the TCP handshake and sends the TLS record. The Integration Guide shows a simplified probe returning `{"status": "probe_sent", ...}` — use that as the Phase 3 v1 contract, and flag a full handshake implementation as a follow-up ticket.
- Wrap in `ThreadPoolExecutor` with the same pattern as `tls_scanner.py` so it can be awaited from the orchestrator.

**Windows note:** Scapy requires Npcap (not WinPcap). Add Npcap to the Windows dev setup checklist.

---

### Task 4 — `backend/app/services/cli_scanner_service.py`

**Goal:** One generic async subprocess runner that all CLI wrappers use, plus six tool-specific wrapper functions that normalise each tool's native output into the internal schema.

**Module contract:**

```python
async def run_cli_tool(
    command: List[str],
    timeout: int = 30,
    json_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a CLI tool, captures stdout/stderr, parses JSON if available.
    Returns a normalised dict with keys: success, tool, exit_code, findings, raw_output, error.
    """
```

**Six wrapper functions to implement:**

| Function | CLI | Binary check | Output parsing |
|---|---|---|---|
| `run_pqcscan(host, port)` | `pqcscan --target host:port --output-format json --timeout 30` | `shutil.which("pqcscan")` | JSON → `tls_version`, `cipher_suite`, `kex_group`, `kex_group_is_pqc`, `pqc_status` |
| `run_ssh_audit(host, port)` | `ssh-audit -j host port` | `shutil.which("ssh-audit")` | JSON → `kex_algorithms`, `pqc_kex_available`, `pqc_kex_algorithms`, `host_key_algorithms` |
| `run_testssl(host, port, tmp_dir)` | `testssl.sh --jsonfile <path> --color 0 host:port` | `shutil.which("testssl.sh")` | JSON file parse → `protocols`, `cipher_suites`, `vulnerabilities`, `pqc_findings` |
| `run_ike_scan(host, port)` | `ike-scan --ikev2 -M host:port` | `shutil.which("ike-scan")` | Text parse → `ike_version`, `dh_groups`, `encryption_algorithms`, `encryption_algorithms`, `pqc_dh_groups` from `_DH_GROUP_POLICY` in `ike_scanner.py` |
| `run_trivy(target)` | `trivy filesystem --format json <target>` | `shutil.which("trivy")` | JSON → `vulnerabilities` filtered to crypto-related CWE entries |
| `run_semgrep(repo_path, configs)` | `semgrep --config <rules> --json --quiet <repo_path>` | `shutil.which("semgrep")` | JSON → filter hits matching crypto patterns (`RSA_`, `EC_KEY_`, `MD5`, `SHA1`, `DES_`, `RC4`, `hardcoded`, `BEGIN RSA PRIVATE KEY`) |

**Design rules:**
- Each wrapper returns a dict with the same top-level keys: `tool`, `host`, `success`, `error`, `raw_output` (parsed dict or raw string).
- Missing binary → return `{"success": False, "error": "tool not found on PATH", "skipped": True}`. Do NOT raise.
- Timeout handling: wrap with `asyncio.wait_for(proc.communicate(), timeout=timeout+5)`; on `asyncio.TimeoutError`, kill the process and return a timeout error dict.
- `testssl.sh` writes to a temp file. Use `C:\Users\chauh\AppData\Local\Temp\kilo\` on Windows and `/tmp/` on Linux; clean up the file after parsing.

---

### Task 5 — `backend/app/scanners/vendor_pqc_db.py`

**Goal:** Port Section 4 of the Integration Guide into a live Python module so scan results can be enriched with vendor PQC readiness metadata.

**Contract:**

```python
VENDOR_PQC_DB: Dict   # keyed by lower-case software name

def get_pqc_readiness(software: str, version: str) -> Dict[str, Any]:
    """Returns closest version match with ml_kem/ml_dsa booleans and notes."""
```

**Usage in orchestrator:**
- After `network_discovery.py` returns `product`/`version` strings for discovered services, call `get_pqc_readiness(product, version)` and store the result in `asset_metadata["pqc_readiness"]`.
- After cloud connectors return `algorithm` / `key_type` strings, run through the same lookup.

**Extension point:** The dict should be loaded from a JSON sidecar file (`vendor_pqc_db.json` next to the `.py` file) rather than hardcoded, so the Security Engineer can update vendor data without touching code.

---

### Task 6 — Wire Advanced Scanners Into `scan_orchestrator.py`

**Do not overwrite existing TLS/SSH logic.** Add a new optional pass.

**Approach A (preferred for Phase 3):**

Add a new `scan_type` value `"deep"` alongside the existing `"full"`, `"tls_only"`, `"ssh_only"`, `"targeted"`, `"ct_monitor"`. Inside the existing host loop in `scan_orchestrator.py:238-453`, after the standard TLS/SSH block, add:

```python
# Deep TLS pass — SSLyze + scapy + pyshark
if scan.scan_type == "deep":
    from app.scanners.sslyze_scanner import scan_endpoint_with_sslyze
    from app.scanners.scapy_probe import probe_tls_with_pqc_groups
    sslyze_res = await scan_endpoint_with_sslyze(host, port=443)
    scapy_res  = await probe_tls_with_pqc_groups(host, port=443)
    # Merge or persist as additional findings / asset_metadata entries
```

**Approach B (safer, merge-friendly):**

Add a boolean column `advanced_tools` to the `Scan` model, exposed via API/UI. When `True`, the orchestrator runs the extra passes regardless of `scan_type`. This avoids changing the existing enum and lets users opt-in.

**Recommendation:** Use Approach B. It is a single-column migration that does not break any existing queries or frontend assumptions.

---

### Task 7 — CLI Tool Host Dependencies

Add host-level install steps to `README.md` and `docker-compose.yml`:

```markdown
## Host Dependencies (CLI scanners)

| Tool | Windows | Linux | macOS |
|---|---|---|---|
| `tshark` | Chocolatey: `choco install wireshark` | `apt install tshark` | `brew install wireshark` |
| `nmap` | Chocolatey / installer | `apt install nmap` | `brew install nmap` |
| `ssh-audit` | `pip install ssh-audit` | `pip install ssh-audit` | `pip install ssh-audit` |
| `testssl.sh` | Download binary | `apt install testssl.sh` | `brew install testssl.sh` |
| `pqcscan` | Download prebuilt binary | Download prebuilt binary | Download prebuilt binary |
| Npcap | Required for scapy | Not required | Not required |
```

**Docker image additions** (for `docker-compose.yml` runner service):

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    nmap \
    testssl.sh \
    ssh-audit \
    && rm -rf /var/lib/apt/lists/*
```

Note: `pqcscan` is a Rust binary; download the prebuilt release to `/usr/local/bin/` during Docker build.

---

## 6. Task Sequencing and Estimates

All tasks are within Phase 3 scope unless noted.

| # | Task | Effort | Blocking depends on |
|---|---|---|---|
| 1 | `sslyze_scanner.py` | 0.5 day | `cert_parser.py` already done |
| 2 | `pyshark_capture.py` | 1 day | `tshark` installed; `cert_parser.py` done |
| 3 | `scapy_probe.py` | 0.5 day | None; simple probe is independent |
| 4 | `cli_scanner_service.py` | 1 day | None; subprocess wrappers are independent |
| 5 | `vendor_pqc_db.py` | 0.5 day | None; pure data port |
| 6 | Wire into `scan_orchestrator.py` (+ migration) | 0.5 day | Tasks 1–5 merged |
| 7 | Host dependency docs + Dockerfile | 0.5 day | None |

**Total: ~4.5 days** (one engineer, Phase 3 sprint).

The remaining CLI tools (`Trivy`, `Semgrep`) are **optional** and can be deferred to Phase 8 as SAST/SBOM tooling. They are not required for MVP scanner coverage.

---

## 7. Acceptance Criteria

A task is complete when all of the following hold:

1. **SSLyze** — `POST /api/v1/scans` with `scan_type=deep` on a live HTTPS endpoint returns `supported_versions` as a dict of booleans, `tls_versions.<version>.accepted_ciphers` populated, and an SSLyze result surfaced in the scan log.
2. **pyshark** — `pyshark.LiveCapture` can consume a live interface (or PCAP file) and returns `ClientHello` / `ServerHello` dicts with `cipher_suites`, `supported_groups`, and `pqc_kex_detected` boolean. Missing `tshark` raises a clear `RuntimeError` logged as a scan skip, not a crash.
3. **scapy** — `probe_tls_with_pqc_groups(host, 443)` sends a crafted ClientHello with groups `0x2B93` and `0x2B92` and returns `{"probe_sent": True, "target": host, "pqc_groups_advertised": [...]}` without timing out on a non-responsive IP.
4. **CLI wrappers** — Each wrapper handles missing binary gracefully (`skipped: True`), missing JSON output file returns a structured error, and a real run of `ssh-audit -j localhost` (or any reachable SSH server) returns parsed `kex_algorithms` and `pqc_kex_available`.
5. **Vendor DB** — `get_pqc_readiness("openssh", "9.9")` returns `ml_kem: True, ml_dsa: False, notes: "mlkem768x25519 support"`; `get_pqc_readiness("openssl", "3.4")` returns the correct values.
6. **Orchestrator** — A `deep` scan through the API creates `Asset`, `Certificate`, `Algorithm`, and `ScanLog` rows identical to an existing `full` scan, plus additional rows with `discovery_source="sslyze"` / `"pyshark"` / `"scapy"` where applicable.

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| `pyshark` on Windows often fails due to Npcap vs WinPcap | Document Npcap explicitly; guard with `shutil.which("tshark")` at startup; fail-soft with a scan log warning |
| `sslyze` API changes between minor versions | Pin exact version in `requirements.txt`; briefly review `sslyze` 5.x CHANGELOG before implementation |
| `scapy` TCP handshake implementation is fragile on Windows | Implement the simple probe only (SYN sent, SYN-ACK checked); full handshake is a future ticket |
| CLI tool JSON output formats drift across versions | Wrap each wrapper in a `try/except json.JSONDecodeError`; fall back to text parsing; log raw output for debugging |
| `ike-scan` requires raw socket access (admin/root) | Run via `asyncio.create_subprocess_exec` same as nmap; document privilege requirement; skip gracefully on `PermissionError` |
