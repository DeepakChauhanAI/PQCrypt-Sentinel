# Secure Development & Cryptographic Baseline Document

**Product:** PQCrypt Sentinel  
**Version:** 1.0  
**Date:** June 2026  
**Status:** Draft  
**Owner:** Security Engineering  
**Audience:** Developers, security reviewers, CI/CD maintainers, customer security auditors

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Threat Model for the Platform Itself](#2-threat-model-for-the-platform-itself)
3. [Dependency Security Standards](#3-dependency-security-standards)
4. [Cryptographic Library Selection Rules](#4-cryptographic-library-selection-rules)
5. [Pre-Commit Security Gates](#5-pre-commit-security-gates)
6. [CI/CD Security Gates](#6-cicd-security-gates)
7. [Secrets & Key Management](#7-secrets--key-management)
8. [Build & Runtime Hardening](#8-build--runtime-hardening)
9. [Scanner Process Isolation](#9-scanner-process-isolation)
10. [Audit Trail Integrity](#10-audit-trail-integrity)
11. [Monitoring & Incident Response](#11-monitoring--incident-response)
12. [Release Security Checklist](#12-release-security-checklist)

---

## 1. Purpose

PQCrypt Sentinel is a security product whose credibility depends entirely on one thing: **does it practice what it preaches?**

If the platform itself uses quantum-vulnerable algorithms, has exploitable dependency vulnerabilities, or leaks secrets, the product is worse than useless — it becomes an attack surface for every customer who deploys it.

This document defines the minimum security standards that every commit, build, and release must meet before it reaches a customer.

**These rules are non-negotiable.** They are enforced automatically in CI, reviewed manually at each release, and auditable by customers.

---

## 2. Threat Model for the Platform Itself

The platform handles secrets, runs untrusted scanners, and holds the cryptographic map of an enterprise. The threat model covers:

| Threat | Source | Impact |
|---|---|---|
| Exploitable CVEs in dependencies | Public | Scanner compromise, lateral movement |
| Weak or outdated crypto in the platform's own auth | Internal or attacker | Credential theft, token forgery |
| Scanner process escapes into the API tier | Malicious scan target | Full database access |
| Secrets leakage in logs or evidence store | Developer error or tool bug | Customer credential exposure |
| Supply chain attack on build pipeline | CI/CD compromise | Backdoor in shipped product |
| SSRF via scanner workers | Misconfiguration | Access to internal metadata endpoints |
| Audit log tampering | Insider threat | Compliance failure, evidence loss |

---

## 3. Dependency Security Standards

### 3.1 Prohibited Dependency Types

The following are **never allowed** in the codebase. CI must fail on detection.

| Prohibited | Rationale |
|---|---|
| `pycrypto` | Unmaintained since 2012, multiple CVEs, replaced by `cryptography` |
| `cryptography` below 42.0.0 | Multiple CVEs in earlier versions |
| `OpenSSL` runtime below 3.0 in scanner images | Heartbleed-class vulnerabilities in 1.x |
| Unpinned dependencies | Reproducible builds and CVE tracking require pins |
| Dependencies with no CVE history but no maintainer | Abandonware risk |

### 3.2 Allowed Cryptographic Libraries (with locked versions)

These are the only libraries that may perform cryptographic operations. Any new crypto library must be approved by security review before merge.

| Library | Minimum Version | Allowed For | Rationale |
|---|---|---|---|
| `cryptography` (pyca) | `>= 42.0.0` | X.509 parsing, signature verification, key analysis | Actively maintained, backed by PyCA, audited |
| `python-jose` | `>= 3.3.0` | JWT creation and verification | Widely used, no known critical CVEs in recent versions |
| `passlib[bcrypt]` | `>= 1.7.4` | Password hashing | bcrypt via passlib, cross-platform |
| `bcrypt` (direct) | `>= 4.0.0` | Password hashing (alternative) | Pure-Python fallback available |
| `cryptography` hazmat | via `cryptography` package | RSA/ECDSA operations for JWT | Via python-jose |

### 3.3 JWT Configuration Standards

JWT is the authentication backbone. These settings are non-negotiable:

| Setting | Value | Rationale |
|---|---|---|
| Algorithm | `HS256` (MVP) | Symmetric, no pubsub key exposure in MVP |
| Access token lifetime | 60 minutes | Limits window for token theft |
| Refresh token lifetime | 7 days | Limits duration of stolen refresh cookie |
| Secret key length | 32+ bytes (256 bits) | HMAC-SHA256 minimum |
| Secret key rotation | Every 90 days | Limits damage from undetected leak |
| Key generation | `openssl rand -hex 32` | OS-level CSPRNG |

**What is prohibited:**
- `HS384` or `HS512` without a documented reason (HS256 is sufficient for 1-hour tokens)
- `alg: none` in any token validation path
- Secret keys shorter than 32 bytes
- Secret keys stored in environment variables without encryption at rest (Vault for Phase 2)
- JWT tokens stored in `localStorage` (use httpOnly cookies for refresh tokens only)

### 3.4 Algorithm Classification Policy

The platform's algorithm classifier maps algorithms to PQC status. This classifier is the single most trusted output of the product. It must be accurate.

| Rule | Enforcement |
|---|---|
| All PQC OIDs must reference NIST FIPS 203/204/205 standard OIDs | Unit test: every key in PQC OID map must have NIST citation in comment |
| Classical algorithm OIDs must reference IETF RFC or NIST publication | Unit test: every classical OID must have RFC citation |
| Unknown OIDs must map to `pqc_status = "unknown"` — never `vulnerable` | Unit test: random hex string → `unknown` |
| `is_quantum_vulnerable` must be `True` for all RSA/ECC/Ed25519 and `False` for all ML-KEM/ML-DSA/SLH-DSA | Complete map coverage test |
| The OID map lives in Python source code, not in the database, in MVP | Prevents tampering; DB-backed map is a Phase 2 feature |

---

## 4. Cryptographic Library Selection Rules

No cryptographic library may be added to the project without going through this gate:

```
CAN THIS LIBRARY BE APPROVED?
├─ Is it a well-known library used by major security products?
│  ├─ YES → Continue
│  └─ NO → Requires external security audit before approval
│
├─ Does it have an active maintainer (commit in last 12 months)?
│  ├─ YES → Continue
│  └─ NO → Rejected unless a fork with active maintainer is used
│
├─ Does it have no unpatched CRITICAL CVEs?
│  ├─ YES → Continue
│  └─ NO → Rejected until patched
│
├─ Does it use the OS CSPRNG (os.urandom / /dev/urandom)?
│  ├─ YES → Continue
│  └─ NO → Rejected (no custom PRNGs)
│
└─ Does it expose raw key material or plaintext credentials in logs/serialization?
   ├─ NO → Approved
   └─ YES → Rejected, or requires explicit sanitization wrapper
```

### 4.1 Approved Libraries Summary

| Category | Approved | Condition |
|---|---|---|
| TLS scanning | `sslyze`, `pyshark` (tshark backend) | Use sslyze Python API directly; pyshark requires tshark ≥ 4.0 |
| SSH analysis | `paramiko`, `ssh-audit` | paramiko ≥ 3.3 |
| Certificate parsing | `cryptography` (pyca) | ≥ 42.0.0 only |
| Packet crafting | `scapy` | Use only for outbound probes; never process inbound untrusted packets |
| Network discovery | `python-nmap`, `dnspython` | nmap ≥ 7.90 |
| Hashing | stdlib `hashlib` | Use SHA-256 or SHA-3 only for new code |
| Password hashing | `passlib[bcrypt]` or `bcrypt` ≥ 4.0 | Cost factor 12 minimum |
| JWT | `python-jose[cryptography]` ≥ 3.3.0 | HS256 only (MVP); RS256 allowed in Phase 2 with key rotation |
| Random generation | stdlib `os.urandom`, `secrets` module | No custom PRNG |
| Symmetric encryption (future) | `cryptography` Fernet or AES-GCM | AES-256-GCM only; no AES-CBC, no ECB, no custom modes |

### 4.2 Forbidden Practices

| Practice | Why Forbidden | Alternative |
|---|---|---|
| AES-CBC mode | Requires custom padding; padding oracle risk | AES-256-GCM (authenticated encryption) |
| ECB mode for block encryption | Reveals plaintext patterns | GCM or ChaCha20-Poly1305 |
| MD5 for any purpose | Collision attacks since 2004 | SHA-256 or SHA-3 |
| SHA-1 for signatures | Collision attacks demonstrated (SHAttered) | SHA-256 minimum |
| RC4 stream cipher | Biased keystream, practical breaks | ChaCha20-Poly1305 if stream needed |
| 3DES (Triple DES) | 64-bit block, meet-in-the-middle attack | AES-256 |
| Custom PRNG (`random` module) | Mersenne Twister is not cryptographically secure | `secrets` module or `os.urandom` |
| RSA with PKCS#1 v1.5 padding | Bleichenbacher attack | RSA-OAEP or migrate to ML-KEM |
| Static IV or nonce in AES-GCM | Nonce reuse == key reuse in GCM | Random 96-bit nonce per encryption |
| Storing secrets in `config.py` or `.env` in git | Accidental exposure during PR review | Vault integration (Phase 2); gitignored .env (MVP) |

---

## 5. Pre-Commit Security Gates

All security checks run on every `git commit` via `.pre-commit-config.yaml`. If any check fails, the commit is blocked.

### 5.1 Enforced Checks

```yaml
# .pre-commit-config.yaml — full configuration

repos:
  # ── Python security checks ──────────────────────────────────────
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ["-ll", "-r", "backend/"]
        name: bandit — security issue scanner

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
        args: ["--select=S", "backend/"]  # S = security rules (bandit subset)
        name: ruff — security lint rules

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-yaml
      - id: check-toml
      - id: check-json
      - id: detect-private-key        # BLOCKS committed private keys
      - id: detect-secrets           # Gitleaks-based secret detection
        args: ["--exclude", "tests/fixtures/", "--exclude", "docs/"]
      - id: check-added-large-files
        args: ["--maxkb=500"]        # PCAP/binary uploads blocked in git

  # ── Python code quality ──────────────────────────────────────────
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
        args: ["--fix"]
        name: ruff — auto-fix lint issues

  - repo: https://github.com/psf/black
    rev: 24.4.0
    hooks:
      - id: black
        name: black — code formatting

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        name: mypy — type checking
        args: ["backend/app/"]
        additional_dependencies:
          - "pydantic>=2.0"
          - "sqlalchemy[aio]>=2.0"
          - "types-passlib"
          - "types-redis"

  # ── Frontend security checks ────────────────────────────────────
  - repo: https://github.com/awebdeveloper/pre-commit-lint-staged
    rev: v0.3.5
    hooks:
      - id: lint-staged
        name: lint-staged — frontend lint on changed files

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]
        name: detect-secrets — baseline diff check

  # ── Dockerfile security ──────────────────────────────────────────
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        name: hadolint — Dockerfile lint
```

### 5.2 What Each Gate Catches

| Gate | Blocks | Example caught |
|---|---|---|
| `detect-private-key` | Commits containing PEM keys, SSH private keys, JWK private keys | `-----BEGIN RSA PRIVATE KEY-----` |
| `detect-secrets` | API keys, passwords, tokens in source code | `AWS_SECRET_ACCESS_KEY = "..."` |
| `bandit` | Insecure Python: hardcoded passwords, weak hashing, shell injection | `hashlib.md5(password)` |
| `ruff --select=S` | Insecure Python: `random.random()` for security, weak TLS settings, assert bypass | `random.seed()` used for token generation |
| `check-added-large-files` | Binary blobs in git (pcap files, cert bundles >500KB) | `tests/fixtures/large.pcap` |
| `mypy` | Type errors that could mask security logic bugs | `None` passed where `str` expected for API key |

### 5.3 Secrets Baseline Management

Generate a baseline after the initial audit:

```bash
# First run: generate baseline of current (clean) secrets in repo
detect-secrets scan --baseline .secrets.baseline

# On each commit: compares against baseline, flags NEW secrets
# If a real secret is found in code: fix the code, don't update the baseline
# If a false positive (test fixture): add to .secrets-whitelist
git add .secrets.baseline
```

The `.secrets.baseline` file must be committed. Any difference from it on `git commit` triggers a review.

---

## 6. CI/CD Security Gates

The CI pipeline must run on every PR and branch push before merge. A PR cannot be merged if any gate fails.

### 6.1 Required Gates (in order)

```
PR Created / Pushed
    │
    ▼
┌───────────────────────────────────────────────────────┐
│ GATE 1: Dependency Pinning                           │
│ • Poetry lock / requirements.txt committed            │
│ • pip-audit / npm audit run                           │
│ • FAIL: any CRITICAL CVE in production dependencies   │
│ • WARN: any HIGH CVE — must have issue + timeline     │
└───────────────────────┬───────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 2: Dependency Age                                │
│ • pip-audit checks for EOL packages                   │
│ • FAIL: pycrypto, pyopenssl below 24.0, requests<2.32 │
│ • All Node packages within 6 months of latest minor   │
└───────────────────────┬───────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 3: SAST (Static Application Security Testing)   │
│ • Bandit (Python security linter)                     │
│ • Semgrep with security ruleset                       │
│ • ESLint security plugin (frontend)                   │
│ • FAIL: any HIGH severity finding                      │
│ • FAIL: any CRITICAL severity finding                  │
└───────────────────────┬───────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 4: Cryptographic Policy Check (custom)          │
│ • Custom script: verify no forbidden imports          │
│   - no 'Crypto.Cipher.AES' (pycrypto)                 │
│   - no 'Crypto.Hash.MD5' (pycrypto)                   │
│   - no 'random' for token generation                   │
│   - no 'DES', 'RC4', 'Blowfish' in crypto imports     │
│ • FAIL: any forbidden import found                    │
└───────────────────────┬────────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 5: Test Suite                                    │
│ • pytest with --cov --cov-fail-under=80               │
│ • Frontend: vitest --run (no watch)                   │
│ • FAIL: any test failure or coverage drop             │
│ • FAIL: new code in security-critical path            │
│   (auth/, scanners/, analysis/) without tests         │
└───────────────────────┬────────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 6: Docker Image Security Scan                    │
│ • Trivy on built Docker images                        │
│ • FAIL: any CRITICAL CVE in base image or packages    │
│ • WARN: any HIGH CVE — must be addressed before merge │
│ • FAIL: image runs as root (must use non-root user)   │
└───────────────────────┬────────────────────────────────┘
                        │ pass
                        ▼
┌───────────────────────────────────────────────────────┐
│ GATE 7: Dependency License Check                      │
│ • pip-licenses / license-checker                      │
│ • FAIL: any license that prohibits commercial use      │
│ • WARN: AGPL, GPL-3 — legal review required           │
└───────────────────────┬────────────────────────────────┘
                        │ pass
                        ▼
                    ALL GATES PASS
                    Merge allowed
```

### 6.2 CI Configuration (GitHub Actions)

```yaml
# .github/workflows/security-gates.yml
name: Security Gates
on: [pull_request, push]

jobs:
  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install pip-audit
        run: pip install pip-audit
      - name: Audit Python dependencies
        run: |
          pip install -r backend/requirements.txt
          pip-audit --strict --fix  # --strict = FAIL on any CVE

  sast-bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run bandit
        run: |
          pip install bandit
          bandit -r backend/app -ll -f json -o bandit-report.json
          bandit -r backend/app -ll  # fails on HIGH/CRITICAL

  sast-semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run semgrep security rules
        run: |
          pip install semgrep
          semgrep --config p/security-audit --error --json backend/

  crypto-policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check for forbidden crypto imports
        run: |
          FORBIDDEN="pycrypto|Crypto\.Cipher\.AES|Crypto\.Hash\.MD5|Crypto\.Cipher\.DES|rc4|from random import"
          MATCHES=$(grep -rnE "import ($FORBIDDEN)|from ($FORBIDDEN)" backend/ || true)
          if [ -n "$MATCHES" ]; then
            echo "FORBIDDEN CRYPTO IMPORT FOUND:"
            echo "$MATCHES"
            exit 1
          fi
          echo "Crypto policy check passed."

  docker-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker images
        run: docker compose build
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'pqcrypt-api:latest,pqcrypt-worker:latest'
          format: 'sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # fail on CRITICAL

  license-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check licenses
        run: |
          pip install pip-licenses
          pip-licenses --format=json --output-file=licenses.json
          # CI checks for AGPL, GPL-3 in production deps
```

---

## 7. Secrets & Key Management

### 7.1 What Counts as a Secret

| Secret | Storage Location | Who Can Access |
|---|---|---|
| User passwords | PostgreSQL as bcrypt hash | Not even admins (one-way hash) |
| JWT secret key (`SECRET_KEY`) | Vault (Phase 2) or encrypted env var (MVP) | API server process only |
| Refresh token blocklist | `sessions.token_hash` (bcrypt) | API server |
| API key hashes | `api_keys.key_hash` (bcrypt) | Not even admins in plaintext |
| CMDB passwords | Vault at `secret/pqc/connectors/{id}` | API/worker process at runtime |
| Cloud IAM keys | Vault or IAM role (AWS) | Worker process at runtime |
| SMTP credentials | Vault or env var SMTP_PASSWORD | API/worker process at runtime |

### 7.2 The Golden Rule

> **The database never contains a secret that could be used to access another system.**

This means:
- `connectors.credentials_ref` stores only `vault:secret/pqc/connectors/conn-123` — never the actual password.
- `findings.evidence` JSONB is sanitized before storage: all patterns matching `password`, `secret`, `api_key`, `token`, `BEGIN PRIVATE KEY` are redacted to `***REDACTED***`.
- Scan logs never contain credentials. The logger strips any line matching credential patterns before writing.
- `SCAN_TOOL_MISSING` errors mention only the configured path, not any credential paths.

### 7.3 JWT Secret Key Receipt and Storage

**On first deployment:**

```bash
# Generate secret key — use OS CSPRNG, not a password manager
openssl rand -hex 32
# Example output: a1b2c3d4e5f6... (64 hex chars = 256 bits)

# Store in .env (gitignored)
echo "SECRET_KEY=<output-from-above>" >> .env

# Verify length
python -c "import os; key=os.environ['SECRET_KEY']; print(f'Length: {len(key)} chars, {len(key)*4} bits')"
# Must output: Length: 64 chars, 256 bits
```

**On rotation (every 90 days):**

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -hex 32)

# 2. Update .env (and Vault in Phase 2)
# SECRET_KEY=<old>, NEXT_SECRET_KEY=<new>

# 3. Deploy with both keys active
# API validates tokens signed by either key during transition period

# 4. After 1 hour (all old tokens expired): remove old key

# 5. Log rotation event to audit log
```

---

## 8. Build & Runtime Hardening

### 8.1 Docker Security

All Dockerfiles must follow these rules:

| Rule | Enforcement |
|---|---|
| Non-root user in container | `USER pqcrypt` in Dockerfile; fail if `USER root` in final stage |
| Minimal base image | Use `python:slim` (not full `python`), `node:slim` |
| No package manager cache in final image | `rm -rf /var/lib/apt/lists/*` in same RUN layer |
| No SSH keys in image | `.ssh/` never copied into Docker build context |
| No `.env` in image | `.env` is gitignored and never copied |
| Health checks | Each service has `HEALTHCHECK` instruction |
| Read-only filesystem where possible | `volumes:` mounted as `ro:` for static assets |
| No `CAP_SYS_ADMIN` | Not granted in docker-compose.yml |
| No `--privileged` flag | Never used |
| Content trust | `DOCKER_CONTENT_TRUST=1` when pulling base images (Phase 2) |

### 8.2 Runtime Security Seccomp Profile (Phase 3 / K8s)

The scanner worker container needs network access but should be restricted:

```json
{
  "defaultAction": "SCMP_ERR_EPERM",
  "allowUnsafe": false,
  "syscalls": [
    { "name": "read" },
    { "name": "write" },
    { "name": "open" },
    { "name": "close" },
    { "name": "socket" },
    { "name": "connect" },
    { "name": "accept" },
    { "name": "bind" },
    { "name": "sendto" },
    { "name": "recvfrom" },
    { "name": "select" },
    { "name": "poll" },
    { "name": "epoll_create" },
    { "name": "epoll_wait" },
    { "name": "fork" },
    { "name": "execve" },
    { "name": "exit" },
    { "name": "kill" },
    { "name": "wait4" },
    { "name": "getpid" },
    { "name": "gettimeofday" },
    { "name": "clock_gettime" }
  ]
}
```

### 8.3 CSP Headers

The frontend served by Nginx must have these security headers:

```nginx
# nginx.conf — security headers block
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';  /* Tailwind needs inline */
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' wss://localhost:8000;  /* WebSocket */
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
" always;

add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## 9. Scanner Process Isolation

The scanner worker is the most dangerous component in the system. It connects to arbitrary external hosts, parses untrusted binary data (PCAP files, certificate chains), and runs subprocesses.

### 9.1 Process Architecture

```
                 ┌──────────────────────────────────┐
                 │      Scanner Docker Network       │
                 │      (isolated from API tier)     │
                 │                                  │
                 │   ┌──────────────────────────┐   │
                 │   │   Celery Worker Process   │   │
                 │   │   (runs as non-root user  │   │
                 │   │    pqcrypt:pqcrypt UID    │   │
                 │   │    1000:1000)             │   │
                 │   └──────────┬───────────────┘   │
                 │              │                    │
                 │   ┌──────────▼───────────────┐   │
                 │   │   Subprocess Sandbox      │   │
                 │   │   (per-scan or per-batch) │   │
                 │   │   • Resource limits       │   │
                 │   │   • Timeout enforcement   │   │
                 │   │   • Network namespace     │   │
                 │   └──────────────────────────┘   │
                 │                                  │
                 │   Tools run HERE:                │
                 │   tshark, nmap, pqcscan,         │
                 │   testssl.sh, ssh-audit, scapy   │
                 │                                  │
                 │   Outbound: ALLOWED              │
                 │   Inbound: DENIED (no listening) │
                 │   Metadata IP: DENIED (SSRF block)│
                 └──────────────────────────────────┘
```

### 9.2 SSRF Prevention

The scanner worker must not be able to reach cloud provider metadata endpoints. These are the most common SSRF targets in cloud environments:

| Endpoint | Blocked | Method |
|---|---|---|
| `http://169.254.169.254/latest/meta-data/` (AWS) | Yes | iptables rule in worker container |
| `http://169.254.169.254/metadata/instance` (Azure) | Yes | iptables rule |
| `http://metadata.google.internal/` (GCP) | Yes | iptables rule |
| `http://[::ffff:169.254.169.254]/` (IPv6 variant) | Yes | iptables rule |
| Internal RFC 1918 ranges on scan management interface | Yes | Network policy in K8s |

Implementation — add to Dockerfile or entrypoint:

```bash
# Block cloud metadata IPs at the network level
iptables -A OUTPUT -d 169.254.169.254 -j DROP
iptables -A OUTPUT -d metadata.google.internal -j DROP
iptables -A OUTPUT -d 100.100.100.200 -j DROP  # Azure metadata
```

### 9.3 Subprocess Timeout Enforcement

Every subprocess call (pqcscan, testssl.sh, ssh-audit, nmap, tshark) must be wrapped with a hard timeout. A runaway scanner process must not consume resources indefinitely.

```python
import asyncio

TIMEOUT_SECONDS = 30  # Enforced at wrapper level

async def run_subprocess_safe(cmd: list[str], timeout: int = TIMEOUT_SECONDS) -> tuple[int, bytes, bytes]:
    """
    Run a subprocess with hard timeout.
    Returns (returncode, stdout, stderr).
    Raises asyncio.TimeoutError on timeout — caller handles gracefully.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Resource limits are set at Docker level (cgroups)
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout, stderr
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"Subprocess timed out after {timeout}s: {' '.join(cmd)}")
```

### 9.4 Resource Limits

Set cgroup limits in `docker-compose.yml`:

```yaml
services:
  worker:
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 8G
        reservations:
          cpus: "1.0"
          memory: 2G
    # Per-process ulimits
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    # Prevent core dumps from leaking secrets
    security_opt:
      - no-new-privileges:true
```

---

## 10. Audit Trail Integrity

The scan evidence store is append-only. This is a security feature — it means findings cannot be silently altered after the fact. But the append-only property must be enforced technically, not just by convention.

### 10.1 Database-Level Enforcement

```sql
-- Prevent UPDATE and DELETE on evidence tables via database role separation

-- Create a role that CANNOT modify evidence
CREATE ROLE scanner_writer NOLOGIN;
GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA public TO scanner_writer;
-- scanner_writer has NO UPDATE, NO DELETE permissions

-- Application connects as scanner_writer for write operations
-- Separate read-only role for dashboard queries
CREATE ROLE app_reader NOLOGIN;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;
```

In SQLAlchemy, use separate engine configurations for read vs write if enforcing at the app level:

```python
# write_engine: INSERT only (via DB role permissions)
# read_engine:  SELECT only (via DB role permissions)
# Admin operations: separate admin role with UPDATE/DELETE
```

### 10.2 Evidence Hash Chain (Phase 2)

For compliance-grade audit trails, implement a hash chain: each scan result row includes a SHA-256 hash of the previous scan result. Any modification to a historical row breaks the chain and is detectable.

```python
import hashlib

def compute_evidence_hash(scan_result: dict, previous_hash: str | None) -> str:
    """Compute SHA-256 hash chain for scan evidence immutability."""
    payload = json.dumps(scan_result, sort_keys=True, default=str)
    if previous_hash:
        payload = previous_hash + ":" + payload
    return hashlib.sha256(payload.encode()).hexdigest()
```

This is a Phase 2 feature — the append-only design (no UPDATE/DELETE permissions) provides the core guarantee in MVP.

---

## 11. Monitoring & Incident Response

### 11.1 What Must Be Logged (and What Must Not)

| Log This | Do NOT Log This |
|---|---|
| Authentication attempt (success/failure) with IP | Password values, even hashed |
| Scan creation: who, what target, credential tier used | Credential values retrieved from vault |
| Scan completion/failure | Raw scan output that may contain internal hostnames (sanitized version only) |
| Credential access event (vault read) | Vault path is logged — but NOT the value at that path |
| RBAC violation attempt | Full JWT payload (log sub and role only, not the token itself) |
| Dependency scan results | Private key material from scanned certificates |
| Rate limit trigger | Full request body |

### 11.2 Security Event Alerting

| Event | Severity | Alert |
|---|---|---|
| 5+ failed logins from same IP in 10 min | HIGH | → Admin Slack/email |
| RBAC violation (viewer trying analyst endpoint) | MEDIUM | → Application log + weekly admin summary |
| Scan worker subprocess timeout > 3 in 1 hour | HIGH | → Admin alert |
| Trivy finds CRITICAL CVE in any image | CRITICAL | → Block merge in CI + instant Slack to security channel |
| Detected PQC OID not in vendor database | LOW | → Admin notification, auto-create "add to DB" ticket |
| Scanner subprocess exit code non-zero | MEDIUM | → Logged with full stderr |
| Credential vault unreachable | HIGH | → Block new scans, alert admin, retry with backoff |
| Audit log write failure | CRITICAL | → Alert + refuse to proceed (fail closed) |

### 11.3 Incident Response: If a Security Issue Is Found in Production

1. **Identify scope:** Which version is affected? Which customers are deployed on it?
2. **Contain:** Disable affected feature via feature flag or emergency deploy. Rotate `SECRET_KEY`.
3. **Assess:** Was any data accessed? Were any credentials exposed?
4. **Notify:** Affected customers within 72 hours per typical breach notification requirements.
5. **Patch:** Security fix in a patch release (hotfix branch, expedited review).
6. **Post-mortem:** Document root cause, update this document, update dependency audit rules.

The incident response runbook is maintained separately. This document defines the preventative controls.

---

## 12. Release Security Checklist

Complete every item before tagging a release.

### Pre-Release (CI Verified)

- [ ] All 7 CI security gates pass on `main` branch
- [ ] No CRITICAL Trivy findings in final Docker images
- [ ] All HIGH Trivy findings documented with accepted-risk or patched rationale
- [ ] `pip-audit` shows zero CRITICAL, zero HIGH in production dependencies
- [ ] `npm audit --production` shows zero CRITICAL, zero HIGH
- [ ] Bandit reports zero HIGH/CRITICAL in `backend/app/`
- [ ] Semgrep security rules pass with zero findings
- [ ] Custom crypto-policy check passes (no forbidden imports)
- [ ] `SECRET_KEY` is 64 hex chars (256 bits), generated via `openssl rand -hex 32`
- [ ] `.env.example` has no placeholder secrets (only `change-me` warnings)
- [ ] No `fetch(`, `axios(`, or HTTP calls in frontend going to undocumented endpoints
- [ ] All API endpoints have error response envelope (tested in integration tests)

### Dependency Review

- [ ] All Python packages pinned in `requirements.txt` with exact versions
- [ ] All Node packages locked in `package-lock.json`
- [ ] No dependency added in this release that skipped the approval gate (Section 4.1)
- [ ] Any new dependency has been scanned with `pip-audit` and `snyk test`
- [ ] Dependency licenses verified: no AGPL/GPL in production code without legal review

### Docker Image Review

- [ ] Final images built with `DOCKER_BUILDKIT=1`
- [ ] Multi-stage build confirmed: no build tools in final image
- [ ] Containers run as non-root user (`pqcrypt` UID 1000)
- [ ] No secrets in image layers (verified with `docker history --no-trunc`)
- [ ] Base image digest pinned in docker-compose.yml (not `latest` tag)
- [ ] Image size within budget: API < 800MB, worker < 2GB

### Code Review

- [ ] Every new auth/scanner/connector endpoint has an integration test
- [ ] Every PQC OID classification has a unit test
- [ ] Every new API endpoint has RBAC decorator checked by reviewer
- [ ] No `print()` statements that could leak secrets (use `logging` with filtered handlers)
- [ ] No `DEBUG = True` in production FastAPI configuration
- [ ] No CORS wildcard (`"*"`) in production config
- [ ] All `subprocess` calls reviewed for shell injection vectors
- [ ] No raw SQL strings — ORM queries only (checked via `ruff` + manual review)
- [ ] All error messages sanitized — no credential paths, no internal IPs exposed to user

### Deployment Review

- [ ] `docker-compose.yml` uses named secrets or env var references — no hardcoded credentials
- [ ] PostgreSQL `pg_hba.conf` uses scram-sha-256 authentication, not `trust`
- [ ] Redis has `requirepass` set in production
- [ ] TLS certificates for the platform's own HTTPS are valid and not expired
- [ ] Backup strategy documented and tested (pg_dump → S3 or NFS)
- [ ] Monitoring configured: health check endpoints responding, alerts wired

### Final Sign-Off

- [ ] Security engineering has reviewed all changes since last release
- [ ] At least one reviewer has read and approved changes to `backend/app/auth/`
- [ ] At least one reviewer has read and approved changes to `backend/app/scanners/`
- [ ] Release notes include: new dependencies, dependency updates, any waived CI gates with rationale
- [ ] Version in `pyproject.toml` and `package.json` matches git tag

---

## Appendix A: Quick Dependency Scan Command

Run this before every release commit:

```bash
# Python — CRITICAL CVEs
pip install pip-audit
pip-audit --strict  # FAIL on any CVE (recommended for CLI use)

# Python — outdated packages
pip list --outdated | grep -E "cryptography|jose|passlib|bcrypt|fastapi|sqlalchemy|pydantic|celery|redis|pyshark|scapy|paramiko|sslyze|boto3"

# Node — known vulnerabilities
npm audit --omit=dev --json | jq '.vulnerabilities | to_entries | map(select(.value.severity == "critical"))'

# Docker — image CVEs
trivy image --severity CRITICAL pqcrypt-api:latest
trivy image --severity CRITICAL pqcrypt-worker:latest

# Secrets check
detect-secrets scan --baseline .secrets.baseline  # compare against baseline
```

## Appendix B: Dependency Update Policy

| Dependency Type | Update Frequency | Who Approves |
|---|---|---|
| Python security fixes (CVE) | Immediate | Any engineer (urgent process) |
| Python minor updates | Monthly | 1 reviewer + security sign-off |
| Python major updates | Quarterly | Full security review + integration test pass |
| Node packages (prod) | Monthly | 1 reviewer |
| Node packages (dev) | Per PR | Any engineer |
| Base Docker images | Monthly | Security engineering |
| System binaries (tshark, nmap, openssl) | Quarterly + CVE-triggered | Security engineering |

No dependency is updated silently. Every update must produce a `pip-audit` diff in the PR description showing what changed and why.

---

*End of Secure Development & Cryptographic Baseline Document*
