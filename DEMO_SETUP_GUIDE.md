# PQCrypt Sentinel — Demo Setup Guide

> **Last updated:** 2026-06-16  
> **Environment:** Windows 10/11 + Docker Desktop + Python 3.11 + Node.js 18+  
> **Status:** v0.9.0 — demo-ready for small inventories (< 50 hosts)

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker Desktop | 4.25+ | PostgreSQL 16 + Redis 7 |
| Python | 3.11.x | Backend API + Celery worker |
| Node.js | 18 LTS | Frontend dev server (Vite) |
| Windows Terminal | latest | `start.bat` uses `wt.exe` |
| Git | 2.40+ | Clone repo |

**Check versions:**
```powershell
docker --version
python --version
node --version
wt --version   # must be in PATH for start.bat
```

---

## Step 1 — Start Docker Services

Open PowerShell in the project root (`D:\Project Files\PQC_Scanner\`) and run:

```powershell
docker compose up -d postgres redis
```

Wait for both to be healthy (30–45s):
```powershell
docker compose ps
```

You should see:
```
NAME                   STATUS
pqc-scanner-postgres-1   Up 5s (healthy)
pqc-scanner-redis-1      Up 5s (healthy)
```

---

## Step 2 — Configure .env

Copy the example and edit only `SECRET_KEY`:

```powershell
copy .env.example .env
```

**Minimum changes for local demo:**
```ini
APP_ENV=development
SECRET_KEY=<generate-with-openssl-rand-hex-32>
CORS_ORIGINS=http://localhost:5173
DATABASE_URL=postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
```

Generate a secure `SECRET_KEY`:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Step 3 — Install Backend Dependencies

```powershell
cd "backend"
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Verify:
```powershell
python -m pytest tests/ --tb=line -q
```
Expected: `668 passed, 2 skipped`

---

## Step 4 — Create the First Admin User

The app has no registration endpoint; run this once in the backend directory:

```powershell
. .venv\Scripts\Activate.ps1
$env:DATABASE_URL="postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt"
python -c "
import asyncio
from app.db import AsyncSessionLocal
from app.models.models import User
from app.auth.jwt import hash_password

async def seed():
    async with AsyncSessionLocal() as session:
        u = User(
            email='admin@demo.local',
            password_hash=hash_password('DemoPass123!'),
            full_name='Demo Admin',
            role='admin',
            is_active=True,
        )
        session.add(u)
        await session.commit()
        print('Admin user created: admin@demo.local / DemoPass123!')

asyncio.run(seed())
"
```

---

## Step 5 — Launch the Application

From the **project root** (not `backend`):

```powershell
start.bat
```

Windows Terminal opens 3 tabs:
| Tab | Service | URL |
|-----|---------|-----|
| Backend API | Uvicorn | http://localhost:8000 |
| Celery Worker | Solo prefork | — |
| Frontend Dev | Vite | http://localhost:5173 |

Wait ~5s for all tabs to stabilise, then open:
```
http://localhost:5173
```

The backend OpenAPI docs are at:
```
http://localhost:8000/docs
```

---

## Step 6 — Pre-Seed Demo Data (Optional but Recommended)

For a richer dashboard, scan two small public targets before the demo. Open Swagger (`/docs`) and authenticate, or use this one-liner in PowerShell (from `backend` dir with `.venv` active):

```powershell
$env:DATABASE_URL="postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt"
python -c "
import asyncio
from app.db import AsyncSessionLocal
from app.models.models import Scan, User

async def seed():
    async with AsyncSessionLocal() as session:
        # Two safe demo targets
        targets = [
            Scan(scan_type='full', target='scanme.nmap.org', status='queued'),
            Scan(scan_type='tls_only', target='cloudflare.com', status='queued'),
        ]
        for t in targets:
            session.add(t)
        await session.commit()
        for t in targets:
            await session.refresh(t)
            print(f'Seeded scan {t.id} -> {t.target}')

asyncio.run(seed())
"
```

Then trigger the Celery tasks in Swagger:
1. POST `/api/v1/auth/login` → `admin@demo.local` / `DemoPass123!`
2. POST `/api/v1/scans` → create a new scan
3. Wait 60–90s for completion
4. Refresh the dashboard

---

## Shutdown

Close Windows Terminal (kills all 3 tabs) or run separately:
```powershell
docker compose down
```

To wipe all data and start fresh:
```powershell
docker compose down -v
docker compose up -d postgres redis
```

---

# Scanning Use Cases

## 1. TLS / HTTPS Endpoint Scan
**What it does:** Active handshake to discover certificate algorithm, key size, PQC KEX groups, TLS version.

**Demo target:** `scanme.nmap.org` or `cloudflare.com`

**Key findings produced:**
- `weak_algorithm` — RSA/SHA-1/MD5 certificates
- `weak_key_size` — RSA < 2048
- `cert_expiring` / `cert_expired`
- `pqc_not_supported` — no hybrid ML-KEM advertised
- `self_signed` certificates

**Dashboard impact:** PQC readiness score, layer L1 coverage, algorithm distribution.

**Safe for demo:** Yes — public test targets, no credentials.

---

## 2. SSH Server Scan
**What it does:** Negotiates SSH KEX to detect PQC key exchange (`sntrup761x25519`, `mlkem768x25519`).

**Demo target:** Any internal dev box with OpenSSH 9.0+, or skip if none available.

**Key findings produced:**
- `ssh_weak_kex` — no PQC KEX support
- `ssh_weak_host_key` — RSA host key < 4096

**Dashboard impact:** Layer L1 / L6 coverage.

**Safe for demo:** Only against hosts you own.

---

## 3. L1 OCSP + DNSSEC Live Probe
**What it does:** One-click probe of certificate revocation status and DNSSEC chain health.

**How to trigger:** POST `/api/v1/scans/{scan_id}/l1-probe`

**Key findings produced:**
- `cert_expired` — OCSP returns "revoked"
- `weak_algorithm` — OCSP responder uses SHA-1/MD5
- DNSSEC broken chain → `pqc_not_supported`

**Dashboard impact:** L1-specific findings, risk score recalculation.

**Safe for demo:** Yes — passive network queries only.

---

## 4. Passive SPAN / PCAP Analysis *(requires tshark)*
**What it does:** Captures live TLS handshakes from a network interface and reports advertised PQC groups.

**How to trigger:** Not exposed in UI yet; backend-only via scanner module.

**Key findings produced:**
- Real-time PQC adoption stats
- Classical vs hybrid negotiation ratios

**Safe for demo:** Only on networks you own and have Wireshark installed.

---

## 5. Certificate Store / PKI Audit
**What it does:** Parses X.509 PEM/DER, detects RSA-3072→2030 deadline, classifies `ML-DSA-65` vs `RSA-2048`.

**Demo target:** Upload a PEM bundle or target a CA endpoint.

**Key findings produced:**
- `weak_algorithm` — pre-quantum sig algos
- `cert_expiring` — < 30 days to expiry
- CBOM export with `nistQuantumSecurityLevel` + `pqcSafe`

**Dashboard impact:** Layer L2 coverage, migration timeline.

---

## 6. Report Generation
**What it does:** Produces CycloneDX CBOM v1.7, PDF executive summary, CSV findings export.

**Supported formats:**
| Report Type | Format | Use Case |
|-------------|--------|----------|
| CBOM | JSON | Import into CISA/E8 compliance tools |
| Executive | PDF | CIO / board-level readiness briefing |
| Findings | CSV | Spreadsheet analysis, Jira bulk import |
| SAST | SARIF | CI/CD artifact ingestion |

**How to trigger:** POST `/api/v1/reports` → poll GET `/api/v1/reports/{id}` until `status=ready` → download.

**Safe for demo:** Yes — reads already-discovered data only.

---

# Recommended Demo Script (5 min)

1. **Login** → show the dashboard with summary cards (PQC readiness, open findings).
2. **Create Scan** → `scanme.nmap.org` (TLS) → status goes `queued` → `running` → `completed`.
3. **Refresh Dashboard** → watch the layer-coverage heatmap and risk-distribution chart populate.
4. **View Findings** → click into the scan, show severity badges, risk scores, and Mosca timeline.
5. **Generate Report** → start a CBOM request, show the async status, then download JSON.
6. **Layer-Coverage Drill-down** → toggle L1 vs L2, explain 7-layer model.

---

# Troubleshooting

| Symptom | Fix |
|---------|-----|
| `column findings.layer does not exist` | Restart backend — `_sync_missing_columns` adds it on startup (v0.9.0+) |
| `401 Unauthorized` on dashboard | Login via `/login` first; tokens expire in 60 min |
| `RuntimeError: tshark not found` | Install Wireshark or ignore — passive scan is optional |
| `500` on asset list with `TypeError` | Check PostgreSQL is running: `docker compose ps` |
| Frontend blank page | Ensure `CORS_ORIGINS` includes `http://localhost:5173` |
| Rate-limit `429` | Default is 10 RPS; wait 1s between rapid clicks |
