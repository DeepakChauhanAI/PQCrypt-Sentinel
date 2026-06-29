# Security & Access Document

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Security Engineering  
**Status:** Draft

**Audience:** Developers, security reviewers, DevOps, customers running security audits.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Authentication Methods](#2-authentication-methods)
3. [User Roles & Permissions](#3-user-roles--permissions)
4. [Scanner Credential Tier Model](#4-scanner-credential-tier-model)
5. [Row-Level Security](#5-row-level-security)
6. [Error Handling](#6-error-handling)
7. [Edge Cases](#7-edge-cases)
8. [Credential Security](#8-credential-security)
9. [Audit Logging](#9-audit-logging)
10. [Network Isolation](#10-network-isolation)

---

## 1. Overview

This document defines every security-relevant decision in PQCrypt Sentinel: who can log in, what they can do, how scanner credentials are managed, what happens when things break, and how the system defends itself against misuse.

PQCrypt Sentinel is a **security product** — it holds the cryptographic map of an enterprise. Its own security posture must be defensible to a customer's security team before they will deploy it. Every decision here is written to pass a third-party security audit.

**Core security principles:**
- **Least privilege always:** Users and workers get the minimum access required — no more.
- **Credentials never touch the database:** Scanner credentials, connector passwords, and API keys are referenced by vault path only, never stored as plaintext or reversible ciphertext in PostgreSQL.
- **Append-only evidence:** Scan results are immutable. A third party can verify the audit trail has not been tampered with.
- **Defense in depth:** Authentication → Authorization → Input validation → Output sanitization → Network isolation — each layer catches what the previous one missed.
- **Fail closed:** When in doubt, deny access. A misconfigured permission should hide data, not expose it.

---

## 2. Authentication Methods

Three methods are supported across the product lifetime. MVP ships with Method 1 and 3. Method 2 is Phase 2.

---

### 2.1 Local Username/Password (MVP)

**When used:** Single-tenant deployments with strict data-residency requirements (financial services, government, healthcare, critical infrastructure sectors operating on-prem or in private VPCs).

**How it works:**
1. User submits email + password to `POST /api/v1/auth/login`.
2. Backend looks up user by email, verifies password using bcrypt with cost factor 12.
3. On success: generates two JWTs — an **access token** (1 hour, HS256) and a **refresh token** (7 days, stored in httpOnly secure cookie, not localStorage).
4. Access token payload contains: `sub` (user UUID), `role` (admin/analyst/viewer), `exp` (expiry timestamp).
5. Every subsequent request sends `Authorization: Bearer <access_token>` header.
6. When the access token expires, the frontend calls `POST /api/v1/auth/refresh` with the httpOnly cookie to get a new access token.
7. On logout (`POST /api/v1/auth/logout`): the refresh token is invalidated server-side (stored hash added to a blocklist table) and the cookie is cleared.

**Plain-English walkthrough:**
> Think of the access token as a 1-hour building badge. The refresh token is the front desk number you call to get a new badge when yours expires. When you leave the building (logout), the front desk marks your badge number as revoked so no one else can use it.

**Why bcrypt, not Argon2?**
bcrypt is time-tested (since 1999), requires no external C library, and is auditable. Argon2 requires libsodium and is harder to get right. For a system where the threat model is internal misuse (a frustrated analyst) rather than nation-state attacks against the auth system itself, bcrypt at cost factor 12 is sufficient. Upgrade to Argon2 in Phase 2 if customers demand it.

**Why JWT and not sessions?**
JWT is stateless — no server-side session store needed. This simplifies the Docker Compose deploy. The refresh token server-side blocklist is the only stateful component, and it's small (only revoked tokens, which are rare).

**Why httpOnly cookies for refresh tokens, not localStorage?**
localStorage is accessible to JavaScript — if the app has an XSS vulnerability, an attacker can steal tokens from localStorage. httpOnly cookies cannot be read by JavaScript. The SameSite=Strict flag on the refresh cookie prevents CSRF. This is the current OWASP recommendation for token storage.

---

### 2.2 SSO via OIDC / SAML (Phase 2)

**When used:** Enterprise customers running Okta, Entra ID, Keycloak, or ADFS. These customers want to use their existing identity provider rather than maintaining a separate password database.

**How it works:**
1. User clicks "Login with Okta" (or configured IdP).
2. Frontend redirects to IdP's authorization endpoint.
3. User authenticates with their corporate credentials (possibly with MFA).
4. IdP returns an authorization code to the app's callback URL.
5. Backend exchanges the code for an ID token and access token.
6. Backend creates or updates the local user record (matched by email from the IdP token claim).
7. Backend issues its own access + refresh JWTs (same as Method 1).

**What is NOT handled:**
- SAML SSO for the frontend (this is a backend OIDC flow — the browser never sees SAML XML).
- Fine-grained IdP group-to-role mapping in Phase 1 — all SSO users default to "analyst" role. Admin promotion is manual in settings.

---

### 2.3 API Keys (MVP)

**When used:** CI/CD pipelines, automation scripts, external tool integration. A user generates an API key from the settings page and uses it as a `Authorization: Bearer <key>` header.

**How it works:**
1. Admin or analyst goes to Settings → API Keys → "Generate New Key".
2. Frontend calls `POST /api/v1/api-keys`. Backend generates a random 32-byte key, hashes it with bcrypt, stores only the hash.
3. The full key is shown to the user **once** — it must be copied immediately. It cannot be retrieved later.
4. Scopes are assigned at creation: `scans:read`, `scans:write`, `assets:read`, `findings:read`, `reports:read`, etc.
5. API key auth is checked on every endpoint using a FastAPI dependency: the incoming key's hash is looked up in the `api_keys` table, then the key hash is compared using bcrypt.
6. `last_used_at` is updated on every call (for audit trail).

**Plain-English:**
> An API key is like a hotel room key card. The person at the desk creates it, hands it to you once, and cannot make another copy. The card only opens the doors you were given access to. Every time you use it, the front desk marks the time.

---

### 2.4 Authentication Summary

| Method | Phase | Use Case | Token Lifetime |
|---|---|---|---|
| Local password + JWT | MVP | Default, single-tenant | Access: 1h, Refresh: 7d |
| OIDC SSO | Phase 2 | Enterprise, corporate IdP | Same JWT tokens internally |
| API key | MVP | CI/CD, automation | No expiry (manual rotation) |

**Unauthenticated endpoints** (require no token):
- `GET /health` — liveness probe for load balancers
- `POST /api/v1/auth/login` — login endpoint
- `POST /api/v1/auth/refresh` — token refresh (requires valid httpOnly cookie)
- `GET /api/v1/auth/docs` — OpenAPI documentation
- `GET /api/v1/auth/openapi.json` — OpenAPI spec

**Every other endpoint requires authentication.** The FastAPI app uses a single `get_current_user` dependency applied globally via `app.dependencies`.

---

## 3. User Roles & Permissions

### 3.1 The Five Product Roles (From PRD)

The PRD defines five user personas. These are *product roles* (what the person does in the real world), not *system roles* (what the system lets them click). System roles are coarser — they map many product roles to a single permission set.

| Product Persona | System Role | Why |
|---|---|---|
| CISO / Security Director | **Admin** or **Viewer** | Needs executive dashboards and report access. Usually not running scans directly. |
| Security Architect | **Admin** | Full control — they set up connectors, define scan strategy, configure settings. |
| IT Security Analyst | **Analyst** | The primary day-to-day user — runs scans, triages findings, updates status, creates tickets. |
| Compliance Officer | **Viewer** | Read-only access to reports, dashboards. Cannot accidentally change findings or cancel scans. |
| DevOps / Platform Engineer | **Analyst** | Runs SBOM/k8s/cloud scans. Same permissions as analyst for the scanner features they use. |

**Recommendation:** Use system roles for authorization. Add a `title` / `team` field on the `users` table to capture the product persona for display purposes ("CISO", "Security Architect") without affecting permissions.

---

### 3.2 The Four System RBAC Roles

These are the roles in the database `users.role` column and enforced on every API endpoint.

#### ADMIN — "The Keys to the Kingdom"

| Capability | Allowed |
|---|---|
| View all dashboards | ✅ |
| Run/create scans | ✅ |
| View all assets and findings | ✅ |
| Edit/delete assets (manual override) | ✅ |
| Assign/reassign findings | ✅ |
| Change finding status (resolve, accept) | ✅ |
| Manage connectors (create, edit, delete, test) | ✅ |
| Manage users (create, edit role, disable) | ✅ |
| Manage API keys (any user's keys) | ✅ |
| Manage platform settings | ✅ |
| View audit log | ✅ |
| Delete scan evidence | ✅ |

**Who gets this role:** Security Architect, the person who deployed the platform. Maximum 2-3 people per deployment.

---

#### ANALYST — "The Operator"

| Capability | Allowed |
|---|---|
| View all dashboards | ✅ |
| Run/create scans | ✅ |
| View all assets and findings | ✅ |
| Edit own-created assets | ✅ (own assets only) |
| View all findings | ✅ |
| Update finding status (open → in_progress → resolved) | ✅ |
| Assign findings to others | ✅ |
| Create reports | ✅ |
| Manage own API keys | ✅ |
| Test connectors | ✅ (read + test, cannot create/delete) |
| Manage own profile | ✅ |
| View others' API keys | ❌ |
| Delete scan evidence | ❌ |
| Manage users | ❌ |
| Manage platform settings | ❌ |
| Delete connectors | ❌ |

**Who gets this role:** IT Security Analysts, DevOps Engineers. The bulk of users.

---

#### VIEWER — "The Consumer"

| Capability | Allowed |
|---|---|
| View executive dashboard | ✅ |
| View operational dashboard | ✅ |
| View assets (read-only) | ✅ |
| View findings (read-only) | ✅ |
| View reports | ✅ (can download, cannot create) |
| View migration progress | ✅ |
| View connector status (name + last_sync_at only) | ✅ |
| Run scans | ❌ |
| Update finding status | ❌ |
| Create reports | ❌ |
| View raw scan output / evidence JSON | ❌ |
| Manage connectors | ❌ |
| Manage users | ❌ |
| Manage settings | ❌ |

**Who gets this role:** CISOs (who just want the summary), Compliance Officers (who need report access for auditors), executives who want to see the dashboard without the risk of accidental changes.

---

#### API — "The Machine"

| Capability | Allowed |
|---|---|
| What it can do | **Exactly what its scopes allow** |
| Scope examples | `scans:read`, `scans:write`, `assets:read`, `findings:read`, `reports:read` |
| Scope enforcement | Checked per-endpoint via FastAPI dependency |
| Login to web UI | ❌ |
| View dashboards | ❌ |

**Who uses this:** CI/CD pipelines calling the API to trigger scans. External SIEM/ticketing systems pulling findings. The `api` role in the users table is a placeholder — real authorization is determined by the API key's `scopes` array.

---

### 3.3 Permission Matrix (Complete)

| Resource / Action | Admin | Analyst | Viewer | API |
|---|---|---|---|---|
| **Dashboard — Executive** | read | read | read | — |
| **Dashboard — Operational** | read | read | read | — |
| **Assets** | CRUD | read + update own | read | scoped read |
| **Findings** | CRUD | read + status update | read | scoped read |
| **Scans** | CRUD + cancel | create + read + cancel | read | scoped read/write |
| **Scan logs** | read | read | ❌ | ❌ |
| **Reports** | CRUD | create + read | read (download only) | scoped read |
| **Connectors** | CRUD | read + test | read (name/status only) | ❌ |
| **CMDB/cloud credentials** | read config | ❌ | ❌ | ❌ |
| **VAULT references** | read path | ❌ | ❌ | ❌ |
| **Settings** | CRUD | read | read | — |
| **Users** | CRUD | read own | read own (name/role only) | — |
| **API Keys — own** | CRUD | CRUD | ❌ | — |
| **API Keys — others** | CRUD | ❌ | ❌ | — |
| **Audit log** | read | ❌ | ❌ | ❌ |

---

### 3.4 Permission Enforcement (Technical)

Every API endpoint declares its required role or scope using FastAPI dependencies:

```python
# In dependencies.py
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    payload = jwt.decode(token, SECRET_KEY)
    user = await db.get_user(payload["sub"])
    if not user or user.deleted_at:
        raise HTTPException(401, "Invalid or expired token")
    return user

async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return current_user

async def require_analyst_or_above(current_user: User = Depends(get_current_user)):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(403, "Analyst access required")
    return current_user

# Applied to routes
@router.post("/scans", dependencies=[Depends(require_analyst_or_above)])
async def create_scan(...): ...

@router.delete("/scans/{scan_id}", dependencies=[Depends(require_admin)])
async def delete_scan(...): ...
```

API key scopes use a similar pattern:

```python
async def require_scope(required_scope: str):
    async def checker(api_key: ApiKey = Depends(get_api_key)):
        if required_scope not in api_key.scopes:
            raise HTTPException(403, f"Missing scope: {required_scope}")
        return api_key
    return checker

# Applied to routes
@router.get("/scans", dependencies=[Depends(require_scope("scans:read"))])
async def list_scans(...): ...
```

**Plain-English:**
> Each API endpoint has a bouncer. The bouncer checks your wristband (your role). If your wristband says "viewer" and the room requires "analyst", the bouncer stops you at the door with a 403 error. The same logic applies to API keys — each key has a list of rooms (scopes) it's allowed in.

---

## 4. Scanner Credential Tier Model

This is the most security-critical design in the entire product. The scanner needs to access many different systems to do its job — but each system requires a different level of access. The tier model ensures that the scanner never uses a high-privilege credential for a low-privilege operation.

### The Four Tiers

#### Tier 0 — Unauthenticated (No Credentials Required)

**What it is:** Operations that work without any login or access control. These are public-information lookups.

| Operation | Examples | Risk if Misused |
|---|---|---|
| TLS handshake probing | Scanning api.example.com:443 | Very low — same as any port scan |
| CT log polling | Querying crt.sh for public certificates | None — CT logs are public by design |
| DNS enumeration | Looking up A/AAAA/CNAME records | Low — standard DNS |
| Shodan/Censys queries | (Phase 2) Reconnaissance | Low — public data |

**Credentials needed:** None.

**Plain-English:** This is like walking around a public building and noting which doors have locks. You don't need a key to see the doors.

---

#### Tier 1 — Read-Only Service Account

**What it is:** Operations requiring a low-privilege, read-only account. The account can see data but cannot change anything. If this credential is compromised, the attacker can read but not modify.

| Operation | Examples | Required Credential |
|---|---|---|
| SSH audit | Connecting to a server's SSH banner | SSH user account with no shell (`/bin/false`) |
| CMDB query | Pulling CI data from ServiceNow | ServiceNow read-only API account |
| NetBox query | Pulling device inventory | NetBox API token with read scope |
| AD CS query | Enumerate issued certificates | AD service account with read access to CA |
| Vault PKI query | List issued certs from Vault PKI | Vault token with `cert:list` capability only |
| GitHub/GitLab API | Read repo contents for SBOM/crypto audit | PAT with `contents:read` scope only |

**Credential requirements:**
- Must be a dedicated service account — not a personal user account.
- Must be read-only in the target system.
- Must have no write/delete/execute permissions in the target system.
- Vault path stored in `connectors.credentials_ref`, never the actual credential.

**Plain-English:** This is like having a library card — you can read books but you can't rewrite them. If someone steals your library card, they can read, but they can't burn the library down.

---

#### Tier 2 — Local Admin / Root on Target

**What it is:** Operations requiring administrative access to the machine being scanned. This is needed for deep host-level inspection.

| Operation | Examples | Required Credential |
|---|---|---|
| TPM enumeration | Query TPM 2.0 for key attestation | Local admin (Windows) or root (Linux) |
| Secure Boot audit | Read UEFI firmware config | Root / SYSTEM account |
| Local cert store audit | enumerate /etc/ssl/certs or Windows cert store | Admin |
| AD audit | Enumerate domain controllers, Kerberos settings | Domain admin or equivalent delegated account |
| Remote execution agent | WinRM / SSH with command execution | Admin account |

**Credential requirements:**
- Must be scoped to the minimum required. If you only need to read the registry key for Secure Boot settings, do not grant full domain admin.
- Must be documented per connector: which operations require Tier 2, which don't.
- In Phase 3, use a dedicated endpoint agent (running as a service account, not full root) instead of remote admin credentials.

**Plain-English:** This is the master key to one specific room. You need it to open the safe inside the room, but you shouldn't be able to open the building's front door with it.

---

#### Tier 3 — Hardware / Out-of-Band Access

**What it is:** Operations requiring physical or near-physical access to hardware security devices. These are the highest-risk credentials in the platform.

| Operation | Examples | Required Credential |
|---|---|---|
| HSM PKCS#11 enumeration | Query Thales Luna key hierarchy | HSM auditor partition PIN / SO login |
| Smart card enumeration | Read PIV/cardholder certificates | Physical card + PIN |
| KMS hardware access | AWS CloudHSM crypto user login | HSM crypto user credentials |

**Credential requirements:**
- Stored exclusively in customer-managed vault (BYO), not in the scanner's vault.
- Never transmitted over the network — HSM operations require physical or VPN access.
- Must be used in a session that is logged and time-limited.
- The scanner must document which operations require Tier 3 and warn the operator before running them.

**Plain-English:** This is the key to a secure vault. It requires two people to authorize, it's logged every time it's used, and it's never stored in the same facility as the scanner.

---

#### Tier 4 — Cloud Control Plane

**What it is:** Operations using cloud provider APIs that have broad account-level access. A compromised Tier 4 credential could expose entire cloud environments.

| Operation | Examples | Required Credential |
|---|---|---|
| AWS Config / KMS / ACM inventory | List all KMS keys, ACM certs across regions | AWS IAM role with read-only permissions |
| Azure Resource Graph query | List all Azure Key Vault keys | Azure service principal with Reader role |
| GCP Asset Inventory / KMS | List all GCP KMS keys | GCP service account with `roles/cloudkms.viewer` |
| AWS S3 bucket enumeration | List buckets and encryption config | IAM role with `s3:ListAllMyBuckets`, `s3:GetBucketEncryption` |

**Credential requirements:**
- IAM role must be scoped to read-only for the specific services needed. No wildcard permissions (`*`).
- Must have no access to change/delete resources.
- Must be time-limited where possible (AWS IAM session tokens with expiry).
- Regular audit: every 90 days, verify the cloud IAM policy has not been broadened by customer changes.

---

### 4.1 Tier Enforcement in the Scanner

Every scanner worker declares its required tier. Before executing, the worker verifies that a credential of the appropriate tier is configured:

```python
class BaseScanner(ABC):
    @property
    @abstractmethod
    def access_tier(self) -> int:
        """Minimum tier required to run this scanner. 0-4."""
        ...

    @abstractmethod
    async def scan(self, target: str, credentials: CredentialSet) -> ScanResult:
        ...

class TLSScanner(BaseScanner):
    @property
    def access_tier(self) -> int:
        return 0  # No credentials needed

class CMDBConnector(BaseScanner):
    @property
    def access_tier(self) -> int:
        return 1  # Requires Tier 1 (read-only service account)

class HSMScanner(BaseScanner):
    @property
    def access_tier(self) -> int:
        return 3  # Requires Tier 3 (HSM hardware access)
```

The `scan_orchestrator` service checks the tier before dispatch:

```python
async def execute_scan(scan_id: UUID, connector: Connector):
    scanner = scanner_registry.get(scan.scan_type)
    required_tier = scanner.access_tier
    available_tier = connector.get_credential_tier()

    if available_tier < required_tier:
        raise InsufficientCredentialTier(
            f"This scan requires Tier {required_tier} credentials. "
            f"Configured connector has Tier {available_tier}."
        )
    # ... proceed with scan
```

**This prevents the critical mistake of using a Tier 1 CMDB service account to try a Tier 3 HSM scan, which would fail and potentially lock out the HSM after repeated failed PIN attempts.**

---

### 4.2 Tier Summary

| Tier | Name | Risk if Compromised | Scanners Using It |
|---|---|---|---|
| 0 | Unauthenticated | Very low | TLS active probe, CT log monitor, DNS enum |
| 1 | Read-only service | Low (read only) | CMDB query, CA query, Vault PKI, code repo |
| 2 | Local admin | Medium (can change config, read secrets) | TPM, Secure Boot, AD audit, endpoint agent |
| 3 | HSM hardware | Very high (can extract or lock keys) | HSM PKCS#11, smart card, KMS hardware |
| 4 | Cloud control plane | Very high (full account access potential) | AWS Config/KMS, Azure RG/KeyVault, GCP KMS |

---

## 5. Row-Level Security

### 5.1 Multi-Tenancy: Phase 1 is Single-Tenant

In MVP and Phase 2, PQCrypt Sentinel is a single-tenant application. One deployment = one customer. All data in the database belongs to that customer. There is no `tenant_id` column in MVP because there is no multi-tenancy.

**Implication for queries:** In MVP, there are no tenant filters. Every query is `SELECT * FROM findings WHERE deleted_at IS NULL`. Multi-tenant row filtering (adding `WHERE tenant_id = X`) is a Phase 4 change.

---

### 5.2 Ownership Rules (Single-Tenant MVP)

Even within a single tenant, not every user should see everything. These are the ownership boundaries:

| Data | Who Can See It | Rationale |
|---|---|---|
| **Dashboard data** | All authenticated users | Summary stats are not sensitive |
| **Scan results (raw)** | Admin + Analyst | Raw tool output may contain internal hostnames, IPs |
| **Connector credentials** | Admin only | Passwords/API keys in vault references |
| **API keys (other users')** | Admin only | Key material is sensitive |
| **User passwords** | Nobody | Stored as bcrypt hash, not even admins can read |
| **Audit log / credential access logs** | Admin only | Shows who accessed what |
| **Reports generated by others** | All authenticated users | Reports are shared outputs |
| **Personal settings** | The user themselves + Admin | User can edit their own profile |

**Implementation:**

```python
# Ownership check on findings update
async def update_finding(
    finding_id: UUID,
    update: FindingUpdate,
    current_user: User = Depends(get_current_user)
):
    finding = await db.get_finding(finding_id)

    # Viewer role: cannot modify at all
    if current_user.role == "viewer":
        raise HTTPException(403, "Viewers cannot modify findings")

    # Analyst: can update findings they created or that are unassigned
    if current_user.role == "analyst":
        if finding.assigned_to and finding.assigned_to != current_user.id:
            raise HTTPException(403, "You can only update findings assigned to you")
        if finding.assigned_to is None and finding.created_by != current_user.id:
            raise HTTPException(403, "You can only update findings you created")

    # Admin: can update anything
    # Proceed with update...
```

---

### 5.3 Asset Ownership Propagation

Assets are discovered by scans (system-generated) and enriched by connectors (CMDB sync). The `owner_id` is set during discovery:

1. **TLS/SSH scan discovery:** Asset is created without an owner (or with a default "scanner" system user).
2. **CMDB sync:** Connector enriches the asset with owner from CMDB. `owner_id` is set to the CMDB CI owner mapped to a local user or left as the system user if no match.
3. **Manual assignment:** An analyst can assign owner via the Asset Detail page.
4. **Ownership does not cascade automatically:** If an asset is reassigned to a new owner, existing findings are not reassigned. The analyst must explicitly reassign findings.

---

## 6. Error Handling

Every major failure point is defined below. The guiding principle: **never show a raw Python exception to the user.** Always return a structured, actionable error response.

### 6.1 Common Error Response Shape

```json
{
  "error": {
    "code": "SCAN_TARGET_UNREACHABLE",
    "message": "Could not connect to 10.0.0.1:443 within 10 seconds.",
    "detail": "Connection timed out after 10s. Check network connectivity and firewall rules.",
    "field": null,
    "timestamp": "2026-06-03T09:15:30Z",
    "request_id": "abc-123-def"
  }
}
```

Fields:
- `code`: Machine-readable error code (used by frontend for localization and icon selection).
- `message`: Short human-readable sentence.
- `detail`: Longer explanation or remediation hint.
- `field`: Which form field the error applies to (null for non-form errors).
- `request_id`: Correlates with backend log entry for support.
- `timestamp`: UTC ISO-8601.

---

### 6.2 Authentication Errors

| Scenario | HTTP Status | Error Code | User Sees |
|---|---|---|---|
| Wrong password | 401 | `AUTH_INVALID_CREDENTIALS` | "Invalid email or password. Please try again." |
| Account disabled | 401 | `AUTH_ACCOUNT_DISABLED` | "Your account has been disabled. Contact your administrator." |
| Token expired (access) | 401 | `AUTH_TOKEN_EXPIRED` | *(Transparent — frontend silently refreshes token)* |
| Token expired (refresh) | 401 | `AUTH_REFRESH_EXPIRED` | "Your session has expired. Please log in again." Redirects to `/login`. |
| Missing token | 401 | `AUTH_TOKEN_MISSING` | *(Redirected to login, not shown to user)* |
| Insufficient role | 403 | `AUTH_INSUFFICIENT_ROLE` | "You don't have permission to perform this action." |

---

### 6.3 Scan Errors

| Scenario | HTTP Status | Error Code | Behavior |
|---|---|---|---|
| Target unreachable (timeout) | 422 | `SCAN_TARGET_UNREACHABLE` | Scan status = `failed`. Error recorded in `scans.error_message`. Finding NOT created. UI shows "Failed" badge with detail. |
| Target refused TLS connection | 422 | `SCAN_TARGET_NO_TLS` | Scan continues for other targets. Target marked as "no TLS" in results. Dashboard shows partial results. |
| Worker crashed (unhandled exception) | 500 | `SCAN_WORKER_ERROR` | Scan status = `failed`. Error logged. Admin notified via webhook. User sees "Scan failed — contact administrator" with request_id. Raw traceback NOT shown to user, stored in `scan_logs` for admin. |
| Celery broker unavailable | 503 | `SCAN_QUEUE_UNAVAILABLE` | API returns 503 immediately. "Scanner service temporarily unavailable. Please try again in a few minutes." |
| Scan cancelled by user | 200 | `SCAN_CANCELLED` | Scan status = `cancelled`. Partial results preserved. UI shows "Cancelled" badge. |
| Tool subprocess failed (pqcscan not found) | 500 | `SCAN_TOOL_MISSING` | Scan fails immediately. Admin alert. "Scanner configuration error — contact administrator." |

---

### 6.4 Connector Errors

| Scenario | HTTP Status | Error Code | Behavior |
|---|---|---|---|
| CMDB unreachable (timeout) | 422 | `CONNECTOR_TIMEOUT` | Connector status = `error`. `last_error` populated with timeout detail. UI shows yellow warning icon. "ServiceNow connection failed: timeout after 30s." Admin can "Retry" without re-entering credentials. |
| Invalid credentials | 422 | `CONNECTOR_AUTH_FAILED` | Connector status = `error`. `last_error` = "Authentication failed: 401 from ServiceNow". UI prompts: "Check configured credentials. Verify the service account is not locked." |
| Schema mismatch (CMDB field missing) | 500 | `CONNECTOR_SCHEMA_ERROR` | Partial sync: whatever could be parsed is saved. Error logged. Admin notification. |
| Cloud API rate limited (429) | 429 | `CONNECTOR_RATE_LIMITED` | Exponential backoff retry (max 3 retries). If exhausted, error. Admin notification. |
| Network isolated (VPN required) | 422 | `CONNECTOR_NETWORK_ERROR` | "Cannot reach ServiceNow. Ensure the scanner has network access to the CMDB endpoint." |

---

### 6.5 Input Validation Errors

All API inputs use Pydantic v2 schemas. Validation errors return 422 with a structured list:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid scan target format.",
    "detail": {
      "field_errors": [
        {"field": "target", "error": "Invalid CIDR notation: 10.0.0.1/33"},
        {"field": "ports", "error": "Port number 0 is out of range 1-65535"}
      ]
    }
  }
}
```

Validation rules for key inputs:
- **Scan target:** Must be valid CIDR (10.0.0.0/24), single IP address, or resolvable FQDN. Rejected outright if obviously wrong.
- **Port:** Integer 1-65535.
- **Cron expression:** Must pass `croniter` validation before storage in `connectors.sync_schedule`.
- **Email:** RFC 5322 compliant. Checked at registration and update.
- **File uploads (SBOM, PCAP):** Max 500MB. Content-type checked (application/json for SBOM, application/octet-stream or vendor/pcap for PCAP). Files parsed in isolated subprocess with memory limits.

---

### 6.6 Database Errors

| Scenario | HTTP Status | Behavior |
|---|---|---|
| Connection pool exhausted | 503 | "Database temporarily unavailable. Please retry." Frontend retries with exponential backoff. |
| Unique constraint violation (duplicate cert thumbprint) | 409 | Silently handled — scanner deduplicates by thumbprint. No error returned to user. New scan uses existing cert record. |
| Foreign key violation (invalid asset_id in finding) | 500 | Logged as bug. Returns 500 with generic message. Technical team notified. |
| Migration pending (old schema) | 500 on startup | API refuses to start. Logs "Alembic migration not up to date. Run `alembic upgrade head`." Startup script blocks. |

---

## 7. Edge Cases

### 7.1 Authentication Edge Cases

| Edge Case | Handling |
|---|---|
| **User logs in from two browsers simultaneously** | Both get valid JWTs. Refresh token blocklist is checked per-refresh, so both sessions work independently. User can log out one session without killing the other. Admin sees both sessions' `last_used_at` timestamps. |
| **User password reset while logged in** | Existing JWT remains valid until it expires (1 hour). After expiry, refresh also fails — must re-login with new password. No interrupt to active scans. |
| **Admin deletes themselves** | Blocked in API. `DELETE /api/v1/users/{id}` returns 422 if `id == current_user.id`. "You cannot delete your own account. Ask another admin." |
| **All admins deleted** | Safety mechanism: the first user created is always an admin. If all admins are deleted, the API starts in "bootstrap mode": any login at `localhost` (loopback) receives admin role. Logs critical warning. |
| **Concurrent scan cancellation** | If two users click "Cancel" simultaneously, both requests succeed. The Celery task is revoked once. Second cancel finds the task already revoked — no error. |
| **Scan run by user who is deleted mid-scan** | Scan continues to completion. `created_by` remains the original user ID. Auditable. |

---

### 7.2 Scanner Edge Cases

| Edge Case | Handling |
|---|---|
| **TLS endpoint presents a self-signed cert** | Certificate is captured and stored. `is_self_signed=true`. Finding created: "Self-signed certificate" (severity: medium). Scan continues. |
| **Certificate chain has 5+ intermediates** | All certs in chain are parsed. `chain_position` set for each. Finding created if chain exceeds 3 intermediates (severity: low). |
| **Server presents different certs on TCP vs TLS** | TLS scanner captures the negotiated cert. If SSL handshake fails (no response), records "no response" rather than erroring. |
| **Asset appears in two connectors (CMDB + cloud API)** | Deduplication by `(ip_address, port)` + `(fqdn, port)`. The `discovery_source` field records both. The asset is merged: the more detailed metadata wins. `first_discovered_at` records the earlier timestamp. |
| **Same cert seen on 100 different assets (load balancer sharing)** | Deduplication by `thumbprint`: only one row in `certificates` table. Each asset references the same cert via `asset_id`. |
| **Scan target is a DNS name that resolves to multiple IPs (round-robin)** | nmap resolves the DNS, finds N IPs, scans each individually. Results show all IPs. Asset record uses the FQDN, not the IP, as primary name. |
| **SPAN port has 100K packets per second** | pyshark processes in batches of 1000 packets with a 1-second window. Batch results written to `scan_logs` periodically. UI shows progress every 5 seconds. If buffer fills, oldest packets are dropped with a log entry. |
| **pyshark/tshark crashes during capture** | Worker catches the exception, writes error to `scan_logs`, sets scan status to `failed` with a partial results snapshot. Scanner process is restarted cleanly on next task. |
| **PQC OID not in vendor database** | Falls through to `pqc_status = "unknown"` rather than incorrectly classifying as vulnerable. Finding created with severity "info" — "Unknown algorithm — manual review required." A notification is sent to the admin to add the OID to the vendor database. |
| **SSH server sends KEX_INIT with 0 algorithms** | Handled as error state. Finding: "SSH server responded with empty KEX list — possible honeypot or misconfiguration." Severity: high. |
| **CT log query returns 50,000 certificates** | Paginated processing (500 per request). Batch insert into `certificates` table. UI shows "Importing 50,000 certificates from CT log..." with progress bar. |
| **Scan runs while CMDB sync is happening on same asset** | Both write to the same `assets` row using `last_scan_id` pointer. The later timestamp wins on `updated_at`. No write conflict — the ORM handles this at the row level. Concurrent writes to the same row during a scan are rare and acceptable (eventual consistency). |

---

### 7.3 Data Edge Cases

| Edge Case | Handling |
|---|---|
| **Asset is deleted, but findings still reference it** | `asset.deleted_at` is set. `asset_id` FK is not deleted. Queries on `findings` include `WHERE assets.deleted_at IS NULL` via a join filter. Old findings remain auditable. |
| **Certificate expires during a running scan** | `not_after` is checked after parsing. Expired cert is still stored. Finding created: "Certificate expired" (severity: high). Subsequent scans continue to show the expired cert until it's replaced. |
| **User generates an API key and immediately loses it** | API key cannot be retrieved after creation. User must generate a new one and revoke the old one. One-entry-only: `POST /api/v1/api-keys` returns the full key in the response body. Subsequent `GET` returns only the key hash prefix (first 8 chars) for identification. |
| **Migration score is NaN (asset has 0 algorithms)** | `readiness_score` set to `NULL` rather than NaN. Frontend displays "N/A" for assets with no algorithm data. |
| **Report generation fails halfway (disk full)** | `reports.status` set to `failed`. `error_message` populated. Partial file is deleted. User can retry. |

---

## 8. Credential Security

This is the most security-critical chapter. If PQCrypt Sentinel itself has weak credential security, customers will not deploy it.

### 8.1 What Is Never Stored in the Database

| Credential Type | Stored In | Stored As |
|---|---|---|
| User passwords | `users.password_hash` | bcrypt hash, never reversible |
| User refresh tokens | `sessions.token_hash` | bcrypt hash (blocklist on logout) |
| API keys | `api_keys.key_hash` | bcrypt hash, never reversible |
| Connector credentials | **Not in database** | Vault reference only (`credentials_ref` = vault path string) |
| CMDB passwords | **Not in database** | Vault secret at `secret/pqc/connectors/{id}` |
| Cloud IAM keys | **Not in database** | Vault secret or environment variable picked up at runtime |

**The `credentials_ref` field pattern:**
```python
# In the connectors table
credentials_ref = "vault:secret/pqc/connectors/servicenow-sbi"  # A path, not a password

# At runtime, when a scan needs credentials:
async def get_connector_credentials(connector_id: UUID) -> dict:
    connector = await db.get_connector(connector_id)
    # Fetch from vault at runtime, never from database
    credentials = await vault.read(connector.credentials_ref)
    return credentials
    # credentials object is NOT written to logs or evidence store
```

### 8.2 Credential Lifecycle

```
Creation:  Admin configures connector → enters credential → stored in Vault only
                                                                     ↓
In use:    Scanner worker fetches credential from Vault at job start
           → used for scan → discarded from memory after use
           → written to NO logs, NO evidence store, NO database
                                                                     ↓
Rotation:  Admin updates credential in Vault → new scan picks up new credential
           → `connector.last_sync_at` updated to reflect new credential test
                                                                     ↓
Revocation: Admin deletes connector → Vault secret deleted → credential_ref set to NULL
```

### 8.3 Secrets in Environment Variables (MVP)

In Phase 1 (MVP), before HashiCorp Vault is integrated, credentials are stored in environment variables or an encrypted `.env` file:
- `.env` is in `.gitignore` and never committed.
- For air-gapped deployments: `.env` is distributed on an encrypted USB or via a secure channel.
- `SECRET_KEY` must be 32+ random bytes: generate with `openssl rand -hex 32`.

**Phase 2 upgrade to Vault:** Connector credentials are migrated to Vault paths. The transition is transparent — `credentials_ref` changes from `env:SMTP_PASSWORD` to `vault:secret/pqc/connectors/servicenow-1`.

### 8.4 Scan Output Sanitization

Scan tools may output credentials in their results (e.g., a verbose SSH banner with authentication method names, a TLS config dump with cipher suite details that include credential references). Before storing any tool output in `findings.evidence` or `scans.results`, the scanner passes it through a sanitizer:

```python
CREDENTIAL_PATTERNS = [
    r'(password|passwd|pwd)\s*[=:]\s*\S+',
    r'(api[_-]?key|apikey)\s*[=:]\s*\S+',
    r'(secret|token)\s*[=:]\s*\S+',
    r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    r'(bearer)\s+[A-Za-z0-9\-_]+',
]

def sanitize_output(raw_text: str) -> str:
    sanitized = raw_text
    for pattern in CREDENTIAL_PATTERNS:
        sanitized = re.sub(pattern, r'\1=***REDACTED***', sanitized, flags=re.IGNORECASE)
    return sanitized
```

This is not perfect (obfuscation is hard) but it prevents the most common accidental credential leaks from making it into the database.

---

## 9. Audit Logging

### 9.1 What Gets Logged

Every security-relevant action is recorded with timestamp, actor, action, and result.

| Event | Log Fields |
|---|---|
| User login (success/failure) | user_id (or email attempted), IP, user_agent, timestamp, result |
| User logout | user_id, timestamp |
| Token refresh | user_id, timestamp, old token expiry |
| Scan created | user_id, scan_type, target, credential_profile used |
| Scan started / completed / cancelled / failed | scan_id, user_id, timestamp, result |
| Finding status changed | user_id, finding_id, old_status, new_status, timestamp |
| Finding assigned | user_id, finding_id, old_assigned, new_assigned, timestamp |
| Connector created / updated / deleted | user_id, connector_id, connector_type, timestamp |
| Connector sync executed | connector_id, timestamp, assets_synced, errors |
| Credential accessed (vault read) | connector_id, user_id (who triggered), timestamp |
| API key created / revoked | user_id, api_key_id (hash prefix), timestamp |
| User created / role changed / disabled | admin_user_id, target_user_id, old_role, new_role, timestamp |
| Settings changed | user_id, setting_key, old_value, new_value, timestamp |

### 9.2 Where Logs Are Stored

| Log Type | Storage | Retention |
|---|---|---|
| Application logs (JSON) | Docker stdout → host journald | 90 days |
| Scan logs | `scan_logs` table | 90 days (auto-purged by Celery beat task) |
| Audit events | `audit_log` table (Phase 2) | 2 years |
| Failed login attempts | Application logs → alert after 5 failures from same IP in 10 minutes | 90 days |

**MVP:** No dedicated `audit_log` table — audit events are written to application JSON logs. Phase 2 adds the dedicated table for compliance reporting.

### 9.3 Failed Login Protection

After 5 failed login attempts from the same IP within 10 minutes, further attempts from that IP are **rate-limited to 1 attempt per 60 seconds**. The IP is logged. An optional Slack/email alert fires to admin after 10 failures.

Implementation: Redis-based sliding window counter (key: `login_attempts:{ip}`).

---

## 10. Network Isolation

### 10.1 Docker Network Segments (MVP)

The Docker Compose setup creates three isolated network segments:

```
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Network (isolated)                 │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐   │
│  │  worker  │  │  tshark      │  │  nmap / pqcscan     │   │
│  │ container│  │  (tshark)    │  │  binaries           │   │
│  └────┬─────┘  └──────────────┘  └─────────────────────┘   │
│       │                                                      │
│       │  Full outbound access (scans the world)              │
│       ▼                                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  scan_targets: internet, cloud VPCs, on-prem hosts   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

         ▲                      ▲                      ▲
         │ bridge               │ bridge               │ bridge
         │                      │                      │
┌────────┴──────────┐  ┌────────┴──────────┐  ┌────────┴──────────┐
│  frontend_network  │  │  api_network      │  │  data_network     │
│                    │  │                    │  │                    │
│  ┌─────────────┐  │  │  ┌─────────────┐   │  │  ┌─────────────┐  │
│  │   Nginx     │◄─┘  │  │   FastAPI   │◄──┘  │  │  │  PostgreSQL │   │
│  │  (proxy)    │     │  │   (app)      │     │  │  │  Redis      │   │
│  └─────────────┘     │  └─────────────┘     │  │  └─────────────┘  │
│                     │                     │  │                    │
│  React SPA          │  Responds to API    │  │  Data only         │
│  (port 80/443)      │  requests            │  │  (no external)     │
└─────────────────────┘ └────────────────────┘ └────────────────────┘
```

**Network rules:**
- **Frontend network:** Nginx ↔ React. No other traffic.
- **API network:** Nginx ↔ FastAPI ↔ Celery workers. No direct external access to Celery or PostgreSQL.
- **Data network:** FastAPI ↔ PostgreSQL + Redis. No external access to database at all.
- **Scanner network:** Celery workers ↔ tshark/pyshark/nmap/pqcscan ↔ Internet. This network is the most dangerous — it touches untrusted targets.

**Why this matters:** If a TLS endpoint being scanned is malicious and attempts a counter-attack against the scanner, the blast radius is limited to the scanner network. The API server and database are not directly reachable from scanner targets.

### 10.2 Kubernetes Network Policies (Phase 3)

```yaml
# api-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-network-policy
  namespace: pqcrypt
spec:
  podSelector:
    matchLabels:
      app: pqcrypt-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: pqcrypt-nginx
      ports:
        - protocol: TCP
          port: 8000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: pqcrypt-postgresql
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - podSelector:
            matchLabels:
              app: pqcrypt-redis
      ports:
        - protocol: TCP
          port: 6379
---
# scanner-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-network-policy
  namespace: pqcrypt
spec:
  podSelector:
    matchLabels:
      app: pqcrypt-worker
  policyTypes:
    - Egress
  egress:
    - to: []
      ports:
        - protocol: TCP
          port: 443  # HTTPS for CT logs, cloud APIs
        - protocol: TCP
          port: 22   # SSH scan targets
        - protocol: TCP
          port: 443  # TLS scan targets
        - protocol: UDP
          port: 53   # DNS
```

---

## Appendix: Quick-Reference Security Checklist

Use this before each release or deployment:

- [ ] All API endpoints return structured error JSON — no raw tracebacks to users
- [ ] `users.password_hash` is bcrypt, cost factor 12+, never reversible
- [ ] `credentials_ref` in connectors table — no passwords stored in DB
- [ ] Scan output sanitizer strips credential patterns before storage
- [ ] RBAC enforced on every endpoint — no unguarded routes
- [ ] CORS origins configured — not `*` in production
- [ ] TLS enforced on all internal service communication
- [ ] `SECRET_KEY` is 32+ random bytes, not in git
- [ ] `.env` file is in `.gitignore`
- [ ] HttpOnly + Secure flags on all cookies
- [ ] Rate limiting on `/api/v1/auth/login` (5 attempts per 10 min)
- [ ] Scanner worker runs in isolated Docker network
- [ ] `OFFLINE_MODE=true` disables all external callbacks
- [ ] Logs do not contain passwords, tokens, or private keys
- [ ] Celery task results don't leak credential data in error messages
- [ ] Audit log captures all credential access (Phase 2)
- [ ] File uploads checked for type and size before processing
- [ ] `deleted_at` soft-delete on all user-facing tables — no hard deletes

---

*End of Security & Access Document*
