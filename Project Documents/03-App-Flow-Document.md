# App Flow Document

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** UX Strategy Team  
**Status:** Draft  

---

## 1. Screen Inventory

| # | Screen | Route | Purpose |
|---|---|---|---|
| S1 | Login | `/login` | Authentication |
| S2 | Dashboard (Executive) | `/` | High-level risk posture overview |
| S3 | Dashboard (Operational) | `/dashboard/ops` | Scan coverage, team backlogs, drift alerts |
| S4 | Asset Explorer | `/assets` | Searchable table of all discovered crypto assets |
| S5 | Asset Detail | `/assets/:id` | Single asset: algorithms, certs, risk, findings |
| S6 | Findings List | `/findings` | All findings, filterable by severity/status/type |
| S7 | Finding Detail | `/findings/:id` | Single finding: evidence, remediation, assignment |
| S8 | Scans | `/scans` | Scan history, schedule, initiate new scan |
| S9 | Scan Detail | `/scans/:id` | Scan results, progress, diff from previous |
| S10 | Reports | `/reports` | Generate and download CBOM/compliance reports |
| S11 | Connectors | `/settings/connectors` | Manage CMDB, cloud, CA integrations |
| S12 | Settings | `/settings` | General config, credentials, notifications |
| S13 | User Management | `/settings/users` | RBAC user administration |
| S14 | Migration Progress | `/migration` | PQC migration tracking dashboard |

---

## 2. Detailed Screen Flows

### S1: Login Page

**URL:** `/login`

| Element | Behavior |
|---|---|
| Username field | Text input, required |
| Password field | Password input, required |
| "Sign In" button | Submits credentials → POST `/api/v1/auth/login` |
| Error state | "Invalid credentials" toast on 401 |
| Success state | Redirect to `/` (Dashboard) |
| Empty state | N/A |

**Navigation:**
- On success → S2 (Dashboard)
- On failure → Stay on S1 with error message

---

### S2: Dashboard (Executive)

**URL:** `/`

**Purpose:** One-screen answer to "How exposed are we to quantum threats?"

| Element | Behavior |
|---|---|
| **PQC Readiness Score** | Large circular gauge (0-100%), color-coded (red < 30, yellow 30-70, green > 70) |
| **Risk Distribution** | Donut chart: Critical / High / Medium / Low / PQC-Ready |
| **HNDL Exposure Timeline** | Bar chart: assets grouped by "years until quantum risk" |
| **Top 10 Vulnerable Assets** | Table: asset name, algorithm, risk score, owner, action button |
| **Migration Progress** | Line chart: % PQC-ready over time (last 12 scans) |
| **Scan Coverage** | Horizontal bar: % of known assets scanned in last 30 days |
| **Drift Alerts** | Card: count of assets that regressed since last scan |
| **"Run New Scan" button** | Navigates to S8 with scan creation modal open |

**Empty State (no scans yet):**
- Show onboarding wizard: "Run your first scan" CTA
- Placeholder cards with dashed borders and "No data yet" labels
- Tooltip: "Connect your first scan target to see your cryptographic posture"

**Error State:**
- If API fails: "Unable to load dashboard data. Retry." with refresh button

**Navigation:**
- Click on any asset → S5 (Asset Detail)
- Click on any finding → S7 (Finding Detail)
- Click "Run New Scan" → S8 (Scans)
- Click "View All Findings" → S6 (Findings List)

---

### S3: Dashboard (Operational)

**URL:** `/dashboard/ops`

**Purpose:** Day-to-day operational view for security analysts.

| Element | Behavior |
|---|---|
| **Scan Queue** | Active/completed/failed scans with status badges |
| **Team Backlog** | Findings grouped by assigned team/owner, sorted by count |
| **Drift Alerts** | Table: asset, regressed algorithm, previous state, timestamp |
| **New Discoveries** | Assets found since last scan (new TLS endpoints, new certs) |
| **Coverage Gaps** | Assets in CMDB but not scanned in 30+ days |

**Navigation:**
- Click scan → S9 (Scan Detail)
- Click finding → S7 (Finding Detail)
- Click asset → S5 (Asset Detail)

---

### S4: Asset Explorer

**URL:** `/assets`

**Purpose:** Searchable, filterable table of all discovered cryptographic assets.

| Element | Behavior |
|---|---|
| **Search bar** | Full-text search across asset name, IP, FQDN, owner |
| **Filter panel** | Collapsible sidebar with: Algorithm type, PQC status, Risk level, Owner, Business service, Discovery source, Last scanned date |
| **Asset table** | Columns: Name, Type, IP/FQDN, Primary Algorithm, PQC Status (badge), Risk Score (color), Owner, Last Scanned |
| **Sort** | Click column header to sort (default: risk score desc) |
| **Pagination** | 50 items per page, page controls at bottom |
| **Bulk actions** | Select multiple → Assign owner, Change status, Export |
| **"Export CSV" button** | Downloads filtered results as CSV |
| **"Export CBOM" button** | Downloads CycloneDX JSON of filtered assets |

**Empty State:**
- "No assets match your filters" with "Clear Filters" button
- If no scans have run: "No assets discovered yet. Run your first scan."

**Navigation:**
- Click asset row → S5 (Asset Detail)
- Click owner name → Filter by that owner

---

### S5: Asset Detail

**URL:** `/assets/:id`

**Purpose:** Complete view of a single cryptographic asset.

| Section | Content |
|---|---|
| **Header** | Asset name, type icon, IP/FQDN, owner badge, risk score gauge |
| **Overview tab** | Asset type, discovery source, first discovered, last scanned, business service, environment |
| **Algorithms tab** | Table: Algorithm, Type (KEX/Sig/Symmetric/Hash), Key Size, PQC Status (badge), CVE links |
| **Certificates tab** | Table: Thumbprint, Subject, Issuer, Sig Alg, Key Size, Expiry, PQC Status |
| **Findings tab** | All findings for this asset: severity, type, status, remediation |
| **Dependencies tab** | Graph: this asset → certs → CAs → business services (interactive, zoomable) |
| **History tab** | Timeline: scan results over time, algorithm changes, drift events |

| Element | Behavior |
|---|---|
| **"Re-scan" button** | Triggers immediate scan of this asset |
| **"Assign Owner" button** | Opens modal with user search |
| **"Create Ticket" button** | Opens modal → POST to Jira/ServiceNow (Phase 2) |
| **"View in CMDB" link** | External link to ServiceNow/NetBox CI (if CMDB connected) |

**Empty States:**
- No certificates: "No certificates discovered for this asset"
- No findings: "No findings — this asset appears PQC-ready"
- No dependencies: "No dependency data available. Connect a CMDB for richer context."

**Navigation:**
- Click certificate → Certificate detail modal
- Click finding → S7 (Finding Detail)
- Click dependency node → S5 for that asset

---

### S6: Findings List

**URL:** `/findings`

**Purpose:** All cryptographic findings across all assets.

| Element | Behavior |
|---|---|
| **Filter panel** | Severity, Status (open/in-progress/resolved/accepted), Type, Owner, Asset, Algorithm |
| **Findings table** | Columns: Severity (badge), Type, Asset, Algorithm, Status, Owner, Discovered, Action |
| **Status badges** | Open (red), In Progress (yellow), Resolved (green), Accepted (gray) |
| **"Assign" action** | Inline dropdown to assign to user |
| **"Change Status" action** | Inline dropdown: Open → In Progress → Resolved / Accepted |

**Navigation:**
- Click finding row → S7 (Finding Detail)
- Click asset name → S5 (Asset Detail)

---

### S7: Finding Detail

**URL:** `/findings/:id`

**Purpose:** Complete context for a single cryptographic finding.

| Section | Content |
|---|---|
| **Header** | Severity badge, finding type, asset name link, algorithm |
| **Evidence** | Raw scan output (collapsible code block), tool used, scan timestamp |
| **Risk Context** | HNDL exposure, business criticality, regulatory deadline, composite risk score |
| **Remediation** | Recommended action (e.g., "Upgrade OpenSSL to 3.5+", "Reissue cert with ML-DSA-65") |
| **Algorithm Map** | Current algo → Recommended PQC replacement → Hybrid transition |
| **Assignment** | Owner, status, ticket link (if integrated) |
| **History** | Timeline: when found, status changes, re-scan results |

| Element | Behavior |
|---|---|
| **"Change Status" button** | Dropdown: Open / In Progress / Resolved / Accepted |
| **"Assign" button** | User search modal |
| **"Re-scan" button** | Triggers scan of parent asset |
| **"Create Ticket" button** | Creates Jira/ServiceNow ticket (Phase 2) |
| **"Mark as False Positive" button** | Changes status to "Accepted" with reason field |

**Navigation:**
- Click asset name → S5 (Asset Detail)
- Click related finding → S7 for that finding

---

### S8: Scans

**URL:** `/scans`

**Purpose:** Scan management — history, scheduling, and initiation.

| Element | Behavior |
|---|---|
| **"New Scan" button** | Opens scan creation modal |
| **Scan history table** | Columns: ID, Type, Target, Status, Start Time, Duration, Assets Found, Findings |
| **Status badges** | Queued (gray), Running (blue pulse), Completed (green), Failed (red) |
| **Schedule panel** | List of scheduled scans with cron expressions, next run time |

**Scan Creation Modal:**

| Field | Behavior |
|---|---|
| **Scan Type** | Dropdown: Full Scan / TLS Only / SSH Only / Targeted |
| **Target** | Text area: IP ranges (CIDR), domain list, or "All known assets" |
| **Credential Profile** | Dropdown: select pre-configured credential set |
| **Schedule** | Toggle: Run Now / Schedule (cron picker) |
| **"Start Scan" button** | POST `/api/v1/scans` → closes modal → redirects to S9 |

**Empty State:**
- "No scans have been run yet. Start your first scan to discover cryptographic assets."
- Large "New Scan" button centered

**Navigation:**
- Click scan row → S9 (Scan Detail)
- Click "New Scan" → Modal → S9 (on start)

---

### S9: Scan Detail

**URL:** `/scans/:id`

**Purpose:** Real-time and historical view of a single scan.

| Section | Content |
|---|---|
| **Header** | Scan ID, type, target, status badge, start time, duration |
| **Progress bar** | Real-time: % complete, current phase (discovery/analysis/reporting) |
| **Live log** | Streaming log output (WebSocket) showing current operation |
| **Results summary** | Assets discovered, findings created, algorithms breakdown |
| **Diff from previous** | Changes since last scan: new assets, removed assets, algorithm changes, regressions |
| **Findings created** | Table of new findings from this scan |

| Element | Behavior |
|---|---|
| **"Cancel Scan" button** | Stops running scan (confirmation modal) |
| **"Re-run Scan" button** | Creates new scan with same parameters |
| **"View Findings" button** | S6 filtered to this scan_id |
| **"Export Results" button** | Download scan results as JSON/CSV |

**States:**
- **Running:** Progress bar animates, live log streams, results update in real-time
- **Completed:** Full results shown, diff highlighted
- **Failed:** Error message, partial results (if any), "Retry" button

---

### S10: Reports

**URL:** `/reports`

**Purpose:** Generate and download compliance and analysis reports.

| Element | Behavior |
|---|---|
| **Report Type selector** | Dropdown: CBOM (CycloneDX), Executive Summary, Compliance (NIST/CISA/NCSC/DORA), Migration Progress |
| **Scope selector** | All assets / Filtered by business service / Filtered by owner |
| **Format selector** | JSON (CBOM), PDF (Executive/Compliance), CSV (raw data) |
| **"Generate Report" button** | POST `/api/v1/reports` → shows progress → download link |
| **Report history table** | Previous reports with download links |

**Empty State:**
- "No reports generated yet. Select a report type and scope to generate your first report."

---

### S11: Connectors

**URL:** `/settings/connectors`

**Purpose:** Manage integrations with external systems.

| Element | Behavior |
|---|---|
| **Connector list** | Cards for each connector type: CMDB, Cloud, CA, Code Repo, K8s |
| **"Add Connector" button** | Opens connector-specific configuration form |
| **Status indicator** | Green (connected), Yellow (error), Gray (not configured) |
| **Last sync timestamp** | Shows when data was last pulled |
| **"Sync Now" button** | Triggers immediate sync |
| **"Test Connection" button** | Validates credentials and connectivity |

**Connector Configuration Forms:**

| Connector | Fields |
|---|---|
| **ServiceNow** | Instance URL, Username, Password, Table prefix |
| **NetBox** | URL, API Token |
| **AWS** | Access Key, Secret Key, Region, Role ARN |
| **Azure** | Tenant ID, Client ID, Client Secret, Subscription |
| **GCP** | Service Account JSON, Project ID |
| **AD CS** | LDAP URL, Service account DN, Password |
| **GitHub** | PAT token, Org/Repo scope |
| **Kubernetes** | Kubeconfig or API server URL + token |

---

### S12: Settings

**URL:** `/settings`

| Tab | Content |
|---|---|
| **General** | Platform name, timezone, scan defaults (throttle rate, timeout) |
| **Credentials** | Credential profiles (encrypted storage), tier labels |
| **Notifications** | Email/Slack/webhook config for drift alerts, scan completion |
| **Backup** | Database backup schedule, export/restore |
| **License** | License key, usage stats |

---

### S13: User Management

**URL:** `/settings/users`

| Element | Behavior |
|---|---|
| **User table** | Columns: Name, Email, Role, Last Login, Status |
| **"Add User" button** | Modal: Name, Email, Role (Admin/Analyst/Viewer), Temporary password |
| **Edit user** | Inline edit: Role, Status (active/disabled) |
| **Delete user** | Confirmation modal, soft-delete |

---

### S14: Migration Progress

**URL:** `/migration`

**Purpose:** Track PQC migration journey over time.

| Element | Behavior |
|---|---|
| **Overall progress** | Large gauge: % assets PQC-ready |
| **Trend chart** | Line chart: % Vulnerable → % Hybrid → % PQC-ready over time |
| **By algorithm** | Stacked bar: count of each algorithm type (RSA, ECC, ML-KEM, ML-DSA, etc.) |
| **By business service** | Table: Service name, % migrated, findings count, owner |
| **By deadline** | Timeline: assets grouped by regulatory deadline urgency |
| **Regression alerts** | Table: assets that moved backward (PQC-ready → vulnerable) |

---

## 3. Global Navigation

```
┌─────────────────────────────────────────────────────┐
│  PQCrypt Sentinel    [Dashboard] [Assets] [Findings]   │
│                   [Scans] [Reports] [Migration]      │
│                                           [Settings] │
│                                           [User ▼]   │
├─────────────────────────────────────────────────────┤
│                                                     │
│   < Page content here >                             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Sidebar (collapsible):**
- Dashboard (Executive)
- Dashboard (Operational)
- Assets
- Findings
- Scans
- Reports
- Migration Progress
- ---
- Connectors
- Settings
- User Management

---

## 4. Error States (Global)

| Error Type | Display | Action |
|---|---|---|
| **API unreachable** | Red banner: "Unable to connect to server" | Auto-retry every 5s, manual "Retry" button |
| **401 Unauthorized** | Redirect to login with "Session expired" toast | — |
| **403 Forbidden** | "You don't have permission to view this page" | Link back to dashboard |
| **404 Not Found** | "This page doesn't exist" | Link back to dashboard |
| **500 Server Error** | "Something went wrong" with error ID | "Retry" button, error ID for support |
| **Scan failed** | Red badge on scan, error message in scan detail | "Retry Scan" button |

---

## 5. Toast Notifications

| Event | Toast Type | Message |
|---|---|---|
| Scan started | Info | "Scan #1234 started" |
| Scan completed | Success | "Scan #1234 completed: 47 assets, 12 findings" |
| Scan failed | Error | "Scan #1234 failed: connection timeout" |
| Drift detected | Warning | "Regression detected: api.bank.in reverted to RSA-2048" |
| Report ready | Success | "CBOM report ready for download" |
| Connector sync | Info | "ServiceNow sync completed: 1,204 CIs updated" |
| User created | Success | "User john@example.com created" |
