# PQC Scanner Technical Strategy — Presentation Prep

A consolidated analysis of the four technical questions, drawing on the project's existing research (CMDB, discovery, scanner architecture, feature comparison) and industry-standard patterns for OSI-layer inventory, CMDB federation, and schema normalization.

---

## 1. Components at Each OSI Layer in a Large Organization

The OSI model is useful as a framework for thinking about where cryptographic operations live. In a very large enterprise, every layer from 1 to 7 has components that may use or implement cryptography. Here is a comprehensive map, with typical hosting locations and whether they need PQC scanning.

### Layer 7 — Application

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| Web applications (in-house) | Custom portals, banking apps, ERPs | On-prem, cloud, SaaS vendors | TLS, JWT, session signing, form encryption | Yes |
| Web applications (3rd-party) | Salesforce, Workday, ServiceNow, M365 | Vendor SaaS | TLS to vendor, SSO via SAML/OIDC | Partially (TLS only) |
| APIs (REST/GraphQL/gRPC) | Internal microservices, partner APIs | Cloud, on-prem, edge | TLS, mTLS, JWT/JWS, OAuth2 | Yes |
| SaaS config surfaces | Okta, Auth0, Entra ID | Vendor SaaS | Signing keys, SAML certs | Yes (key rotation monitoring) |
| Email (S/MIME) | Outlook, Gmail, internal mail | Endpoint, gateway | S/MIME signing, DKIM, PGP | Yes |

### Layer 6 — Presentation

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| Serialization frameworks | Protocol Buffers, Avro, Thrift, JSON Web Encryption | Application runtime | Field-level encryption, JWE | Yes (via SAST/SBOM) |
| Encoding libraries | Apache Commons Codec, BouncyCastle | Application runtime | Encoding that wraps crypto | Yes (SBOM) |

### Layer 5 — Session

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| Session managers | Redis sessions, JWT issuers, SAML IdP | Cloud, on-prem | Signing, session token crypto | Yes |
| SSO / federation gateways | Okta, ADFS, PingFederate, Keycloak | Cloud, on-prem | SAML signing, OIDC signing, mTLS | Yes |
| RPC frameworks | gRPC, Thrift, RMI | Application runtime | mTLS, channel encryption | Yes (via SBOM) |

### Layer 4 — Transport

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| TLS terminators | Nginx, HAProxy, F5 BIG-IP, AWS ALB, Cloudflare | Edge, DMZ, cloud | TLS handshake, certs, cipher suites | Yes (high priority) |
| Load balancers with TLS | Same as above | Edge | Same as above | Yes |
| Service mesh sidecars | Istio, Linkerd | Kubernetes | mTLS, cert rotation | Yes |
| API gateways | Kong, Apigee, AWS API Gateway | Edge, cloud | TLS, JWT validation, mTLS | Yes |

### Layer 3 — Network

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| IPsec VPN gateways | Cisco ASA, Palo Alto, pfSense, strongSwan | Edge, on-prem | IKEv2, ESP, RSA/ECDSA | Yes (PQC migration is complex) |
| BGPsec implementations | Router firmware, ISP edge | ISP, large enterprise edge | BGPsec signatures | Limited (mostly out of scope) |
| DNSSEC validators | BIND, Unbound, Windows DNS | Internal DNS, ISP | DSA/ECDSA signing keys | Yes (DNSSEC key inventory) |
| Routers with MACsec | Enterprise switches/routers | Network core | MACsec key agreement | Limited (rare) |

### Layer 2 — Data Link

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| 802.1X authenticators | Switches, Wi-Fi controllers (Cisco ISE, Aruba ClearPass) | Network access layer | EAP-TLS, RADIUS, cert-based auth | Yes (RADIUS/TLS certs) |
| MACsec devices | Switches with MACsec | Data center, campus | MACsec | Limited |
| Wi-Fi (WPA3-Enterprise) | Enterprise APs | Campus, branch | 802.1X with certs | Yes (RADIUS) |

### Layer 1 — Physical

| Component | Example | Where located | Crypto used | Scan? |
|---|---|---|---|---|
| Hardware Security Modules (HSM) | Thales Luna, Entrust nShield, AWS CloudHSM | Data center, cloud | Key storage, signing operations | Yes — high priority |
| TPM chips | Endpoint devices, servers | Every modern endpoint | Disk encryption keys, attestation | Yes — high priority |
| Smart cards / PIV | User endpoints, secure rooms | Physical cards | User auth, signing | Yes — slow to migrate |
| Secure Boot / UEFI firmware | Every modern device | Endpoint firmware | Boot integrity chain | Yes — firmware crypto |
| Hardware tokens (FIDO2/YubiKey) | User endpoints | Physical | Authentication, signing | Yes — firmware version |

### Cross-layer (cross-cutting)

| Component | Where located | Crypto used | Scan? |
|---|---|---|---|
| Source code repositories | GitHub Enterprise, GitLab, Bitbucket | Crypto API calls, hardcoded keys | Yes (SAST) |
| Build pipelines | Jenkins, GitHub Actions, GitLab CI, Argo | Build-time crypto, signing | Yes |
| Container images | Docker Hub, ECR, GCR, ACR | Bundled crypto libraries | Yes (SBOM) |
| Certificate Authorities | AD CS, EJBCA, AWS Private CA, Vault PKI | Issuing certs, signing chains | Yes — backbone |
| Key Management Systems | HashiCorp Vault, AWS KMS, Azure Key Vault, GCP KMS | Symmetric + asymmetric key storage | Yes — high priority |
| HSMs (cloud-managed) | AWS CloudHSM, Azure Dedicated HSM | FIPS 140-2/3 key protection | Yes — high priority |
| Database TDE | Oracle, MSSQL, PostgreSQL pgcrypto | At-rest encryption | Yes |
| Identity providers | AD/Entra ID, Okta, Auth0, Keycloak | User identity, signing keys | Yes |
| SaaS / cloud provider crypto | AWS ACM, Azure Front Door, Cloudflare | TLS, cert management | Yes |



Every layer has crypto, and each layer has its own component types in its own hosting location. A complete PQC inventory must touch all of them. The layers that contribute the most to the total crypto surface, in order, are: **Application (Layer 7), Transport (Layer 4), Cross-layer cloud/SaaS, and Physical/cross-cutting (Layer 1)**. The layers that contribute least are the pure network/link layers (2 and 3) except for IPsec, DNSSEC, and 802.1X.

---

## 2. Where the Components Are Located (Hosting Model)

For a very large organization, the hosting model determines how you scan. The same component (e.g., a TLS endpoint) is scanned differently depending on where it lives.

| Hosting model | Examples | Scanning approach |
|---|---|---|
| On-premises data center | Bare-metal servers, VMware, Hyper-V, KVM | Agent-based or SSH/WinRM remote exec |
| Private cloud | OpenStack, VMware vSphere, on-prem Kubernetes | API-based (vCenter, OpenStack API, K8s API) + agent |
| Public cloud — IaaS | AWS EC2, Azure VMs, GCP Compute | Cloud provider API (AWS Config, Azure Resource Graph, GCP Asset Inventory) + agent |
| Public cloud — PaaS | AWS RDS, Azure App Service, GCP Cloud SQL | Cloud provider API; no agent access |
| Public cloud — SaaS | M365, Salesforce, Workday, Okta, ServiceNow | Vendor admin API only; no host access |
| Public cloud — serverless | AWS Lambda, Azure Functions | Cloud provider API; static analysis of deployment packages |
| Public cloud — containers | EKS, AKS, GKE, ECS, Fargate | K8s API + container image SBOM scan |
| 3rd-party vendor | Any external service your org uses | External TLS scan + CT log monitoring + vendor questionnaires |
| Embedded / OT / IoT | PLCs, RTUs, network equipment, medical devices, vehicles | Vendor firmware analysis + serial/SSH access where available |
| Endpoint devices | Laptops, desktops, mobile, BYOD | MDM/UEM API + endpoint agent |
| Backup and archive | Tape libraries, object storage (S3 Glacier, Azure Archive) | Encrypted at rest — scan catalog metadata |
| Partner / B2B | EDI gateways, partner APIs, SFTP servers | External TLS scan + protocol-specific probes |

### The Practical Implication

A scanner designed for one hosting model (e.g., on-prem network scan) gives you maybe 20-30% coverage in a typical large enterprise. The other 70-80% requires cloud APIs, K8s APIs, vendor admin APIs, and endpoint agents. This is the strongest argument for a CMDB-driven or CMDB-backed approach: the CMDB (or its cloud equivalents — AWS Config, Azure Resource Graph) already knows where everything lives, classified by hosting model.

---

## 3. Which Components Need to Be Scanned


### Scan (in priority order, high to low)

1. Internet-facing TLS endpoints — public web, APIs, mail, VPN. Highest HNDL exposure.
2. Internal TLS endpoints in production — service mesh, internal APIs, databases.
3. Code signing keys and infrastructure — HSMs, signing services, certificate authorities.
4. PKI root and intermediate CAs — the keys that sign everything else. Highest blast radius.
5. KMS / HSM-stored asymmetric keys — private keys whose compromise is catastrophic.
6. Identity provider signing keys — SAML, OIDC, JWT signing. Compromise = impersonation.
7. Database TDE — at-rest encryption of the actual data.
8. Document and email signing — long-lived S/MIME, PGP, code-signed binaries.
9. Endpoint disk encryption (TPM/BitLocker/FileVault) — recovery key handling.
10. Firmware signing (Secure Boot, device attestation) — slow to migrate.
11. IPsec / VPN gateways — long-lived tunnels, often unpatched.
12. IoT / OT device crypto — firmware, embedded keys.

### Sample-scan or Defer

- MACsec on data center switches (low business value, often transparent)
- Internal DNS without DNSSEC (most orgs don't sign internal DNS)
- BGPsec (almost nobody runs it)
- Tape backup encryption (very long-lived, but rarely a remote attack vector)

### Out of Scope

- Layer 1 physical security (cabinet locks, mantraps) — not cryptography
- Compliance attestations that don't require crypto (SOC 2 controls unrelated to crypto)

---

## 4. CMDB-Based PQC Scanner: Filter and Classify by Scanning Mechanism

When a CMDB is available, the PQC scanner does not start blind. It uses the CMDB to:

### Step 1 — Pull the target list

Query the CMDB for Configuration Items (CIs) using a CMDB-agnostic interface. The CIs that matter for PQC are:

- Servers, VMs, containers (compute layer)
- Applications and services (application layer)
- Network devices (TLS terminators, VPN)
- Certificate CIs (if modelled)
- Software CIs (for SBOM)
- Storage and database CIs (for TDE)

### Step 2 — Filter for PQC relevance

Apply four filter layers (already documented in `pqc-scanner-cmdb-discovery.html`):

1. **Class filter** — keep only CIs that can host crypto
2. **Attribute/keyword filter** — keep only CIs with `tls`, `cert`, `key`, `hsm`, etc.
3. **Relationship traversal** — expand the list by walking relationships (apps dependent on this server, certs issued by this CA, libraries used by this software)
4. **Priority filter** — keep only production + business-critical first

### Step 3 — Classify by scanning mechanism

For each candidate CI, the scanner picks the appropriate scan method based on CI attributes:

| CI attribute | Scanning mechanism |
|---|---|
| Has `ip_address` + `fqdn` + service in production | Active TLS/SSH handshake scan (Nmap + sslyze + pqcscan + cryptolyzer) |
| Has `installed_software` list | SBOM-based library classification (CMDB has OpenSSL version → pre-classify PQC capability) |
| Has `certificate_id` relationship | Pull cert from CMDB or CA directly, parse with Python `cryptography` lib |
| Is a network device with `ssh_enabled: true` | SSH audit (ssh-audit) |
| Is a database with `tde_enabled: true` | Vendor-specific TDE query |
| Is a cloud resource with `cloud_provider` set | Cloud provider API (AWS Config, Azure Resource Graph) |
| Has `agent_installed: true` | Agent pull (osquery, custom) |
| Has `kubernetes_cluster_id` | K8s API scan |
| Is a HSM | PKCS#11 enumeration (high-effort) |
| Has `source_repository_url` | SAST scan (Semgrep + QRAMM rules) |

The classification step is the critical bridge between the CMDB (which knows what exists) and the scan engine (which knows what crypto is in use). It tells the scanner: for this CI, run this scan. This is what makes CMDB integration qualitatively different from blind scanning — you are not running a uniform scan against everything; you are running the right scan against each CI.

### Step 4 — Enrich and write back

Scan results are attached to the CI as new attributes or related records. The CMDB CI now has: `pqc_status`, `quantum_risk_score`, `migration_priority`, `pqc_finding_ids[]`. The owning team sees this in their normal CMDB workflow.

---

## 5. No-CMDB: Build CMDB from Scratch

When no usable CMDB exists, the scanner effectively becomes the CMDB for crypto. The approach is documented in `pqc-scanner-cmdb-discovery.html`. The 6-phase rollout:

### Phase 1 — Public-facing crypto (days)

External TLS scan of known IP ranges + Certificate Transparency log monitoring + public DNS/repo scan. Produces a first inventory of internet-exposed crypto.

### Phase 2 — Certificate authorities (weeks)

Pull from AD CS, AWS Private CA, Azure Key Vault, EJBCA, HashiCorp Vault PKI. This is the single largest source of internal cert truth and reveals unknown certs.

### Phase 3 — Internal network (weeks-months)

Scan internal IP ranges for TLS/SSH endpoints. Cross-reference with Phase 2 to find orphans (certs not in any CA) and untracked endpoints.

### Phase 4 — Key stores and HSMs (months)

Enumerate KMS, HSM, Vault. Captures the asymmetric private keys — the actual PQC migration target.

### Phase 5 — Software and SBOM (months)

Deploy endpoint agents or pull SBOMs from build pipelines. Identifies crypto library versions.

### Phase 6 — Code and cloud (months)

Static analysis for hand-rolled crypto, cloud config audits, SaaS key inventories.

### Reconciliation

The five overlapping lists are merged using:

- **Deduplication** — same cert in network scan + AD CS + Vault → merge by serial/fingerprint/SAN
- **Relationship inference** — same hostname, same IP, same owner tag, same cert chain → build dependency graph with confidence scores
- **Confidence scoring** — every inferred relationship gets a probability; humans review the weak ones

### Result

By month 6, the PQC inventory database is, in effect, a crypto-focused CMDB. This becomes the foundation for everything else — migration tracking, remediation tickets, executive reporting.

---

## 6. Normalized CMDB Connector — The Multi-Vendor Question

The final question: can we build a system that connects to different CMDBs in a normalized way?

**Yes — this is a well-understood engineering pattern.** The standard approach is an **abstraction layer with vendor-specific adapters** behind a common interface. Three reference architectures are widely used.

### Pattern A — Adapter per CMDB, common internal model

The most common pattern. Each CMDB vendor gets a connector that translates its schema into a common internal model.

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  ServiceNow  │  │    NetBox    │  │   BMC Helix  │  │   Device42   │
│   Adapter    │  │    Adapter   │  │    Adapter   │  │    Adapter   │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │
       └─────────────────┴────────┬────────┴─────────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │  Common Internal CI Model    │
                  │  (canonical asset, cert,     │
                  │   relationship, owner)       │
                  └──────────────────────────────┘
```

Components:

- **Adapter per CMDB vendor** — translates vendor schema to the common model. 200-800 lines of code per vendor.
- **Common internal model** — a typed schema representing CI, relationship, owner, software, certificate, etc. Independent of any CMDB vendor.
- **Discovery service** — runs on a schedule, calls each adapter, deduplicates, persists to internal store.
- **Schema discovery** — each adapter introspects the CMDB's schema on first run, caches the result.

Effort to build:

- Internal common model: 1-2 weeks
- ServiceNow adapter: 2-3 weeks
- NetBox adapter: 1-2 weeks
- Each subsequent vendor: 1-2 weeks

### Pattern B — Schema-on-read (ETL into data lake)

The data-warehouse pattern. Pull raw CMDB data into a data lake (S3, BigQuery, Snowflake) and apply the schema at query time.

```
[CMDBs] → [Raw JSON dump] → [Object store] → [Query layer with schema-on-read]
```

Advantages: no upfront integration per vendor; flexible analysis; can ingest CMDB dumps without API access.

Disadvantages: higher latency (batch, not real-time); requires query-time schema knowledge; harder to do incremental updates.

Best fit: analytical use cases, large enterprises with many CMDBs, where latency is acceptable.

### Pattern C — CSDM / CDM alignment

For ServiceNow-heavy environments, ServiceNow publishes the Common Service Data Model (CSDM) — a standardized set of CI classes and relationships. For multi-vendor environments, Microsoft's Common Data Model (CDM) provides a similar cross-vendor entity model.

If the PQC scanner's internal model is aligned with CSDM/CDM, then:

- ServiceNow → CSDM-native adapter is trivial
- Other CMDBs map to CSDM/CDM with a single transformation step
- The scanner output (CBOM) is also CSDM-aligned, so the round-trip CMDB → scan → CBOM → CMDB preserves semantics

This is the strategic choice for a production-grade scanner.

### Recommended Design (Synthesis)

For a PQC scanner that needs to work across many organizations, the right design combines patterns A and C:

1. **Common internal model** aligned with CycloneDX CBOM (for crypto-specific data) and CSDM/CDM (for general asset/relationship data)
2. **Adapter framework** where each new CMDB vendor is a 200-800 line plugin
3. **Schema discovery** on first run, cached, refreshed weekly
4. **Bidirectional sync** — pull from CMDB, write findings back as a new CSDM class (`cmdb_ci_pqc_finding` or `cdm_pqc_finding`)
5. **Versioned adapter API** — the framework defines an interface; vendors ship their own adapters; the scanner can be extended without code changes to the core

### What This Means for Your Project

If the scanner has a CMDB-agnostic adapter framework:

- A new customer running ServiceNow gets the ServiceNow adapter enabled
- A customer running NetBox gets the NetBox adapter
- A customer with no CMDB at all gets the "from-scratch" path (adapters query AWS Config, Azure Resource Graph, GCP Asset Inventory — which are also CMDBs, just cloud-native ones)
- A customer with multiple CMDBs (common during M&A) gets all of them, with deduplication across vendors

The common internal model is the key asset. Once you have it, every adapter is incremental work, and the scanner becomes deployable into any customer's environment regardless of which CMDB they happen to run.

### Reference Patterns from the Wider Industry

This pattern is well-established outside PQC. The same approach is used by:

- **Vulnerability management platforms** (Tenable, Qualys, Rapid7) that ingest from dozens of CMDB/asset sources
- **Data catalog tools** (Collibra, Alation) that connect to many source systems
- **ITSM platforms** (ServiceNow, Jira SM) that federate from multiple discovery sources
- **Data mesh implementations** that apply this pattern at the data layer
- **API gateways** (Kong, Apigee) that translate between many vendor APIs and a common internal representation

The CMDB adapter framework is essentially a small data-integration problem. The engineering is well-understood, the patterns are proven, and the marginal cost per new CMDB vendor is low.

---

## Summary for the Presentation

| Technical question | One-line answer |
|---|---|
| What components exist in a large org? | Every OSI layer has crypto-bearing components; 70-80% of the surface is at Layer 7 (apps), Layer 4 (TLS), and cross-layer cloud/SaaS. |
| Where are they located? | On-prem, public cloud (IaaS/PaaS/SaaS/serverless), K8s, endpoints, vendor SaaS, OT/IoT, B2B partners. Each location needs a different scanning approach. |
| Which need scanning? | Anything that holds, uses, transports, or signs a key. Internet-facing TLS, PKI roots, HSMs, KMS, identity provider signing keys, and code signing are the highest priority. |
| Can we use CMDB as source? | Yes — query CMDB, filter for crypto-relevant CIs, classify each CI by which scan mechanism applies, run the right scan, write findings back. |
| What if no CMDB? | Build the CMDB from scratch using the 6-phase rollout (public crypto → CAs → internal network → key stores → software/SBOM → code/cloud). Reconcile overlapping sources. |
| Can we normalize across CMDBs? | Yes — adapter framework with a common internal model aligned to CSDM/CDM (general asset) and CycloneDX CBOM (crypto). Each new CMDB vendor is a 200-800 line adapter. |
| How does asset discovery happen? | Multi-source: CMDB + cloud APIs + network probes + CT logs + CA/HSM/KMS APIs + code repo APIs + DNS + MDM. Reconciled into one asset graph, then filtered to crypto-relevant nodes. |
| How does scanning happen? | Per-CI scan selection: active TLS/SSH/IPsec probes, cert deep-parse, config audit, cloud KMS/secret scan, SBOM analysis, SAST, PQC capability assertion. Output is a structured finding, not a boolean. |
| What credentials are required? | Tiered least-privilege, 7 tiers (0-6): none for public scan; read-only service account for CMDB/CA/SSHD; local/domain admin for OS cert stores; HSM auditor partition; cloud read IAM; vendor API token; repo read PAT. No domain admin, no HSM crypto officer, no app admin. |
| Agent vs agentless — where to use which? | Agentless-first (covers ~80%): internet-facing, cloud, network devices, HSM/KMS/CA, code repos, K8s API, container registries, CT logs. Agents for the host-local long tail: endpoint disk encryption, local cert stores, TPM, installed crypto libs, process-level crypto, air-gapped/OT, continuous monitoring. Hybrid is the production default. |

The strategic message: a CMDB-agnostic, adapter-based PQC scanner is deployable into any customer's environment, regardless of which CMDB they run or whether they have one at all. That portability is the architectural moat.

---

# Part II — Operational Mechanics (Extended Q&A)

The following four questions go deeper than the strategy overview above. They cover the day-to-day mechanics of running a PQC scanner: how the scanner finds assets, what it actually does against each asset, what credentials it needs, and the agent-vs-agentless split. These are the questions a CISO, security architect, or auditor will ask before approving deployment.

---

## 7. How Will Asset Discovery Happen?

Discovery is **multi-source, not single-technique**. The scanner combines twelve complementary discovery channels and reconciles the overlap into a single asset graph. No single channel gives you complete coverage. The strategic implication: a scanner that only does Nmap (or only does cloud APIs, or only does CMDB query) will see at most 20-30% of the crypto surface. The other 70-80% is invisible to that single channel.

### The twelve discovery channels

| # | Channel | Mechanism | What it finds | Credentials |
|---|---|---|---|---|
| 1 | **Active network probing** | Nmap, masscan, zmap, nmap NSE scripts | Live hosts, open ports, service banners, OS fingerprints | None (Tier 0) |
| 2 | **Passive network observation** | SPAN port tap, NetFlow, sFlow, Zeek | TLS handshakes on the wire, client/server pairs, certs in transit | None — read-only access to network device |
| 3 | **CMDB query** | ServiceNow / NetBox / BMC / Device42 REST API | Existing CI inventory with attributes, owners, relationships | Read-only CMDB service account |
| 4 | **Cloud provider APIs** | AWS Config, Azure Resource Graph, GCP Asset Inventory, OCI | Every resource, region, tag, KMS key, ACM cert, secret, IAM role | Read-only IAM role per cloud account |
| 5 | **Kubernetes API** | kubectl, cluster API server, K8s audit logs | Pods, services, secrets, configmaps, network policies, service accounts | Read-only K8s service account (cluster-wide or per-namespace) |
| 6 | **CA / PKI enumeration** | AD CS, EJBCA, AWS Private CA, Vault PKI, SCEP | Every issued cert, template, validity, key size, sig algorithm | Read-only CA operator role |
| 7 | **HSM / KMS API** | PKCS#11, vendor CLIs, cloud KMS APIs | Stored asymmetric keys, key policies, rotation state, key origin | Read-only HSM partition user; KMS `kms:ListKeys` + `kms:DescribeKey` |
| 8 | **Certificate Transparency** | crt.sh, Google CT log API, Cloudflare Nimbus | Public-facing certs (even ones IT didn't know about) | None — public |
| 9 | **Code repo APIs** | GitHub / GitLab / Bitbucket REST + git clone | Crypto API calls, hardcoded keys, SBOM, CI configs, build scripts | Read-only repo token (PAT or OAuth app) |
| 10 | **DNS enumeration** | Zone transfer, subdomain brute force, passive DNS | Hostname-to-IP mapping, subdomains, dangling DNS records | None for passive; auth needed for zone transfer |
| 11 | **MDM / UEM** | Intune, Jamf, Workspace ONE, MobileIron | Endpoint inventory, OS version, BitLocker state, cert profiles, disk encryption | Read-only MDM admin |
| 12 | **Endpoint agent (osquery, custom)** | Host-level daemon | Installed software, cert stores, OS keys, running processes, TPM state | Agent deployment (admin install via MDM or config management) |

### The reconciliation step

The same TLS endpoint shows up in channel 1 (Nmap), channel 3 (CMDB), channel 4 (AWS Config), and channel 5 (K8s API). The scanner **deduplicates** by `(ip, port, fqdn)` triple, attaches confidence scores to each evidence source, and walks relationships (e.g., this VM is in ServiceNow, runs this app, which talks to this KMS key). After reconciliation, each asset has a unified record with provenance metadata showing which channels contributed.

### Output of discovery

A **raw asset graph**: hosts, IPs, services, software, certificates, keys, identities, and the relationships between them. The graph is then **filtered to crypto-relevant nodes** using the four filter layers documented earlier (class filter, attribute keyword filter, relationship traversal, priority filter). What remains is the PQC scanner's working set — the subset of the asset graph that holds, uses, transports, or signs a key.

### Why this matters ?

A scanner that has 12 channels but doesn't reconcile them produces 12 conflicting lists. The reconciliation engine is the actual product. This is why vendors like ServiceNow, Wiz, Axonius, and Lansweeper are valued at billions — the asset reconciliation problem is hard, and most enterprises cannot solve it internally.

---

## 8. How Will Scanning Happen?

Scanning is the **active verification step** that produces cryptographic evidence. Discovery tells you *what exists*; scanning tells you *what crypto is actually in use* on each asset. The two are separated for a reason: discovery is high-volume, low-cost, runs continuously; scanning is targeted, higher-cost, runs on schedule or on-demand.

### Scan types and their tools

| Scan type | Tool | What it produces |
|---|---|---|
| **Active TLS handshake** | `sslyze`, `testssl.sh`, `nmap --script ssl-enum-ciphers`, `cryptolyzer`, `pqcscan` | Protocol versions, cipher suites, KEX groups, signature algs, server cert chain, PQC support (e.g., `X25519MLKEM768` = IANA 0x639A) |
| **SSH KEX/host-key dump** | `ssh -vvv`, `ssh-audit`, `nmap --script ssh2-enum-algos` | Negotiated KEX, host key alg, ciphers, MACs, PQC support (`mlkem768x25519`, `sntrup761x25519`) |
| **Certificate deep parse** | `openssl x509 -text`, Python `cryptography` library | Subject, issuer, validity, sig alg OID, pub key alg + size, key usage, EKU, SAN, AIA, OCSP, chain validation |
| **Local config audit** | `sshd_config`, `nginx.conf`, Apache `ssl.conf`, `ssh -Q kex` | Configured (not just negotiated) algorithms — often worse than what's actually negotiated |
| **IPsec / IKE probe** | `ike-scan`, `nmap --script ike-version`, vendor CLIs | IKE proposals, DH groups, PFS groups, auth methods, Phase 1/Phase 2 lifetimes |
| **Cloud KMS / secret scan** | AWS KMS, Azure Key Vault, GCP KMS, AWS Secrets Manager, Azure Key Vault | Key metadata: type, spec (RSA-2048 vs ML-KEM), rotation, key policy, alias, origin, HSM backing |
| **SBOM crypto analysis** | CycloneDX / SPDX parsers, `cdxgen`, `syft` | Crypto library versions: OpenSSL 1.1.1 (legacy, no PQC) vs 3.x (PQC-ready), libcrypto, BoringCrypto, BouncyCastle, Go `crypto/tls`, mbedTLS |
| **SAST — hand-rolled crypto** | Semgrep with QRAMM / CryptoGuard rules, custom patterns | Direct calls to `RSA_generate_key`, MD5, custom ECC, hardcoded keys, weak RNG, deprecated APIs |
| **CA template audit** | `certutil -CATemplate`, AD CS PowerShell, EJBCA CLI | Template min key size, allowed sig algs, enrollment EKU, auto-enrollment policy |
| **Container image scan** | Trivy, Grype, Anchore, Snyk Container on ECR/GCR/ACR | Crypto libs in image, OS package vulns, attestation state, signed vs unsigned |
| **PQC capability assertion** | Custom probe that *requests* a hybrid KEX | Verifies the endpoint doesn't just *list* ML-KEM in config but *negotiates* it under real load |
| **Configuration drift** | Continuous diff against baseline | New TLS endpoint appeared since last scan; cert renewed with weaker algorithm; SSH config regressed |

### The scan output is a structured finding, not a boolean

Each finding has a rich, structured shape:

```json
{
  "asset": {
    "id": "vm-prod-7421",
    "type": "server",
    "fqdn": "api.bank.in",
    "ip": "10.20.30.40",
    "owner": "payments-platform",
    "cmdb_id": "cmdb_ci:0a1b2c3d"
  },
  "finding_type": "weak_kex | rsa_2048_cert | tls_1_0_enabled | ssh_rsa_host_key | ...",
  "algorithm": "RSA-2048 | ECDHE-RSA-AES128 | X25519 | ML-KEM-768",
  "evidence": {
    "tool": "sslyze",
    "raw_output": "...",
    "cert_thumbprint": "AB:CD:...",
    "config_line": "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1"
  },
  "pqc_status": "vulnerable | transitioning | pqc_ready | hybrid",
  "quantum_risk_score": 0,
  "hndl_exposure": "high | medium | low | none",
  "remediation": "Upgrade OpenSSL to 3.5+ | Enable ML-KEM | Reissue cert with ML-DSA | Disable TLS 1.0/1.1",
  "cvss_quantum_vector": "AV:N/AC:H/PR:N/...",
  "discovered_at": "2026-06-02T11:30:00Z",
  "last_verified": "2026-06-02T11:30:00Z"
}
```

This shape is what makes the scanner useful to downstream systems (ticketing, dashboards, CBOM export, regulatory reporting).

### The two key insights

1. **Scan selection is per-CI, not uniform.** The CMDB classification table (see section 4) tells the scanner: for this CI, run this scan. A network device gets SSH audit, a database gets TDE query, an S3 bucket gets cloud API, a HSM gets PKCS#11 enumeration. Running a uniform scan against everything produces 80% noise and 20% signal.
2. **PQC capability assertion matters more than config audit.** A server that *lists* ML-KEM in its config but *fails* to negotiate it under real load is not PQC-ready. The scanner must attempt the actual handshake, not just read the config.

---

## 9. What Credentials Are Required?

The principle is **least-privilege, tiered access**. The scanner requests the minimum access needed for each discovery/scan type. Real-world deployments use 6–7 distinct credential types, all stored centrally in a customer-managed vault, all short-lived, all audited.

### The seven tiers of credential

| Tier | Credential | Used for | Example |
|---|---|---|---|
| **Tier 0** | None | Public TLS, CT log, DNS brute, passive network tap, public SBOM registries | Internet-facing scan from scanner cloud |
| **Tier 1** | Read-only service account | SSH audit, K8s read, MDM query, CA read, cloud read-only IAM | `svc-pqc-read` in ServiceNow; AWS `ViewOnlyAccess` IAM role |
| **Tier 2** | Local / domain admin | OS cert store, AD CS audit, GPO inspection, registry read, scheduled task query, SSH to Linux fleet | Domain account in `Cert Publishers` group; sudoers on Linux fleet |
| **Tier 3** | HSM partition / KMS crypto officer (read-only) | HSM key enumeration (PKCS#11 `C_GetInfo`, `C_FindObjects`), key policy read | HSM `auditor` partition; AWS KMS `kms:DescribeKey` + `kms:ListKeys` |
| **Tier 4** | Cloud org-wide read | Cross-account cloud asset inventory, organization-wide resource graph | AWS Org `ViewOnlyAccess`; Azure `Reader` at management-group scope; GCP `Viewer` at folder scope |
| **Tier 5** | App / vendor-specific | Internal CA web enrollment API, vendor admin portal (Okta, M365, Salesforce, Workday, ServiceNow) | API token per vendor; OAuth 2.0 with fine-grained scopes |
| **Tier 6** | Source repo read-only | SAST on code, SBOM pull from build pipeline, CI config inspection | GitHub fine-grained PAT with `contents:read` + `actions:read`; GitLab project access token |

### What the scanner does NOT need

- **Domain Admin / Enterprise Admin** — Domain Admin is overkill for AD CS audit. A domain account in `Cert Publishers` and `Read-Only Domain Controllers` is sufficient.
- **HSM Crypto Officer** — The auditor / read-only partition user is sufficient for enumeration. Crypto Officer is required only for key operations (create, sign, export), which the scanner never performs.
- **Root on every Linux box** — Root is needed only on machines where no API or read-only SSH can produce the same evidence. Most Linux config and SBOM data is readable by a privileged service account.
- **Database DBA** — Database TLS configuration is observable at the network layer (probe the listener) or via the cloud API (RDS / Cloud SQL metadata). Direct DB access is rarely needed.
- **Application admin** — Only required if pulling app-specific config from a private admin API. Most application crypto is observable at the protocol layer.

### Credential management practices

- **Storage**: customer-managed HSM or Vault. Never in the scanner's database. Never in environment variables on the scanner host.
- **Rotation**: Tier 1/2/4/5 rotate every 30–90 days. Tier 3 (HSM) rarely — typically tied to organizational key ceremony cadence. Tier 6 (repo tokens) follows the source system's expiry policy.
- **Short-lived tokens preferred**: OIDC federation, STS assume-role, OAuth refresh tokens with 1-hour expiry. Long-lived static API keys are a fallback, not the default.
- **Audit trail**: every credential use is logged. The scanner's own credential vault is a high-value target and needs its own access controls, audit, and anomaly detection.
- **Just-in-time elevation**: when Tier 2/3 is needed for a one-off scan (e.g., AD CS audit), use a JIT privilege elevation tool (Teleport, CyberArk, Azure PIM) rather than a standing admin grant.

### The Indian banking angle

For the strategic target customers (RBI-regulated banks, NBFCs, insurance), the credential model must support:

- **Data residency**: scanner runs in the customer's VPC (Indian region), credentials never leave the customer's network boundary.
- **RBI Cyber Security Framework alignment**: scanner's credential requests must be auditable under the bank's InfoSec policy. Tiered access maps cleanly to the bank's "maker-checker" model.
- **No standing admin**: JIT elevation aligns with RBI's least-privilege guidance for third-party tools.
- **Shared responsibility clarity**: the scanner's vault is in the customer's control, not the scanner vendor's. The vendor cannot read customer credentials after deployment.

---

## 10. Agent vs Agentless — Where to Use Which?

Short answer: **agentless first, agents where agentless can't reach**. A modern PQC scanner runs ~70-80% of its work agentless. The agent is for the long tail of host-local evidence that no network probe or API call can produce.

### The decision framework

| If the target is… | Use… | Why |
|---|---|---|
| **Internet-facing TLS / SSH / VPN** | **Agentless** | Network probes work fine; no creds needed; scanner runs from cloud |
| **Cloud IaaS / PaaS / SaaS** | **Agentless** | Cloud provider API gives you everything; agents add nothing |
| **Network devices** (routers, switches, firewalls, load balancers) | **Agentless** (SSH/NETCONF/SNMP read-only) | Vendors don't allow third-party agents; config read is enough |
| **HSM / KMS** | **Agentless** (API) | Hardware mandates vendor-only access; PKCS#11 enumeration is agentless |
| **CA / PKI** | **Agentless** (CA APIs, LDAP) | AD CS, EJBCA, Vault PKI all have read APIs |
| **Code repos / CI/CD** | **Agentless** (GitHub API, runner plugins) | No runtime on the build host needed; SAST runs in CI |
| **K8s clusters** | **Agentless** (K8s API) | K8s API + admission webhook data covers pods, secrets, network policies |
| **Container images (in registries)** | **Agentless** (registry scan) | Trivy/Grype on ECR/GCR/ACR; no runtime needed |
| **Public cert monitoring** | **Agentless** (CT log watcher) | crt.sh + Google CT API, no creds |
| **Endpoint disk encryption state** (BitLocker, FileVault, LUKS) | **Agent** | Need to read recovery key escrow, escrow policy, escrow state — host-local |
| **Local OS cert stores** (Windows `Cert:\`, Linux NSS, macOS Keychain) | **Agent** | Cross-user, cross-store enumeration needs local context |
| **TPM inventory** (spec, algs, persistent objects) | **Agent** | `Get-Tpm` / `tpm2_getcap` are host-local commands |
| **Endpoint crypto library inventory** | **Agent** | Need to scan `dpkg` / `rpm` / MSI for OpenSSL, NSS, BoringCrypto versions |
| **Process-level crypto use** (which app calls which lib) | **Agent** | Requires running process inspection, ETW on Windows, eBPF on Linux |
| **Continuous monitoring** (drift, new certs, new TLS endpoints) | **Agent** (or periodic agentless re-scan) | Point-in-time agentless scans miss ephemeral state; agent can stream |
| **Air-gapped / OT / IoT** | **Agent** | No inbound network access; must run locally; ferry results out via sneakernet or one-way diode |
| **BYOD / unmanaged endpoints** | **Agentless** (MDM API if enrolled) or **MDM agent** (Intune/Jamf) | Can't install custom agent on BYOD; use MDM API for enrolled subset |

### Trade-offs

| Dimension | Agent | Agentless |
|---|---|---|
| **Visibility** | Deep — sees host-local state, processes, cert stores, TPM, disk encryption | Shallow — sees network-facing protocols and APIs only |
| **Deployment** | Hard — needs install, support, OS coverage matrix, MDM packaging, autoupdate | Easy — point scanner at target, no host impact |
| **Real-time** | Yes — streams events as they happen | Periodic — schedule-based (hourly, daily) |
| **Ephemeral assets** | Catches them (containers, serverless) | Misses them between scans |
| **Customer friction** | High — IT/InfoSec must approve install, antivirus exclusions, support tickets | Low — no install |
| **Compliance posture** | Difficult — runs in customer env, may need separate audit | Easier — scanner runs out-of-band |
| **Scalability** | Linear in number of endpoints (per-agent cost) | Linear in scan target count (often cheaper at scale) |
| **Failure mode** | Agent stops reporting → silent gap | Scan fails → loud error, easy to detect |
| **Air-gap support** | Strong — designed for it | Weak — usually needs network reachability |

### Recommended architecture (synthesis)

A production PQC scanner runs in **hybrid mode by default**, with the customer picking the mix per asset class:

```
┌──────────────────────────────────────────────────────────────┐
│  DISCOVERY SOURCES (parallel, all agentless)                 │
│  ─────────────────────────────────────────                   │
│  • CMDB query (API, read-only)                               │
│  • Cloud provider APIs (AWS/Azure/GCP, read IAM)             │
│  • CA / PKI / HSM / KMS APIs (read-only)                    │
│  • Network probes (Nmap, Zeek on SPAN port)                  │
│  • Code repo APIs (GitHub/GitLab/Bitbucket)                  │
│  • CT log watchers (crt.sh, Google CT)                       │
│  • DNS / passive DNS                                         │
│                                                              │
│  → Reconciled asset graph (deduped, scored, relationships)   │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│  SCAN ENGINE (per-CI scan selection)                         │
│  ───────────────────────────────────                         │
│  For each CI, pick the right scan (per CMDB classification): │
│  • Active TLS/SSH/IPsec probes (agentless)                   │
│  • API-based key/cert/KMS pull (agentless)                   │
│  • SBOM analysis (agentless from build pipeline)             │
│  • SAST on repos (agentless)                                 │
│  • PQC capability assertion (agentless)                      │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│  HOST-LOCAL EVIDENCE (agent OR admin)                        │
│  ────────────────────────────────────                        │
│  Deployed ONLY where the asset is:                           │
│  • Endpoint device (laptop, desktop, mobile)                 │
│  • Server with no API access (legacy on-prem)                │
│  • Air-gapped / OT / IoT                                     │
│  • Container/K8s node (DaemonSet)                            │
│                                                              │
│  Agent collects: TPM, local cert stores, disk encryption     │
│  state, installed crypto libs, process-level crypto use.     │
│  Streams back to scan engine.                                │
└──────────────────────────────────────────────────────────────┘
```

### Default rule of thumb

> **80% of PQC discovery is agentless. The 20% that isn't is the most sensitive — TPMs, disk encryption keys, and endpoint cert stores. A scanner that only does one mode is incomplete.**

### The Indian banking angle

For the strategic target customers, agentless-first is a strong selling point:

- **Avoids the long InfoSec approval cycle** for agent deployment in regulated banks. RBI auditors scrutinize every piece of software that runs on bank endpoints; an out-of-band scanner is a much easier conversation.
- **Works across the bank's hybrid cloud** (private cloud + on-prem + selective public cloud for non-PII workloads). One scanner deployment covers all three.
- **Respects data residency** — scanner runs in the bank's VPC (Indian region). The agent, where deployed, runs on the bank's managed endpoints under bank's MDM (Intune/Jamf), not the scanner vendor's cloud.
- **Aligns with vendor risk management** — the scanner vendor never touches endpoint OS, never installs software on bank devices for the 80% agentless path. Bank InfoSec teams will see this as a major risk reduction.

### What this means for the scanner architecture

The scanner must support **both modes in a single product**, with the customer choosing per asset class. This means:

1. The scan engine is the same code; the only difference is the data source (agent telemetry vs API/probe).
2. The findings schema is the same; agent-collected and agent-collected findings look identical to downstream systems.
3. The UI presents the deployment mode per asset and lets the operator switch.
4. The pricing model can reflect the cost difference (agent deployment is more expensive, agentless is cheaper at scale) — though for the MVP, flat pricing is simpler.

---

## Part II Summary for the Presentation

| Operational question | One-line answer |
|---|---|
| How will asset discovery happen? | Multi-source: 12 channels (CMDB, cloud APIs, network probes, CT logs, CA/HSM/KMS APIs, code repo APIs, DNS, MDM, agent, etc.) reconciled into one asset graph, then filtered to crypto-relevant nodes. |
| How will scanning happen? | Per-CI scan selection: active TLS/SSH/IPsec probes, cert deep-parse, config audit, cloud KMS/secret scan, SBOM analysis, SAST, PQC capability assertion. Output is a structured finding (asset + algorithm + evidence + PQC status + remediation), not a boolean. |
| What credentials are required? | Tiered least-privilege, 7 tiers (0-6). No domain admin, no HSM crypto officer, no app admin. JIT elevation for one-off scans. Customer-managed vault. |
| Agent vs agentless — where? | Agentless-first (covers ~80%): internet-facing, cloud, network devices, HSM/KMS/CA, code repos, K8s, container registries, CT logs. Agents for host-local long tail: endpoint disk encryption, cert stores, TPM, installed crypto libs, process-level crypto, air-gapped/OT, continuous monitoring. Hybrid is the production default. |

The strategic message for operations: **the scanner is mostly agentless, deeply API-driven, and deliberately credential-light**. This is what makes it deployable inside a regulated Indian bank without a 12-month InfoSec approval cycle.
