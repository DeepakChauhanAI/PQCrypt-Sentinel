# Product Requirements Document (PRD)

**Product Name:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Product Team  
**Status:** Draft  

---

## 1. Executive Summary

PQCrypt Sentinel is an enterprise-grade Post-Quantum Cryptography (PQC) Discovery and Mitigation Platform. It automates the discovery of cryptographic assets across an organization's entire infrastructure, identifies quantum-vulnerable algorithms, maps dependencies, scores risk, and tracks migration progress toward NIST-standardized post-quantum cryptography.

The platform addresses the urgent "Harvest Now, Decrypt Later" (HNDL) threat — where adversaries steal encrypted data today to decrypt it once quantum computers become operational — and helps organizations comply with global regulatory deadlines (NIST 2030/2035, EU DORA, UK NCSC, CISA/NSA roadmaps).

---

## 2. Target Users

### Primary Users

| User Role | Goal | Technical Level |
|---|---|---|
| **CISO / Security Director** | Executive dashboards, compliance reports, risk posture overview | Low-Medium |
| **Security Architect** | Full cryptographic inventory, dependency mapping, migration planning | High |
| **IT Security Analyst** | Day-to-day scanning, finding triage, remediation ticket management | Medium-High |
| **Compliance Officer** | Regulatory reports (NIST, RBI, DORA, NCSC), audit evidence | Low |
| **DevOps / Platform Engineer** | CI/CD integration, SBOM analysis, container scanning, K8s crypto audit | High |

### Secondary Users

| User Role | Goal |
|---|---|
| **MSP / MSSP** | Multi-tenant scanning for client environments, white-label reports |
| **External Auditor** | Read-only access to cryptographic inventory and migration evidence |
| **Application Owner** | View findings assigned to their services, track remediation |

---

## 3. Problem Statement

### The Quantum Threat is Now

Quantum computers will break RSA, ECC, and Diffie-Hellman — the algorithms protecting virtually all digital communication today. The "Harvest Now, Decrypt Later" strategy means adversaries are already stealing encrypted data for future decryption.

### Regulatory Deadlines Are Real

- **NIST:** RSA/ECDSA disallowed after 2030 (112-bit security) and 2035 (all)
- **EU:** Full cryptographic inventory mandated by end of 2026
- **UK NCSC:** 2028 inventory, 2031 priority migration, 2035 full adoption
- **US OMB/CISA:** Federal agencies and critical infrastructure must inventory and migrate
- **G7 Banking:** All G7 central banks committed to 2030-2035 PQC migration

### No One Has Complete Visibility

Every enterprise uses cryptography at every OSI layer — from TLS endpoints and SSH servers to HSMs, code signing, disk encryption, and firmware. No existing tool provides a complete, reconciled view. Open-source tools cover ~25% of the surface. Commercial tools cost $75K-$2M+/yr and require 8-12 weeks of professional services to deploy.

### The Gap

- **No tool deploys in under an hour** (every commercial tool needs weeks of services)
- **No tool tracks migration progress over time** (% migrated, regression detection)
- **No tool covers the full OSI stack** (network + code + infrastructure + hardware)
- **Mid-market ($15K-$50K/yr) is completely empty** globally
- **No tool has a vendor PQC readiness database** (which OpenSSL version supports ML-KEM?)

---

## 4. Core Features

### 4.1 Multi-Source Asset Discovery

| Discovery Channel | What It Finds | Priority |
|---|---|---|
| Active TLS/SSH handshake probes | Internet-facing endpoints, cipher suites, cert chains | MVP |
| Certificate Transparency (CT) log monitoring | Public certs, shadow IT, subsidiaries | MVP |
| DNS enumeration | Hostname-to-IP mapping, subdomains | MVP |
| CA / PKI enumeration (AD CS, Vault, AWS PCA) | Internal cert inventory (70-80% of internal certs) | Phase 2 |
| Cloud provider APIs (AWS Config, Azure Resource Graph, GCP) | Cloud resources, KMS keys, ACM certs | Phase 2 |
| Kubernetes API | Pods, services, secrets, ingress TLS | Phase 2 |
| CMDB integration (ServiceNow, NetBox, BMC Helix) | Existing asset inventory, ownership, relationships | Phase 2 |
| SBOM ingestion (CycloneDX, SPDX) | Crypto library versions, dependency analysis | Phase 2 |
| Code repository APIs (GitHub, GitLab, Bitbucket) | SAST crypto findings, hardcoded keys | Phase 2 |
| Endpoint agent (SSH/WinRM remote exec) | Local cert stores, TPM, installed crypto libs | Phase 3 |
| HSM / KMS API (PKCS#11, KMIP) | Key inventories, algorithms, rotation state | Phase 3 |
| Passive network tap (SPAN/mirror) | Real-time TLS handshakes on the wire | Phase 3 |

### 4.2 Cryptographic Analysis Engine

- **Algorithm classification:** Map every discovered algorithm to its PQC status (vulnerable, transitioning, PQC-ready, hybrid)
- **OID matching:** Detect PQC OIDs for ML-KEM, ML-DSA, SLH-DSA, Falcon, and hybrid composites
- **Downgrade detection:** Identify endpoints that offer PQC but also allow classical fallback
- **Vendor PQC readiness database:** Cross-reference software versions against PQC support (e.g., "OpenSSL 3.4 supports ML-KEM", "Thales Luna firmware 7.9 supports ML-DSA")
- **Composite/hybrid detection:** Recognize hybrid signatures (e.g., `rsa-pss-ml-dsa`) and key exchanges (e.g., `X25519MLKEM768`)

### 4.3 Risk Scoring Engine

Multi-dimensional risk scoring per asset using:

| Factor | Weight | Description |
|---|---|---|
| **HNDL Sensitivity** | High | Long-lived secrets harvested today, decrypted later |
| **System Exposure** | High | Internet-facing, partner integrations, public infrastructure |
| **Business Criticality** | High | Tier-0/Tier-1 core transactional services |
| **Algorithm Vulnerability** | High | RSA-2048 vs RSA-4096 vs ECC vs hybrid vs PQC |
| **Regulatory Deadline** | High | Compliance dates from NIST, CNSA 2.0, banking regulators |
| **Migration Ease** | Medium | Vendor PQC updates ready, standard library upgrades |
| **Certificate Lifetime** | Medium | Certs expiring after the migration deadline |
| **Data Longevity** | Medium | How long the protected data must remain confidential |

### 4.4 Migration Progress Tracking

- **9-stage workflow:** Find → Own → Map → Prioritize → Recommend → Pilot → Roll out → Track → Re-scan
- **Scan-over-scan diff:** Compare cryptographic posture between scan cycles
- **Progress dashboard:** % of assets migrated, % PQC-ready, regression alerts
- **Drift detection:** Alert when a migrated asset regresses to quantum-vulnerable algorithms
- **Algorithm recommendation map:** Automated suggestions (RSA-2048 → ML-DSA-65, ECDH P-256 → ML-KEM-768)

### 4.5 Reporting & Compliance

- **Executive dashboard:** Total PQC readiness rate, top-N remediation queue, risk distribution
- **Operational dashboard:** Per-team backlogs, scan coverage, drift alerts
- **CBOM export:** CycloneDX Cryptographic Bill of Materials
- **Regulatory templates:** NIST, CISA, NCSC, DORA, RBI-aligned reports
- **Ticketing integration:** Auto-create Jira/ServiceNow tickets from findings
- **Audit trail:** Signed, timestamped evidence records with provenance metadata

### 4.6 Deployment

- **Single docker-compose deploy** with PostgreSQL — first scan in under 1 hour
- **On-premise / air-gap capable** — no data leaves the customer's network
- **Agentless-first** — ~80% of discovery requires no agent installation
- **Hybrid mode** — optional endpoint agents for deep host-level visibility

---

## 5. User Stories

### Epic 1: First Scan

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-1.1 | As a security architect, I want to deploy the scanner with a single docker-compose command so that I can start scanning within 1 hour. | docker-compose up completes, web dashboard accessible, first scan initiated |
| US-1.2 | As a security architect, I want to scan my public TLS endpoints by providing an IP range or domain list so that I get an immediate cryptographic inventory. | Scan completes, findings show algorithms, cert details, PQC status |
| US-1.3 | As a CISO, I want to see a risk dashboard after my first scan so that I understand my quantum exposure. | Dashboard shows risk distribution, top vulnerable assets, HNDL exposure |

### Epic 2: Deep Discovery

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-2.1 | As a security architect, I want to connect my AD CS / Vault PKI so that I get a complete internal certificate inventory. | Connector pulls all issued certs, maps to endpoints |
| US-2.2 | As a DevOps engineer, I want to import my SBOM (CycloneDX/SPDX) so that crypto library versions are analyzed. | SBOM parsed, OpenSSL/NSS/BoringCrypto versions flagged with PQC readiness |
| US-2.3 | As a security architect, I want to connect my AWS/Azure/GCP account so that cloud KMS keys and ACM certs are inventoried. | Cloud connector pulls key metadata, algorithms, rotation state |
| US-2.4 | As a security architect, I want to connect my ServiceNow/NetBox CMDB so that findings are enriched with ownership and business context. | CMDB sync maps CIs to findings, ownership resolved |

### Epic 3: Risk & Prioritization

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-3.1 | As a CISO, I want to see a Mosca's Theorem timeline per asset so that I know which data is at HNDL risk. | Each asset shows: data longevity vs quantum timeline vs migration window |
| US-3.2 | As a security analyst, I want findings prioritized by risk score so that I work on the most critical items first. | Findings sorted by composite risk score, filterable by factor |
| US-3.3 | As a compliance officer, I want to export a CBOM (CycloneDX) so that I can share it with auditors. | CBOM export in CycloneDX JSON format, includes all discovered crypto assets |

### Epic 4: Migration Tracking

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-4.1 | As a security architect, I want to track migration progress over time so that I report % PQC-ready to leadership. | Dashboard shows trend line: % vulnerable → % hybrid → % PQC-ready |
| US-4.2 | As a security analyst, I want to be alerted when a migrated asset regresses so that I catch configuration drift. | Drift detection triggers alert on algorithm downgrade |
| US-4.3 | As a security architect, I want automated algorithm recommendations so that I know exactly what to migrate to. | Each finding shows: current algo → recommended PQC replacement → hybrid transition |

### Epic 5: Integration & Operations

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-5.1 | As a security analyst, I want findings auto-created as Jira/ServiceNow tickets so that remediation flows through existing workflows. | Ticket created with finding details, assigned to CI owner |
| US-5.2 | As an MSP, I want multi-tenant support so that I can scan multiple client environments from one deployment. | Tenant isolation, per-tenant dashboards, separate credential vaults |

---

## 6. MVP Scope (Version 1.0 — 8-12 Weeks)

### In Scope (MVP)

- **Active TLS scanning** (sslyze Python API + pqcscan CLI + testssl.sh CLI)
- **Passive TLS/SSH monitoring** (pyshark on SPAN/mirror port — real-time handshake observation)
- **PCAP file analysis** (pyshark FileCapture — offline analysis of customer-provided captures)
- **SSH audit** (paramiko + ssh-audit CLI)
- **PQC group probing** (scapy-crafted ClientHello with ML-KEM groups to test server support)
- Hybrid PQC + downgrade detection
- Certificate chain deep parse (cryptography lib with PQC OID classification)
- CT log monitoring (passive, public — crt.sh API)
- DNS enumeration (dnspython)
- Network discovery (python-nmap)
- CycloneDX CBOM output (cyclonedx-python-lib)
- Multi-dimensional risk scoring
- HNDL / Mosca's Theorem per asset
- Vendor PQC readiness database (software version → PQC support mapping)
- Web dashboard (asset list, risk distribution, top-N remediation queue, migration progress)
- Single docker-compose deploy with PostgreSQL
- Optional: CMDB CSV import for ownership context
- On-premise / air-gap deployment

### Out of Scope (Version 1.0)

- Cloud provider API connectors (AWS, Azure, GCP)
- CMDB bidirectional sync (ServiceNow, NetBox)
- Endpoint agents (SSH/WinRM)
- Kubernetes scanning
- HSM PKCS#11 enumeration
- SAST / SBOM ingestion
- Multi-tenant SaaS
- Ticketing integration (Jira, ServiceNow)
- Cipher translation / virtual patching
- Binary / firmware analysis
- Runtime reachability analysis

---

## 7. Success Metrics

| Metric | Target (6 months) | Target (12 months) |
|---|---|---|
| Time to first scan | < 1 hour | < 30 minutes |
| TLS endpoint coverage | 95% of internet-facing | 99% |
| False positive rate | < 15% | < 5% |
| Scan cycle time (1000 endpoints) | < 4 hours | < 1 hour |
| CBOM completeness | 60% of crypto surface | 85% |
| Customer deployments | 10 pilot customers | 50 paying customers |
| NPS score | > 30 | > 50 |

---

## 8. Features to Avoid in Version 1

| Feature | Why Defer | Risk of Including |
|---|---|---|
| **Multi-tenant SaaS** | Requires identity, billing, tenant isolation, SLAs | 6+ months of engineering, distracts from core product |
| **Cipher translation proxy** | Inline network proxy, latency-critical, hardware-locked | Palo Alto's territory; massive complexity |
| **Runtime reachability** | eBPF or dynamic instrumentation, per-language agents | Research-grade, hard to productize |
| **Binary/firmware analysis** | Disassemblers (Ghidra), custom crypto signature DB | Binarly has a strong lock here; 12+ months effort |
| **PQC/hybrid cert issuance** | Requires HSM investment, CA integration | Different product category (CLM) |
| **Cert lifecycle automation** | ACME protocol, vendor hooks, change windows | Venafi/Keyfactor's core business |
| **HSM deep enumeration** | HSM vendor SDKs, lab access, deep PKCS#11 knowledge | High effort, niche buyer |
| **Agent-based endpoint scanning** | MDM packaging, OS coverage matrix, auto-update | High customer friction; defer to Phase 3 |

---

## 9. Competitive Positioning

### The Empty Zone

The strategic positioning is the "self-hosted, full-coverage, sub-hour deploy, $15K-$50K/yr mid-market" zone — which has zero competitors globally.

| Dimension | Open Source | Commercial Giants | PQCrypt Sentinel |
|---|---|---|---|
| **Coverage** | ~25% of crypto surface | ~70% | 60%+ (MVP), 85%+ (Phase 3) |
| **Passive monitoring** | None (pcap tools exist but no PQC analysis) | Some (SandboxAQ, Palo Alto) | Yes (pyshark on SPAN port) |
| **Deploy time** | Days-weeks (manual) | 8-12 weeks (services) | < 1 hour |
| **Price** | Free (hidden engineering cost) | $75K-$2M+/yr | $15K-$50K/yr |
| **Dashboard** | None/basic | Full | Full |
| **Migration tracking** | None | Partial | Full |
| **On-prem / air-gap** | Yes | Partial | Yes |
| **Vendor readiness DB** | None | None | Yes (MVP) |
| **PCAP file analysis** | Manual (tshark/Wireshark) | None | Yes (automated PQC analysis) |

---

## 10. Regulatory Alignment

The platform's reports and findings will be structured to align with:

| Framework | Region | Key Requirement |
|---|---|---|
| NIST FIPS 203/204/205 | US/Global | ML-KEM, ML-DSA, SLH-DSA standards |
| NIST IR 8547 | US | Transition timeline |
| CISA/NSA/NIST Roadmap | US | Critical infrastructure migration |
| OMB M-23-02 | US | Federal agency inventory + migration |
| EU DORA | EU | Financial services cryptographic resilience |
| EU Commission Mandate | EU | Full crypto inventory by end 2026 |
| UK NCSC | UK | 3-phase: 2028 inventory → 2031 migration → 2035 adoption |
| G7 Banking Coordination | Global | 2030-2035 PQC migration for SIFIs |
| RBI Cyber Security Framework | India | Data residency, crypto inventory |
| SEBI / IRDAI | India | Financial sector crypto compliance |

---

## 11. Open Questions

1. Should the MVP support multi-cloud scanning or focus on on-prem first?
2. What is the minimum viable CMDB integration depth (CSV import vs REST API)?
3. Should the vendor PQC readiness database be a separate product or embedded?
4. What is the pricing model: per-endpoint, per-scan, or flat subscription?
5. Should we offer a free tier (limited scans) for market penetration?
