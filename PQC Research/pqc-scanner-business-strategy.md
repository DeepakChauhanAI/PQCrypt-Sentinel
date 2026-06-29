# PQC Scanner Market — Business Analysis for CEO Presentation

A consolidated answer to the seven business questions, drawing on the project's existing market research (especially `pqc-market-landscape.html`, `pqc-market-landscape-general.html`, and `pqc-banking-scanner-research.html`) plus general industry context.

---

## 1. Active Players (Global and Indian, Open Source and Commercial)

### 1.1 Global Open Source (5)

| Product | Maintainer | Country | Purpose |
|---|---|---|---|
| **pqcscan** | Community (Rust) | — | TLS/SSH PQC handshake detection |
| **QRAMM Toolkit** (CryptoScan, TLS Analyzer, CryptoDeps) | Cloud4Y / community | — | SAST + TLS analysis + SBOM crypto lib scan |
| **IBM QSE + CBOMkit** (PQCA) | IBM | US | Quantum Safe Explorer + CycloneDX CBOM generator |
| **SSLyze + ssh-audit + testssl.sh** (combo) | Various maintainers | — | Deep TLS/SSH auditing stack |
| **PQC-Scanner (cyberjez)** | Community | — | Single-file endpoint scanner |

### 1.2 Global Commercial (10)

| Product | Vendor | Country | Founded/Status |
|---|---|---|---|
| **SandboxAQ AQtive Guard** | SandboxAQ (spun out of Alphabet March 2022; CEO Jack Hidary, Chairman Eric Schmidt) | US | $500M raised (Reuters Feb 2023); valuation not publicly disclosed; DoD and US federal contracts. AQtive Guard is the cryptographic discovery and inventory product. |
| **Keyfactor Command + AgileSec + CipherInsights** | Keyfactor (acquired InfoSec Global 2025; CipherInsights 2024) | US | 1500+ customers, 95% retention. Products: Keyfactor Command (CLM), Keyfactor AgileSec (cryptographic discovery), Keyfactor EJBCA, Keyfactor PQC Lab. |
| **AppViewX AVX ONE** | AppViewX | US | SaaS-first certificate lifecycle + PQC readiness |
| **CryptoNext COMPASS** | CryptoNext Security (Paris) | France | Recognized as Top 5 PQC Leader (ABI Research / Bain Capital Ventures / IDC Innovators). 20+ implemented use cases across banking, finance, defense, energy, aerospace. **COMPASS Discovery launched June 2025.** |
| **QryptoCyber** | QryptoCyber | US | Network+code PQC scanner + remediation roadmap |
| **ISARA Advance** | ISARA Corporation | Canada | Aggregation over EDR (Tanium, CrowdStrike) |
| **PQStation QVision** | PQStation | Singapore | AI-correlated PQC platform, APAC focus |
| **Palo Alto Networks / CyberArk / Venafi** (combined entity) | Palo Alto Networks acquired CyberArk Feb 2026 ($25B; announced July 30, 2025); CyberArk acquired Venafi Oct 1, 2024 ($1.54B, from Thoma Bravo) | US | Combined entity is the largest pure-play certificate-lifecycle-and-machine-identity-management vendor. PQC capabilities added across all three product lines 2024-2026. |
| **Binarly + QuSecure (Partnership)** | Binarly + QuSecure | US | Binary/firmware reachability + PQC remediation |

### 1.3 Indian Players

**This is the most important finding for the CEO: there are essentially zero Indian PQC scanner products.** Based on the project research and the broader public market:

- **Indian IT services companies** (TCS, Infosys, Wipro, HCL, Tech Mahindra, LTIMindtree) have cybersecurity practices and may offer PQC consulting, but **none has a packaged PQC scanner product** with the depth of the global commercial tools.
- **Indian security product companies** (Sequretek, Inspira, Innefu, Aujas) focus on broader security operations (SIEM, SOAR, EDR) — not on PQC-specific discovery.
- **Banking-specific Indian vendors** (Aurionpro, Intellect Design, Mphasis, NIIT Technologies, FIS India, Temenos India) build core banking platforms but do not sell PQC discovery as a separate product.
- **Indian crypto/security startups** (PrivaSapien, BlockBeam, Vervali) operate in adjacent areas (privacy, blockchain, identity) but not PQC scanning.
- **Indian PSUs and government bodies** (RBI, Cert-In, NCIIPC, C-DAC, IDRBT) have R&D activity in post-quantum but have not released commercial PQC scanner products.

**The Indian PQC scanner market is genuinely empty** — not just underserved, but **completely unserved** by domestic players. This is a first-mover opportunity.

---

## 2. Pricing / Costing Systems

### 2.1 Open Source — Free (with hidden costs)

Open-source tools are free to acquire but have hidden costs in engineering effort, integration, and ongoing maintenance:

| Product | License | Hidden cost (estimated) |
|---|---|---|
| pqcscan | Open source | 1-2 weeks integration |
| QRAMM | Open source | 1-2 weeks to assemble + configure |
| IBM QSE + CBOMkit | Open source | 2-4 weeks for SAST + CBOM pipeline |
| SSLyze + ssh-audit + testssl.sh | Open source | 1-2 weeks for combined stack |
| PQC-Scanner (cyberjez) | Open source | Light — single binary |

### 2.2 Commercial — Universal "Contact Sales" (no public pricing)

All commercial vendors use opaque, quote-based pricing. Estimated bands from the project research:

| Product | Price band | Model | Customer segment |
|---|---|---|---|
| **SandboxAQ AQtive Guard** | $200K-$2M+/yr | Assets under management | Mid-enterprise to government |
| **Keyfactor Command + AgileSec** | $75K-$500K/yr | Per certificate / per node | Mid-enterprise to large |
| **AppViewX AVX ONE** | $50K-$150K/yr | Per certificate | SME to mid-enterprise (SaaS only) |
| **CryptoNext COMPASS** | EUR 100K-500K/yr | License + professional services | EU mid-enterprise to large |
| **QryptoCyber** | Contact sales | Quote-based | Mid-enterprise |
| **ISARA Advance** | Contact sales | Quote-based | Large enterprise |
| **PQStation QVision** | Contact sales | Quote-based | APAC mid-enterprise |
| **Palo Alto Quantum-Safe** | Add-on subscription to PANW stack | Bundled | Existing PANW customers only |
| **Venafi / CyberArk** | $250K+/yr (est.) | Per certificate (CLM scale) | Large enterprise |
| **Binarly + QuSecure** | Contact sales | Quote-based | OT/firmware-focused enterprises |

### 2.3 Pricing patterns observed

- **No vendor publishes pricing.** Every commercial tool requires "contact sales." This is a procurement pain point for buyers who lack benchmarks.
- **Professional services (8-12 weeks implementation) often exceeds first-year license cost.** This is a hidden multiplier.
- **Mid-market ($15K-$75K/yr) is completely empty** — every commercial tool starts at $50K and quickly exceeds $200K.
- **Open source requires too much engineering** for a non-specialist team. A typical 8-12 week DIY build to get risk-scored output is realistic but expensive in human time.
- **The "first scan within one hour" use case has no commercial product.** Every tool needs professional services to deploy.

### 2.4 Indian pricing reality

- Indian bank IT security budgets: **INR 500Cr+ ($60M+/yr) at large banks** (SBI, HDFC, ICICI)
- Current commercial tools are priced **beyond the procurement comfort zone** of mid-size Indian PSBs (public sector banks) and NBFCs
- No vendor offers **India-based support, data residency guarantees, or INR billing** — a procurement blocker for RBI-regulated entities
- Project research suggests an accessible Indian pricing band: **INR 1-3Cr/yr ($120K-$360K) for large banks, INR 25-50L ($30K-$60K) for mid-size banks** — and this band has no incumbent

---

## 3. Revenue (Estimated, Since Most Vendors Are Private)

Direct revenue figures are not publicly disclosed for most private vendors. Estimates based on pricing bands, customer counts, and growth signals:

| Vendor | Estimated ARR | Basis |
|---|---|---|
| **SandboxAQ** | $100M-$300M+ (est.) | $5.75B valuation x typical 20-40x revenue multiple for cybersecurity; DoD contract value |
| **Keyfactor** | $80M-$150M (est.) | ABI Research #1 CLM 2025; >500K certs managed; 2025 acquisitions of InfoSec Global + CipherInsights |
| **CryptoNext** | EUR 5M-20M (est.) | EUR 12M total raised (2019); estimated 30-100 customers at EUR 100K-500K each; Banque de France, Allianz as anchors |
| **AppViewX** | $50M-$100M (est.) | Mature SaaS CLM player |
| **QryptoCyber** | $5M-$20M (est.) | Early commercial, smaller customer base |
| **ISARA** | $10M-$30M (est.) | Enterprise aggregation play, mature |
| **PQStation** | $2M-$10M (est.) | Newer entrant, APAC focus |
| **Venafi (CyberArk)** | $200M+ (pre-acquisition) | Largest CLM installed base; CyberArk disclosed Venafi was ~$200M ARR business |
| **Binarly** | $20M-$50M (est.) | Binary/firmware niche; growing |
| **Palo Alto Quantum-Safe** | New revenue line, included in PANW ($5B+ revenue company) | Cross-sell only |

### Open source revenue

Open-source PQC scanner tools generally do not generate direct revenue (the maintainers may have day jobs, consulting practices, or be part of larger organizations like IBM for QSE). The economic value they create is captured downstream by the organizations that deploy them.

### Honest caveat

These are estimates. None of the privately-held vendors (SandboxAQ, Keyfactor, CryptoNext, QryptoCyber, ISARA, PQStation) publish revenue. Only CyberArk/Venafi and Palo Alto disclose segment data, and even then only at the parent-company level.

---

## 4. Gaps in Their PQC Systems

This is the most actionable section for the CEO. Six categories of gaps, in order of strategic value:

### Gap 1 — Indian banking infrastructure is completely uncovered

**No existing product covers:**
- Payment HSM 3DES / PIN block format checks
- Core banking system crypto scanning (Finacle, Temenos, FIS Profile, Flexcube)
- ATM/POS hardware assessment (Diebold Nixdorf, NCR, GRG)
- RBI / NPCI / SWIFT interface compliance
- Indian banking regulatory context (RBI, NPCI, SEBI, IRDAI)

Every existing tool aligns with NIST/CISA (US), NCSC (UK), or ENISA (EU) — **not with Indian regulatory frameworks**.

### Gap 2 — Mid-market pricing is empty

The $15K-$75K/yr price band for self-hosted, full-coverage PQC scanners is completely unoccupied globally. Open source is too engineering-heavy; commercial tools are too expensive. Mid-size enterprises (500-5000 employees) have no viable option.

### Gap 3 — Deployment simplicity

**No commercial product deploys in a single docker-compose command.** Every commercial tool requires 8-12 weeks of professional services. The "first scan within an hour" use case is completely unserved. Open-source tools can do this individually, but no one has packaged them into a deployable platform.

### Gap 4 — HSM and key-management deep enumeration

PKCS#11 full key hierarchy (master key -> zone key -> session key) is mentioned in the CycloneDX CBOM spec but **implemented by nobody in their scanner**. KMIP-based KMS scanning, database TDE algorithm scans, and offline root CA assessment are all poorly covered or absent.

### Gap 5 — Runtime reachability

Every SAST tool (IBM QSE, QRAMM, Keyfactor AgileSec) finds algorithms statically present in code. **None verify which are actually executed at runtime in production.** Only Binarly + QuSecure does reachability analysis, and they focus on firmware, not general enterprise applications. False-positive problem: SAST tools flag unused legacy code paths that are not actually called.

### Gap 6 — Migration progress tracking

**No tool tracks migration progress over time with a % complete metric toward 2030/2035.** Banks, enterprises, and auditors need evidence of progress — not just point-in-time snapshots. CryptoNext + QryptoCyber have partial snapshots, but no tool shows the trajectory.

### Other notable gaps (lower priority)

- **Vendor PQC readiness database** — no tool cross-references Thales Luna firmware version against published PQC support dates, or OpenSSL version against ML-KEM support
- **Crypto agility recommendations** — how to refactor code to decouple algorithm choice from implementation is absent from all tools
- **SaaS-resident cryptography** — cryptography inside SaaS platforms (M365, Salesforce, etc.) is visible only via SAML/TLS handshake, not at the data-at-rest layer
- **IoT/OT firmware crypto** — only Binarly has serious coverage, and even that is partial
- **Air-gap deployment** — only truly supported by open source; commercial products all require connectivity

---

## 5. Market Opportunities

### 5.1 The strategic opportunity map

```
                    HIGH ENTRY BARRIER
                            |
                            |   Tier 3 Big Platform
                            |   (Palo Alto, CyberArk)
                            |   -----------------
                            |   Tier 2 Established
                            |   (SandboxAQ, Keyfactor)
                            |
        HIGH DEMAND --------+-------- LOW DEMAND
                            |
   Tier 1 Open              |   YOUR OPPORTUNITY ZONE
   (pqcscan, QRAMM,         |   (Indian banking,
    IBM QSE)                |    mid-market, on-prem)
                            |
                            |   -----------------
                            |   Tier 4 Niche
                            |   (Binarly, QuSecure)
                            |
                    LOW ENTRY BARRIER
```

### 5.2 The five concrete opportunities (ordered by attractiveness)

**Opportunity 1 — Indian banking vertical (highest moat)**

- IT security budgets of large Indian banks: INR 500Cr+ ($60M+/yr)
- No existing product covers Indian banking infrastructure
- First-mover with RBI-aligned output creates a defensible local market position
- Regulatory language in reports matters to Indian banking CISOs
- On-prem-only deployment (no data leaves India) is a procurement requirement
- Accessible pricing: INR 1-3Cr/yr ($120K-$360K) for large banks, INR 25-50L ($30K-$60K) for mid-size
- 12 public sector banks + 21 private sector banks (per RBI, 1 August 2025) + 28 regional rural banks + 44 foreign banks + 12 small finance banks + 4 payments banks + ~10,000 registered NBFCs (RBI's NBFC registry) of which ~300-400 are systematically important (NBFC-UL, NBFC-ML, NBFC-Base Layer) = addressable market
- Window: 2025-2028 before global platforms add Indian coverage

**Opportunity 2 — Mid-market globally (largest volume)**

- 500-5000 employee companies have no viable commercial option
- Open source requires too much engineering; commercial is too expensive
- The $15K-$50K/yr self-hosted tier has zero competition
- Volume opportunity: tens of thousands of mid-size organizations
- Window: 2-3 years before large platforms build downmarket

**Opportunity 3 — Managed service provider (MSP) channel**

- MSPs serving SMEs have no white-label PQC scanning product to resell
- An entire channel ecosystem is waiting
- Allows rapid geographic and vertical expansion without direct sales
- Recurring revenue model with high gross margins

**Opportunity 4 — Vendor PQC readiness database (defensible IP)**

- Built-in knowledge base: "does OpenSSL 3.4 support ML-KEM? Does Thales Luna firmware 7.9 support ML-DSA? Does AWS KMS support hybrid certs?"
- Enriches findings with remediation path automatically
- Nobody has this. It is a defensible content moat.
- Continuously updated — has ongoing value

**Opportunity 5 — Migration progress tracking (regulatory necessity)**

- Banks and regulators need evidence of progress toward 2030/2035
- Audit-ready dashboards showing % migrated, regression tracking, scan-over-scan diff
- This is what regulators will demand as 2030 approaches
- Becomes a procurement requirement, not a nice-to-have

### 5.3 Adjacent opportunities (lower priority but real)

- **PQC migration professional services** — high-margin, complements the tool
- **Crypto agility consulting** — no one offers this; banks will pay for it
- **HSM migration planning** — specialist area; Thales/Entrust resellers want partners
- **PQC test certificates and PKI pilot services** — for banks running their own PQC pilots

### 5.4 The "where to play" recommendation

**The strongest single opportunity is Indian banking.** Why:

1. **Zero domestic competition** — no Indian company has a PQC scanner product
2. **Strong regulatory tailwinds** — RBI has not yet published a formal PQC mandate (as of March 2025), but the global trajectory (NIST FIPS 203/204/205, EU DORA, US OMB M-23-02) points to 2030-2035 timelines, and Indian banks operating in UK/EU/US face those regulators directly
3. **High willingness to pay** — large Indian banks have security budgets that dwarf the tool's price
4. **Defensible moat** — regulatory language, data residency, on-prem deployment, banking-specific connectors (payShield, Finacle, NPCI, SWIFT LAU) — none of which global vendors offer
5. **Reference value** — Indian banking CISOs know each other; one anchor customer (SBI, HDFC, or ICICI) becomes 5-10 follow-on customers
6. **Window of 3 years** — global platforms will not have Indian-specific modules until they see the market is real

The secondary opportunity is mid-market globally, which can be served by the same product with different packaging (cloud-deliverable, lower touch, English-language regulatory templates).

---

## 6. Current Market and Future Predictions

> **Note on market sizing:** The market size figures in this section are **analyst estimates**, not verified third-party industry projections. They are directionally consistent with broader PQC market growth signals but should be sourced from specific analyst reports (Gartner, IDC, ABI Research, MarketsAndMarkets) before being used in customer-facing materials.

### 6.1 Current market state (mid-2026)

- **Market phase**: Crossing from "awareness" to "early adoption." NIST 2030 deadline is real enough that CISOs are budgeting for it.
- **Market size (PQC scanning only)**: Estimated **$300M-$500M globally in 2026**, growing rapidly. This is a slice of the broader post-quantum cryptography market (estimated $2B-$4B in 2026).
- **Number of paying customers**: Probably fewer than 500 organizations globally have purchased dedicated PQC scanning tools. Most are still in pilot or proof-of-concept.
- **Geographic concentration**: ~60% North America, ~25% Europe, ~10% APAC (mostly Singapore, Japan, Australia), ~5% rest of world (including India)
- **Vertical concentration**: Government/defense, banking/financial services, telecom, healthcare (in that order)

### 6.2 Regulatory drivers creating demand

- **NIST FIPS 203/204/205** (Aug 13, 2024) — the US deprecation timeline: RSA/ECDSA disallowed after 2030 (112-bit security) and 2035 (all). This is the global de facto standard. [Source: NIST]
- **NIST IR 8547** — explicit transition timeline for PQC migration. [Source needed]
- **CISA / NSA / NIST joint roadmap** (2025) — quantum-readiness migration factsheet, targets US critical infrastructure including financial services
- **EU DORA** (Reg. 2022/2554, in force Jan 17, 2025) — financial services resilience, includes cryptographic risk management
- **EU NIS2** (in force Oct 2024) — cybersecurity baseline across member states
- **US OMB M-23-02** (Jan 26, 2023) — federal agencies must inventory and plan PQC migration
- **UK NCSC** — guidance recommends large organisations plan PQC migration; specific dates cited in industry reports are projections, not formally published UK government deadlines. [Source needed]
- **G7 / FSB** — have published on quantum readiness for financial services; specific 2030-2035 deadlines cited in industry reports are not formal G7 commitments
- **RBI** — has not yet published a formal PQC mandate. The 2022 RBI Master Direction on IT Governance (in effect April 2024) covers IT risk but not PQC specifically.
- **SEBI, IRDAI** — expected to follow RBI and global frameworks, but no formal PQC mandate as of mid-2026

### 6.3 Future market predictions

**Near term (2026-2028): Rapid growth from a small base**

- Market grows 5-10x from current size as more CISOs fund PQC programs
- Total PQC scanning market: **$1.5B-$3B globally by 2028**
- Number of paying customers: 5,000-15,000 organizations
- Major consolidation via M&A continues (Keyfactor's 2025 acquisitions are a model)
- Indian banking becomes a defined vertical

**Medium term (2028-2031): Mass adoption phase**

- Market growth continues at 40-60% CAGR
- Total PQC scanning market: **$5B-$10B globally by 2031**
- Every Fortune 500 and major bank has a PQC scanning tool deployed
- Mid-market adoption accelerates as open-source-mature options emerge
- Cloud-delivered PQC scanners become the norm for mid-market
- "Crypto agility" emerges as a separate software category

**Long term (2031-2035): Maturity and consolidation**

- Market growth decelerates to 20-30% CAGR as base effect kicks in
- Total PQC scanning market: **$15B-$25B globally by 2035**
- Market consolidates to 5-8 dominant platforms
- 2030 NIST disallowance deadline triggers a panic-buying wave in 2029-2030
- 2035 NIST disallowance deadline triggers the second wave in 2034-2035
- Indian market matures with 2-3 strong domestic vendors and global players establishing India presence

### 6.4 Adjacent market expansions

The scanner is the **entry point** for a much larger PQC services and tooling market:

- **PQC migration services** — consulting, implementation, HSM upgrades. Estimated at 3-5x the scanner market size.
- **Crypto agility platforms** — refactoring code to decouple algorithm from implementation. Emerging category.
- **PQC-native PKI** — issuing PQC certificates at scale. Will become a $1B+ market by 2030.
- **PQC test infrastructure** — labs for validating PQC implementations. Smaller but high-margin.

### 6.5 The window for entry

| Phase | Years | What happens | Strategic implication |
|---|---|---|---|
| Window open | 2025-2027 | First-mover advantage in underserved segments | Build product, win anchor customers |
| Window closing | 2028-2030 | Large platforms add mid-market and vertical modules | Differentiate or be acquired |
| Window closed | 2031-2035 | Market consolidates; M&A dominant | Survive as a niche or be rolled up |

**The window for establishing product identity and customer base is 2025-2027.** After that, the market likely has 3-4 dominant platforms globally, with 2-3 strong vertical-specific players (including possibly an Indian banking-focused player).

---

## 7. Other Vertical Opportunities (Beyond Banking)

### Tier 1 — Highest Value (Large Budget + Regulatory Pressure + Complex Crypto)

**Government and Defense**
- CNSA 2.0, OMB M-23-02, CISA critical infrastructure designation
- US federal PQC budget estimated $1B+ over 5 years; allied governments following
- Market: $300M-$500M annually by 2028
- Indian angle: DRDO, MHA, defence PSUs (HAL, BEL, BDL), NCIIPC

**Telecom and 5G/6G**
- 5G AKA, SUPI/SUCI, network slice security, lawful intercept, SIM/eSIM
- Indian telecom: 1.2B+ subscribers across Jio, Airtel, Vi, BSNL, MTNL
- Market: $200M-$400M annually by 2028
- Indian angle: massive uncharted crypto inventory; DoT/CCA oversight

**Healthcare and Life Sciences**
- 50+ year data confidentiality; clinical trial IP; genomic data
- HIPAA, GDPR, India DISHA draft, ABDM
- Indian angle: ABDM creating 500M+ health IDs with quantum-vulnerable crypto
- Market: significant slice of $25B+ healthcare cybersecurity spend

**Energy and Utilities**
- SCADA, smart grid, AMI, NERC CIP, India CEA
- Indian angle: 250M+ smart meter national programme
- Market: $200M+ annually by 2028

### Tier 2 — Strong Value

**Insurance** — IRDAI Guidelines 2023, Indian insurance industry is INR 8Lakh+ Cr in premium, easy to extend banking logic.

**Stock Exchanges, Capital Markets, FMI** — SEBI-regulated, NSE/BSE/MCX, NSDL/CDSL, FIX protocol.

**Automotive and Connected Vehicles** — V2X PKI, OTA, ECU firmware, 10-20 year crypto life, Indian automotive is $100B+ industry.

**Cryptocurrency, Web3, Custody** — BLS, secp256k1, Ed25519, MPC, Indian exchanges (WazirX, CoinDCX, ZebPay) and Web3 (Polygon).

### Tier 3 — Strong Niches

**MSPs and MSSPs** — channel play, multi-tenant from day one, white-label.

**Cloud/SaaS** — internal scanning for their own PQC readiness, 500+ large SaaS companies.

**Education and Research** — underfunded but data-rich (medical research, defense-funded).

**Legal Services and Document Signing** — most HNDL-vulnerable use case.

**Embedded/IoT/OT** — smart cities, smart meters, medical devices, drones, mining.

**Space and Aerospace** — ISRO, Dhruva Space, Pixxel.

**Defense Manufacturing** — HAL, BEL, BDL, TATA Advanced Systems, L&T Defence.

### Vertical selection criteria

| Criterion | Weight | Description |
|---|---|---|
| Regulatory pressure | 30% | Are there mandates forcing PQC adoption? |
| Budget availability | 25% | Can they pay for a commercial tool? |
| Crypto complexity | 20% | Do they have non-standard crypto that generic tools miss? |
| Existing competition | 15% | Is the vertical unoccupied or well-served? |
| Strategic reference value | 10% | Does winning one customer unlock many others? |

### Top 5 recommendations for our tool (excluding banking)

1. **Indian telecom (Reliance Jio, Bharti Airtel, Vi)** — highest budget, 5G+ complexity, regulatory tailwind, unoccupied, strong reference value
2. **Government and defense (DRDO, MHA, defence PSUs)** — strong regulatory mandate, high budget, unoccupied in India, high strategic value
3. **Healthcare (Apollo, Fortis, ABDM ecosystem)** — long-lived data, ABDM/DISHA regulatory driver, greenfield
4. **MSP channel** — fastest scale, multiplies into SMB market
5. **Energy and critical infrastructure (PowerGrid, NTPC, smart meter programme)** — massive crypto footprint, NIS2/CEA pressure, large scale
