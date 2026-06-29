# PQC Scanner Technical Strategy — Presentation Prep (v2)

A consolidated analysis of the four technical questions, drawing on the project's existing research (CMDB, discovery, scanner architecture, feature comparison) and industry-standard patterns for OSI-layer inventory, CMDB federation, and schema normalization.

This version adds:
- **Protocol Used** column to every component table
- **Non-PQC-relevant components** alongside crypto-relevant ones (marked with a dash in the Scan column)
- **Deep dive on Web Applications (Layer 7)** — web server → database flow, third-party services, queuing, caching, SaaS authentication

---

## 1. Components at Each OSI Layer in a Large Organization

The OSI model is useful as a framework for thinking about where cryptographic operations live. In a very large enterprise, every layer from 1 to 7 has components that may use or implement cryptography. This table now also lists components that do **not** directly use cryptography (or use it only transitively), so the scanner knows what exists and can skip or sample-scan it.

### Layer 7 — Application

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **Web applications (in-house)** | Custom portals, banking apps, ERPs | On-prem, cloud, SaaS vendors | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket | TLS, JWT, session signing, form encryption | Yes |
| **Web applications (3rd-party)** | Salesforce, Workday, ServiceNow, M365 | Vendor SaaS | HTTPS, SAML POST/Redirect, OIDC | TLS to vendor, SSO via SAML/OIDC | Partially (TLS only) |
| **APIs (REST/GraphQL/gRPC)** | Internal microservices, partner APIs | Cloud, on-prem, edge | HTTP/1.1, HTTP/2, gRPC (HTTP/2), GraphQL over HTTP | TLS, mTLS, JWT/JWS, OAuth2 | Yes |
| **3rd-party microservices** | Payment gateways (Stripe, Razorpay), Twilio, SendGrid, mapping APIs | Vendor SaaS / cloud | HTTPS (REST), gRPC, Webhook callbacks | TLS, API key auth, OAuth2, HMAC signatures | Partially (TLS + auth) |
| **3rd-party APIs** | External data providers, enrichment services, CRM integrations | Vendor SaaS | HTTPS (REST), WebSocket, gRPC | TLS, API key, OAuth2, HMAC | Partially (TLS only) |
| **SaaS config surfaces** | Okta, Auth0, Entra ID | Vendor SaaS | HTTPS (admin API) | Signing keys, SAML certs | Yes (key rotation monitoring) |
| **Email (S/MIME)** | Outlook, Gmail, internal mail | Endpoint, gateway | SMTP, SMTPS, IMAP, IMAPS, EWS, MAPI | S/MIME signing, DKIM, PGP | Yes |
| **Load balancers (L7)** | Nginx, HAProxy, AWS ALB, Cloudflare LB | Edge, cloud | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC pass-through | TLS termination, header inspection, WAF | Yes (TLS termination point) |
| **CDN / Edge** | Cloudflare, Akamai, AWS CloudFront, Fastly | Edge | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) | TLS termination, cert management | Yes (edge TLS) |
| **Webhooks (inbound)** | Stripe webhooks, GitHub webhooks, partner callbacks | Cloud, on-prem | HTTPS POST, HMAC signature verification | TLS, HMAC-SHA256 verification | Yes (signature verification) |
| **Message queues (app-level)** | RabbitMQ (AMQP), Apache Kafka, AWS SQS, Azure Service Bus | Cloud, on-prem | AMQP, Kafka protocol, HTTPS (SQS), SBMS (AMQP over TLS) | TLS in transit, SASL auth, HMAC (SQS) | Partially (TLS config) |
| **Caching layers** | Redis, Memcached, AWS ElastiCache, Azure Cache | Cloud, on-prem | Redis protocol, Memcached protocol, HTTPS (cloud API) | TLS in transit (Redis AUTH + TLS), AES at-rest (Redis 6+), IAM auth (cloud) | Partially (TLS config) |
| **Database connections** | App → DB connections (PostgreSQL, MySQL, Oracle, MSSQL) | On-prem, cloud | PostgreSQL wire, MySQL wire, TDS (MSSQL), Oracle TNS, HTTPS (cloud DB API) | TLS (DBSS), mTLS, TDE, password auth | Yes (DB TLS + TDE) |
| **Static content / file servers** | Apache httpd, IIS static hosting, S3 static website | Cloud, on-prem | HTTP/1.1, HTTP/2 | TLS (if HTTPS), basic auth | Low priority (TLS only) |
| **Web servers** | Nginx, Apache httpd, IIS, Caddy, LiteSpeed | On-prem, cloud | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC proxy | TLS termination, cert management, OCSP stapling | Yes (primary TLS termination point) |
| **Service mesh (L7 proxy)** | Istio Envoy sidecar, Linkerd proxy, Consul Connect | Kubernetes, VM | HTTP/1.1, HTTP/2, gRPC | mTLS, JWT validation, authz policies | Yes |
| **Authentication gateways** | Keycloak, Okta Access Gateway, Azure AD App Proxy | Cloud, on-prem | HTTPS, SAML, OIDC, OAuth2 | TLS, SAML signing, OIDC signing, mTLS | Yes |
| **Container orchestration (app-level)** | Kubernetes API server, Docker daemon, containerd | Cloud, on-prem | HTTPS (K8s API), gRPC (containerd), Docker API over TLS | TLS, client cert auth, admission webhooks | Yes (K8s API TLS) |

### Layer 6 — Presentation

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **Serialization frameworks** | Protocol Buffers, Avro, Thrift, JSON Web Encryption | Application runtime | gRPC (HTTP/2), Thrift binary, Avro over Kafka | Field-level encryption, JWE | Yes (via SAST/SBOM) |
| **Encoding libraries** | Apache Commons Codec, BouncyCastle | Application runtime | N/A (library-level) | Encoding that wraps crypto | Yes (SBOM) |
| **Image/document processing** | LibreOffice, ImageMagick, PDF parsers | Application runtime | N/A (library-level) | Parsing embedded encryption (PDF encryption, encrypted docs) | Low priority (rarely direct crypto) |
| **Compression libraries** | zlib, gzip, zstd, Brotli | Application runtime | N/A (library-level) | None (compression, not crypto) | No |
| **Logging frameworks** | Log4j, Serilog, Winston | Application runtime | Syslog, HTTPS (log shipping), Kafka (log streaming) | TLS in transit, HMAC (integrity) | Low priority |

### Layer 5 — Session

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **Session managers** | Redis sessions, JWT issuers, SAML IdP | Cloud, on-prem | HTTP/HTTPS, Redis protocol, SAML over HTTPS | Signing, session token crypto | Yes |
| **SSO / federation gateways** | Okta, ADFS, PingFederate, Keycloak | Cloud, on-prem | HTTPS, SAML, OIDC, OAuth2 | SAML signing, OIDC signing, mTLS | Yes |
| **RPC frameworks** | gRPC, Thrift, RMI | Application runtime | gRPC (HTTP/2), Thrift binary, RMI over TCP | mTLS, channel encryption | Yes (via SBOM) |
| **WebSocket servers** | Socket.IO, ws, SignalR | Application runtime | WebSocket (ws:// or wss://) | TLS (wss://), JWT auth | Yes (if wss://) |
| **VPN clients / tunnels** | OpenVPN, WireGuard, IPsec client, SSL VPN (AnyConnect) | Endpoint | OpenVPN (TLS over UDP), WireGuard (UDP), IPsec (ESP), DTLS (AnyConnect) | TLS, ChaCha20-Poly1305 (WireGuard), IKEv2, ESP | Yes |
| **DNS resolvers (internal)** | BIND, Unbound, Windows DNS, dnsmasq | On-prem, cloud | DNS (UDP/53, TCP/53), DNS over HTTPS (DoH), DNS over TLS (DoT) | DNSSEC validation (if enabled), DoH/DoT TLS | Partially (if DoH/DoT or DNSSEC) |
| **Network proxies (forward)** | Squid, Zscaler, Blue Coat, Palo Alto GlobalProtect | Edge, on-prem | HTTP CONNECT, HTTPS tunneling | TLS interception (MITB), TLS in transit | Yes (TLS interception point) |

### Layer 4 — Transport

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **TLS terminators** | Nginx, HAProxy, F5 BIG-IP, AWS ALB, Cloudflare | Edge, DMZ, cloud | TCP (underlying), TLS handshake | TLS handshake, certs, cipher suites | Yes (high priority) |
| **Load balancers with TLS** | Same as above | Edge | TCP, TLS | Same as above | Yes |
| **Service mesh sidecars** | Istio, Linkerd | Kubernetes | TCP, TLS | mTLS, cert rotation | Yes |
| **API gateways** | Kong, Apigee, AWS API Gateway | Edge, cloud | HTTP/HTTPS, gRPC, WebSocket | TLS, JWT validation, mTLS | Yes |
| **TCP/UDP load balancers** | AWS NLB, GCP LB, F5 LTM | Edge, cloud | TCP, UDP | None (L4 pass-through) | No (transparent, no crypto termination) |
| **NAT devices** | Enterprise NAT gateways, cloud NAT | Edge, cloud | TCP, UDP, ICMP | None (address translation only) | No |
| **TCP/IP stack (kernel)** | OS kernel networking (Linux, Windows) | Every host | TCP, UDP, ICMP, SCTP | TCP MD5 option (BGP), TCP-AO | No (kernel-level, not user crypto) |

### Layer 3 — Network

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **IPsec VPN gateways** | Cisco ASA, Palo Alto, pfSense, strongSwan | Edge, on-prem | IPsec (IKEv2, ESP), UDP/500, UDP/4500 | IKEv2, ESP, RSA/ECDSA | Yes (PQC migration is complex) |
| **BGPsec implementations** | Router firmware, ISP edge | ISP, large enterprise edge | BGP (TCP/179), BGPsec | BGPsec signatures | Limited (mostly out of scope) |
| **DNSSEC validators** | BIND, Unbound, Windows DNS | Internal DNS, ISP | DNS (UDP/53, TCP/53) | DSA/ECDSA signing keys | Yes (DNSSEC key inventory) |
| **Routers with MACsec** | Enterprise switches/routers | Network core | Ethernet (802.1AE) | MACsec key agreement | Limited (rare) |
| **Routers (standard)** | Cisco ISR, Juniper MX, Arista | Network core, edge | OSPF, EIGRP, BGP, static routes | OSPF MD5 auth, BGP MD5, TCP-AO | No (routing auth, not PQC-relevant) |
| **Firewalls (stateful)** | Palo Alto, Fortinet, Check Point, Cisco ASA | Edge, DMZ, internal | TCP, UDP, ICMP, application-layer inspection | TLS inspection (if enabled), IPsec | Partially (if TLS inspection enabled) |
| **SD-WAN controllers** | Viptela, Silver Peak, Fortinet SD-WAN | Edge, cloud | IPsec tunnels, VXLAN, GRE, proprietary overlay | IPsec, AES-GCM (overlay encryption) | Yes (IPsec tunnels) |
| **Load balancers (L3/L4)** | F5 LTM, AWS NLB, MetalLB | Edge, data center | TCP, UDP | None (L4 pass-through) | No |
| **ICMP / ping** | Standard network utility | Every host | ICMPv4, ICMPv6 | None | No |
| **VLAN / VXLAN / GRE** | Enterprise network overlays | Network core | 802.1Q (VLAN), VXLAN (UDP/4789), GRE | None (clear-text encapsulation) | No (no crypto) |
| **Multicast routing** | PIM, IGMP | Network core | IP multicast, PIM-SM/SSM | None | No |

### Layer 2 — Data Link

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **802.1X authenticators** | Switches, Wi-Fi controllers (Cisco ISE, Aruba ClearPass) | Network access layer | 802.1X (EAP over LAN), RADIUS (UDP/1812) | EAP-TLS, RADIUS, cert-based auth | Yes (RADIUS/TLS certs) |
| **MACsec devices** | Switches with MACsec | Data center, campus | Ethernet (802.1AE) | MACsec | Limited |
| **Wi-Fi (WPA3-Enterprise)** | Enterprise APs | Campus, branch | IEEE 802.11, 802.1X, RADIUS | 802.1X with certs, SAE | Yes (RADIUS) |
| **Wi-Fi (WPA2/WPA3-Personal)** | Home/small office APs | Branch, remote | IEEE 802.11, PSK | WPA2-PSK (AES-CCMP), WPA3-SAE | No (PSK, not cert-based) |
| **Switches (standard)** | Cisco Catalyst, Aruba, Juniper EX | Campus, data center | Ethernet (802.3), LLDP, CDP, STP | None (clear-text L2) | No |
| **Hubs / repeaters** | Legacy network equipment | Legacy segments | Ethernet (802.3) | None | No |
| **ARP / NDP** | Standard L2 protocols | Every L2 segment | ARP (IPv4), NDP (IPv6) | None (or SEcure Neighbor Discovery, rarely used) | No |
| **VLAN tagging** | 802.1Q | Campus, data center | 802.1Q | None (clear-text tag) | No |

### Layer 1 — Physical

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **Hardware Security Modules (HSM)** | Thales Luna, Entrust nShield, AWS CloudHSM | Data center, cloud | PKCS#11, vendor-specific API, KMIP | Key storage, signing operations | Yes — high priority |
| **TPM chips** | Endpoint devices, servers | Every modern endpoint | TPM 2.0 TSS, vendor API | Disk encryption keys, attestation | Yes — high priority |
| **Smart cards / PIV** | User endpoints, secure rooms | Physical (ISO 7816) | PIV, PKCS#11, contact/contactless | User auth, signing | Yes — slow to migrate |
| **Secure Boot / UEFI firmware** | Every modern device | Endpoint firmware | UEFI Secure Boot | Boot integrity chain | Yes — firmware crypto |
| **Hardware tokens (FIDO2/YubiKey)** | User endpoints | Physical (USB, NFC) | FIDO2/WebAuthn, CTAP2 | Authentication, signing | Yes — firmware version |
| **Fibre Channel switches** | Brocade, Cisco MDS | Data center SAN | Fibre Channel (FC-SW, FC-SP) | FC-SP (DH-CHAP), rarely enabled | No (rarely uses crypto) |
| **Serial / console access** | Serial ports, USB console cables | On-prem | RS-232, USB serial | None (clear-text) | No |
| **KVM switches** | Physical KVM over IP | Data center | KVM over IP, some with HTTPS | TLS (if KVM over IP with HTTPS) | Low priority |
| **Physical access control** | Badge readers, biometric scanners | Physical | Wiegand, OSDP, proprietary | OSDP v2 (AES-128 for secure channel) | No (physical security, not network crypto) |
| **Power / environmental monitoring** | PDU, UPS, environmental sensors | Data center | SNMP, Modbus, HTTP | SNMPv3 auth/privacy (if configured) | No (rarely PQC-relevant) |

### Cross-layer (cross-cutting)

| Component | Example | Where located | Protocol Used | Crypto used | Scan? |
|---|---|---|---|---|---|
| **Source code repositories** | GitHub Enterprise, GitLab, Bitbucket | Cloud, on-prem | HTTPS (REST API), SSH (git clone), Git protocol | Crypto API calls, hardcoded keys | Yes (SAST) |
| **Build pipelines** | Jenkins, GitHub Actions, GitLab CI, Argo | Cloud, on-prem | HTTPS (API), SSH (runner), Git | Build-time crypto, signing | Yes |
| **Container images** | Docker Hub, ECR, GCR, ACR | Cloud | HTTPS (registry API), Docker protocol | Bundled crypto libraries | Yes (SBOM) |
| **Certificate Authorities** | AD CS, EJBCA, AWS Private CA, Vault PKI | On-prem, cloud | LDAP (AD CS), HTTPS (EJBCA, AWS PCA, Vault), SCEP, EST, CMP | Issuing certs, signing chains | Yes — backbone |
| **Key Management Systems** | HashiCorp Vault, AWS KMS, Azure Key Vault, GCP KMS | On-prem, cloud | HTTPS (API), gRPC (Vault), KMIP | Symmetric + asymmetric key storage | Yes — high priority |
| **HSMs (cloud-managed)** | AWS CloudHSM, Azure Dedicated HSM | Cloud | PKCS#11, vendor API, KMIP | FIPS 140-2/3 key protection | Yes — high priority |
| **Database TDE** | Oracle, MSSQL, PostgreSQL pgcrypto | On-prem, cloud | DB wire protocol (TLS), cloud API | At-rest encryption | Yes |
| **Identity providers** | AD/Entra ID, Okta, Auth0, Keycloak | Cloud, on-prem | LDAP, LDAPS, HTTPS, SAML, OIDC, OAuth2 | User identity, signing keys | Yes |
| **SaaS / cloud provider crypto** | AWS ACM, Azure Front Door, Cloudflare | Cloud | HTTPS (admin API), ACME (cert provisioning) | TLS, cert management | Yes |
| **Secrets managers** | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault Secrets | Cloud, on-prem | HTTPS (API), gRPC (Vault) | Secret encryption (envelope encryption), TLS | Yes |
| **Configuration management** | Ansible, Chef, Puppet, SaltStack | On-prem, cloud | SSH, HTTPS, proprietary | TLS in transit, signed configs | Low priority |
| **Monitoring / logging** | Prometheus, Grafana, ELK, Splunk, Datadog | Cloud, on-prem | HTTPS, Prometheus scrape (HTTP), Syslog (TLS/UDP), Kafka | TLS in transit, API token auth | Low priority (TLS config only) |
| **Backup systems** | Veeam, Commvault, AWS Backup, Azure Backup | Cloud, on-prem | HTTPS (API), proprietary protocol, S3 API | TLS in transit, AES at-rest (backup encryption) | Partially (if encrypted backups) |
| **Container registries** | Docker Hub, ECR, GCR, Harbor, Nexus | Cloud, on-prem | HTTPS (Docker registry API v2), OCI distribution | TLS, image signing (Cosign, Notary) | Yes (image signing) |
| **Artifact repositories** | Nexus, Artifactory, GitHub Packages | Cloud, on-prem | HTTPS (REST API) | TLS, API token auth, signed artifacts | Low priority (TLS config) |
| **CI/CD runners** | GitHub Actions runners, GitLab runners, Jenkins agents | Cloud, on-prem | HTTPS (API), SSH, Git | TLS, runner authentication | Low priority |
| **Email infrastructure** | Exchange, Postfix, Sendmail, M365, Gmail | Cloud, on-prem | SMTP, SMTPS, IMAP, IMAPS, EWS, MAPI, Exchange ActiveSync | TLS (STARTTLS, implicit TLS), DKIM, SPF, DMARC | Yes (TLS + DKIM) |
| **LDAP / directory services** | Active Directory, OpenLDAP, FreeIPA | On-prem, cloud | LDAP, LDAPS (TCP/636), LDAP over StartTLS (TCP/389) | TLS (LDAPS), Kerberos (AES, RC4) | Yes (LDAPS + Kerberos) |
| **Kerberos KDC** | AD DC, MIT Kerberos, FreeIPA | On-prem | Kerberos (TCP/88, UDP/88) | AES-256-CTS-HMAC-SHA1, RC4-HMAC (legacy) | Yes (Kerberos crypto) |
| **NTP servers** | Chrony, NTPd, Windows Time Service, cloud NTP | On-prem, cloud | NTP (UDP/123), NTS (Network Time Security) | NTS (TLS-based time authentication) | No (rarely uses crypto) |
| **SNMP management** | Nagios, Zabbix, PRTG, SolarWinds | On-prem, cloud | SNMPv1/v2c (UDP/161), SNMPv3 | SNMPv3 auth/privacy (AES, DES, HMAC) | No (rarely PQC-relevant) |
| **Syslog servers** | rsyslog, syslog-ng, Splunk HF | On-prem, cloud | Syslog (UDP/514, TCP/514), Syslog over TLS (TCP/6514) | TLS (if syslog over TLS) | Low priority (TLS config) |
| **Remote access / admin** | SSH, RDP, VNC, TeamViewer, AnyDesk | On-prem, cloud | SSH (TCP/22), RDP (TCP/3389), VNC (TCP/5900+), proprietary | SSH (key exchange, host key), RDP (TLS, NLA), VNC (TLS optional) | Yes (SSH + RDP TLS) |
| **File transfer** | SFTP, FTPS, SCP, AWS S3, NFS, SMB | On-prem, cloud | SFTP (SSH), FTPS (FTP+TLS), SCP (SSH), S3 (HTTPS), NFSv4 (RPCSEC_GSS), SMB (SMB 3.0+ encryption) | TLS, SSH, Kerberos, AES | Yes (SFTP/FTPS/SMB encryption) |

### Key Insight

Every layer has crypto, and each layer has its own component types in its own hosting location. A complete PQC inventory must touch all of them. The layers that contribute the most to the total crypto surface, in order, are: **Application (Layer 7), Transport (Layer 4), Cross-layer cloud/SaaS, and Physical/cross-cutting (Layer 1)**. The layers that contribute least are the pure network/link layers (2 and 3) except for IPsec, DNSSEC, and 802.1X.

Components without crypto (TCP/UDP load balancers, NAT, switches, hubs, physical access control, NTP, SNMP) are **not PQC-relevant** but are listed so the scanner can explicitly exclude them and reduce noise.

---

## 1A. Deep Dive — Web Application Data Flow (Layer 7)

This section traces the full data flow from a user's browser through every hop to the database and back, identifying every protocol and crypto boundary at each step. This is the single most important path to understand for PQC because it touches the highest volume of encrypted traffic in most enterprises.

### The Complete Web Request Path

```
User Browser
    │
    │ ① HTTPS (TLS 1.2/1.3)
    │    Client Hello → Server Hello
    │    Key Exchange: X25519 / ECDHE / (future: ML-KEM-768)
    │    Cipher: AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305
    │    Cert: RSA-2048 / ECDSA-P256 / (future: ML-DSA-44)
    ▼
CDN / WAF (Cloudflare, Akamai, AWS CloudFront)
    │
    │ ② HTTPS / HTTP/2 / HTTP/3 (QUIC)
    │    TLS termination or pass-through
    │    WAF inspection (TLS decryption → re-encryption)
    │    Cert: Same as above
    ▼
Load Balancer (L7) — Nginx, HAProxy, AWS ALB, F5
    │
    │ ③ HTTP/2 or HTTP/1.1 (internal)
    │    May re-terminate TLS (mTLS to backend)
    │    Or pass-through (TLS termination at web server)
    │    Protocol: HTTP/2, HTTP/1.1, WebSocket, gRPC
    ▼
Web Server — Nginx, Apache, IIS, Caddy
    │
    │ ④ Internal (in-process or localhost)
    │    Application code receives request
    │    Session token: JWT (signed RS256/ES256) or opaque session ID
    │    Cookie: Secure, HttpOnly, SameSite
    │
    ├─────────────────────────────────────────────────┐
    │                                                 │
    │ ⑤a TLS to database                               │ ⑤b TLS to cache
    │    PostgreSQL: sslmode=verify-full               │    Redis: --tls
    │    MySQL: --ssl-mode=REQUIRED                    │    REDIS-cli --tls
    │    MSSQL: Encrypt=True                           │    Memcached: no native TLS
    │    Oracle: TCPS                                  │    ElastiCache: in-transit encryption
    │    mTLS: client cert auth                        │
    │                                                 │
    ▼                                                 ▼
Database — PostgreSQL, MySQL, Oracle, MSSQL        Cache — Redis, Memcached, ElastiCache
    │                                                 │
    │ ⑥ TDE (Transparent Data Encryption)             │ ⑥ AES at-rest (Redis 6+)
    │    Oracle TDE: AES-256                           │    AES-256-GCM (if configured)
    │    MSSQL TDE: AES-256                            │    AUTH + TLS in transit
    │    PostgreSQL pgcrypto: AES-256                   │
    │    MySQL InnoDB: AES-256                          │
    │                                                 │
    │ ⑦ Replication (if cluster)                       │ ⑦ Replication TLS
    │    PostgreSQL streaming: TLS                     │    Redis replication: TLS
    │    MySQL replication: TLS                        │    Sentinel TLS
    │    Oracle Data Guard: TLS                        │
    ▼                                                 │
Persistent Storage (disk)                            ▼
    AES-256 (LUKS, BitLocker, dm-crypt)          Persistent Storage
                                                  AES-256 (disk-level)
```

### Hop-by-Hop Protocol and Crypto Analysis

| Hop | Component | Protocol Used | Crypto / Key Exchange | PQC Concern |
|---|---|---|---|---|
| ① | **Browser → CDN/WAF** | HTTPS (TLS 1.2/1.3 over TCP/443), HTTP/3 (QUIC over UDP/443) | **KEX**: X25519, ECDHE (P-256, X25519); **Sig**: RSA-2048, ECDSA-P256; **Cipher**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | **HIGH** — Most exposed. ML-KEM-768 (X25519MLKEM768) for KEX; ML-DSA-44 for signatures. Harvest-now-decrypt-later risk. |
| ② | **CDN/WAF → Origin** | HTTPS (TLS 1.2/1.3), HTTP/2, HTTP/3 | Same as above (CDN re-terminates) | **HIGH** — CDN must support PQC before origin does. Cloudflare/Akamai currently do not offer PQC TLS. |
| ③ | **CDN → Load Balancer** | HTTP/2, HTTP/1.1, gRPC, WebSocket | TLS (mTLS if service mesh); internal traffic may be clear-text | **MEDIUM** — If internal, lower risk. If mTLS, needs PQC KEX. |
| ④ | **Load Balancer → Web Server** | HTTP/2, HTTP/1.1, WebSocket, gRPC | TLS (mTLS in service mesh), JWT validation, cookie signing | **MEDIUM** — Web server TLS config (OpenSSL version) determines PQC readiness. |
| ⑤a | **Web Server → Database** | PostgreSQL wire (TCP/5432 + SSL), MySQL wire (TCP/3306 + SSL), TDS (MSSQL, TCP/1433 + TLS), Oracle TNS (TCP/1521 + TCPS) | **TLS 1.2/1.3** (DBSS — Database SSL), mTLS (client cert), password auth over TLS | **MEDIUM** — Database TLS is internal but long-lived connections. TDE at-rest is symmetric (AES-256, not PQC-relevant for key exchange). |
| ⑤b | **Web Server → Cache** | Redis protocol (TCP/6379 + TLS, or Unix socket), Memcached protocol (TCP/11211, no native TLS), cloud cache API (HTTPS) | **Redis**: AUTH + TLS 1.2/1.3; **Memcached**: no native crypto (rely on network isolation); **ElastiCache**: in-transit encryption (TLS) | **LOW-MEDIUM** — Redis TLS is internal. Memcached has no crypto (network isolation only). |
| ⑥a | **Database → Disk** | Internal I/O (file system) | **TDE**: AES-256 (AES-256-CBC or AES-256-XTS); key wrapped by KMS/DEK | **LOW** — AES-256 is symmetric, not affected by quantum (Grover's reduces to 128-bit, still safe). |
| ⑥b | **Cache → Disk** | Internal I/O (RDB/AOF persistence) | AES-256 (if encryption-at-rest enabled) | **LOW** — Same as above. |
| ⑦ | **Database/Cache Replication** | PostgreSQL streaming replication (TLS), MySQL replication (TLS), Redis replication (TLS) | TLS 1.2/1.3 (same as primary connection) | **MEDIUM** — Replication channels often overlooked; long-lived TLS sessions. |

### Third-Party Services in the Web Application Flow

| Third-Party Service | Protocol Used | Crypto Used | PQC Concern | Scanner Approach |
|---|---|---|---|---|
| **Payment gateways** (Stripe, Razorpay, PayPal) | HTTPS (REST API), Webhooks (HTTPS POST) | TLS 1.2/1.3, HMAC-SHA256 (webhook signatures), API key auth | **HIGH** — Harvest-now-decrypt-later for payment data. HMAC is symmetric (not affected). | External TLS scan of API endpoints; CT log monitoring for their certs; webhook signature verification audit |
| **Email/SMS providers** (SendGrid, Twilio, AWS SES) | HTTPS (REST API), SMTP (for email relay) | TLS 1.2/1.3, API key, OAuth2 | **MEDIUM** — Email content in transit; SMS is cleartext (no crypto). | External TLS scan; verify SMTP TLS enforcement |
| **Mapping/geolocation APIs** (Google Maps, Mapbox) | HTTPS (REST API) | TLS 1.2/1.3, API key | **LOW** — Public data, no PII | External TLS scan only |
| **CDN** (Cloudflare, Akamai, AWS CloudFront) | HTTPS (edge to origin), HTTP/3 (QUIC) | TLS 1.3, X25519 KEX, ECDSA certs | **HIGH** — Edge TLS terminates here; CDN must support PQC first | External TLS scan of edge; CT log monitoring |
| **Analytics/telemetry** (Google Analytics, Segment, Amplitude) | HTTPS (REST API, beacon) | TLS 1.2/1.3, API key | **LOW** — Telemetry data, not PII (usually) | External TLS scan only |
| **SSO / Identity providers** (Okta, Auth0, Entra ID) | HTTPS, SAML (POST/Redirect), OIDC, OAuth2 | TLS, SAML signing (RSA/ECDSA), OIDC JWT signing | **HIGH** — IdP signing keys are high-blast-radius. SAML assertion in transit. | Vendor admin API; CT log for SAML certs; key rotation monitoring |
| **CRM / ERP SaaS** (Salesforce, Workday, SAP) | HTTPS (REST/SOAP API), SAML/OIDC for SSO | TLS, SAML signing, OAuth2, API token | **MEDIUM** — Data in transit to vendor; SSO signing keys | External TLS scan; vendor admin API for cert inventory |
| **Storage / file hosting** (AWS S3, Azure Blob, GCS, Dropbox Business) | HTTPS (REST API), S3 API, SDK | TLS, AES-256 at-rest (SSE-S3, SSE-KMS, SSE-C), IAM auth | **MEDIUM** — At-rest encryption keys in KMS; in-transit TLS | Cloud API scan (bucket policies, encryption config); external TLS |
| **CI/CD platforms** (GitHub Actions, GitLab CI, CircleCI) | HTTPS (API), SSH (git), Git protocol | TLS, SSH host keys, API tokens, OIDC federation | **MEDIUM** — Build pipeline secrets; signed commits | External TLS scan; code repo API for signing config |
| **Container registries** (Docker Hub, ECR, GCR, ACR) | HTTPS (Docker Registry API v2) | TLS, image signing (Cosign, Notary v2), access tokens | **MEDIUM** — Image integrity; TLS in transit | External TLS scan; cloud API for image signing config |
| **Logging / monitoring SaaS** (Datadog, Splunk Cloud, New Relic) | HTTPS (API), agent-to-cloud (TLS), Syslog over TLS | TLS, API tokens, mTLS (agent) | **LOW** — Observability data, not PII | External TLS scan only |

### Web Server Deep Dive

The web server is the **primary TLS termination point** and the most critical component for PQC readiness.

| Aspect | Detail |
|---|---|
| **Primary role** | Terminate TLS, serve HTTP/2 or HTTP/3, proxy to application backends |
| **Common software** | Nginx, Apache httpd, IIS, Caddy, LiteSpeed, Envoy (as reverse proxy) |
| **Crypto libraries** | OpenSSL (most common), BoringSSL (Google), LibreSSL (OpenBSD), Windows SChannel (IIS), BoringCrypto (Go-based) |
| **PQC readiness depends on** | OpenSSL version: **1.1.1** (no PQC, EOL Sep 2023), **3.0 LTS** (no PQC by default, experimental), **3.5+** (ML-KEM support via provider), **BoringSSL** (ML-KEM-768 support) |
| **TLS handshake observed** | `sslyze --cert_info --cipher suites --tls13_kex_groups <host>` — reveals KEX groups, cert chain, signature algorithms |
| **Config location** | `nginx.conf` (`ssl_ecdh_curve`, `ssl_protocols`, `ssl_ciphers`), Apache `ssl.conf`, IIS SChannel registry |
| **Common misconfigurations** | TLS 1.0/1.1 still enabled; weak cipher suites (3DES, RC4); self-signed certs; missing OCSP stapling |
| **PQC migration path** | Upgrade OpenSSL → 3.5+, enable ML-KEM-768 in KEX group config, reissue certs with ML-DSA-44, test hybrid KEX negotiation |
| **Scanner check** | Active TLS handshake (sslyze) + config file audit (read `nginx.conf` or equivalent) |

### Web Server → Database Encryption

| Database | Connection Protocol | TLS Enforcement | TDE (At-Rest) | PQC Concern |
|---|---|---|---|---|
| **PostgreSQL** | PostgreSQL wire (TCP/5432) + SSL | `sslmode=verify-full` (best), `require` (TLS but no cert verify), `allow`/`prefer` (may fallback to plaintext) | pgcrypto extension, AES-256 | **MEDIUM** — TLS in transit; TDE is symmetric AES (not PQC-critical for KEX) |
| **MySQL** | MySQL wire (TCP/3306) + SSL | `--ssl-mode=REQUIRED` or `VERIFY_IDENTITY` | InnoDB tablespace encryption (AES-256) | **MEDIUM** — Same as above |
| **MSSQL** | TDS (Tabular Data Stream, TCP/1433) + TLS | `Encrypt=True` in connection string;强制 TLS | TDE (AES-256, certificate-based DEK) | **MEDIUM** — Same as above |
| **Oracle** | Oracle Net Services (TNS, TCP/1521) + TCPS | `TCPS` listener, `SQLNET.ENCRYPTION_CLIENT=REQUIRED` | TDE (AES-256, TDE tablespace encryption) | **MEDIUM** — Same as above |
| **MongoDB** | MongoDB wire (TCP/27017) + TLS | `--tls`, `--tlsCertificateKeyFile` | WiredTiger encryption at rest (AES-256-CBC) | **MEDIUM** — Same as above |
| **Redis** (as DB) | Redis protocol (TCP/6379) + TLS | `--tls`, `tls-auth-clients optional/required` | RDB/AOF encryption at rest (Redis 6+) | **LOW** — Internal, typically no PQC concern |
| **Cloud-managed DB** | HTTPS (cloud API) + wire protocol | Cloud-enforced TLS (RDS强制 TLS, Cloud SQL强制 TLS) | KMS-managed TDE (AWS KMS, Azure Key Vault) | **MEDIUM** — KMS key wrapping; TLS termination at cloud LB |

**Key concern**: Many databases default to `prefer` TLS mode, which allows fallback to plaintext if the client doesn't support TLS. The scanner must verify that TLS is **强制** (required), not just preferred.

### Queuing Mechanisms

Message queues are critical infrastructure for async communication. They typically use TLS in transit but are often overlooked in PQC audits.

| Queue | Protocol Used | Crypto in Transit | Crypto at Rest | PQC Concern |
|---|---|---|---|---|
| **RabbitMQ** | AMQP 0.9.1 (TCP/5672), AMQP over TLS (TCP/5671), Management API (HTTPS, TCP/15671) | TLS 1.2/1.3 (if configured), SASL auth (PLAIN, AMPLAIN, EXTERNAL) | Message-level encryption optional; disk encryption via OS | **LOW-MEDIUM** — Internal queue; TLS config needs checking |
| **Apache Kafka** | Kafka binary protocol (TCP/9092), Kafka over TLS (TCP/9093) | TLS 1.2/1.3 (if `listeners=SSL`), SASL_SSL (SASL + TLS), mTLS | Disk encryption via OS; message-level encryption optional | **MEDIUM** — Kafka often carries sensitive data; TLS enforcement is critical |
| **AWS SQS** | HTTPS (REST API, TCP/443) | TLS 1.2 (AWS-managed) | SSE-SQS (AES-256, AWS-managed), SSE-KMS (customer KMS key) | **LOW** — AWS-managed TLS; SSE-KMS uses symmetric AES (not PQC-critical) |
| **Azure Service Bus** | AMQP over TLS (TCP/5671), HTTPS (REST API) | TLS 1.2 (Azure-managed) | Service-managed encryption (AES-256), customer-managed keys (CMK) | **LOW** — Same as above |
| **AWS SNS** | HTTPS (REST API) | TLS 1.2 (AWS-managed) | SSE-SNS (AES-256), SSE-KMS | **LOW** — Same as above |
| **Celery + Redis/RabbitMQ** | AMQP (RabbitMQ) or Redis protocol | TLS (if configured) | Depends on backend | **LOW** — Inherits backend's crypto |

**Scanner approach**: Check queue listener config for TLS enforcement; verify no plaintext fallback; check at-rest encryption config.

### Caching Mechanisms

Caches store frequently accessed data to reduce database load. Crypto relevance is typically low (internal traffic) but TLS should still be enforced.

| Cache | Protocol Used | Crypto in Transit | Crypto at Rest | PQC Concern |
|---|---|---|---|---|
| **Redis** (standalone) | Redis protocol (TCP/6379) | AUTH (plaintext password, or `AUTH` with TLS), TLS 1.2/1.3 (Redis 6+) | RDB/AOF encryption at rest (Redis 7+), OS disk encryption | **LOW** — Internal traffic; TLS config check only |
| **Redis Cluster** | Redis protocol (TCP/6379, inter-node TCP/16379) | TLS (if configured), cluster bus encryption | Same as standalone | **LOW** — Internal |
| **Redis Sentinel** | Redis protocol (TCP/26379) | TLS (if configured) | Sentinel doesn't store data | **LOW** — Internal |
| **Memcached** | Memcached protocol (TCP/11211) | **No native TLS** — relies on network isolation (VPN, VPC) | No encryption (in-memory only, no persistence) | **NO** — No crypto at all; network isolation is the only protection |
| **AWS ElastiCache (Redis)** | Redis protocol over TLS (managed) | TLS 1.2 (enforced by AWS) | At-rest encryption (AES-256, optional), in-transit encryption (TLS) | **LOW** — AWS-managed |
| **AWS ElastiCache (Memcached)** | Memcached protocol (managed) | In-transit encryption (TLS, optional) | No persistence (in-memory) | **LOW** — AWS-managed; TLS optional but recommended |
| **Azure Cache for Redis** | Redis protocol over TLS (managed) | TLS 1.2 (enforced) | At-rest encryption (AES-256, always on) | **LOW** — Azure-managed |
| **CDN cache** | HTTP/HTTPS (edge cache) | TLS (same as CDN edge) | In-memory at edge | **LOW** — Inherits CDN TLS |

**Scanner approach**: Check if TLS is enabled on cache connections; verify AUTH is configured; check cloud cache config for in-transit/in-transit encryption settings.

### SaaS Authentication Deep Dive

SaaS authentication is a critical crypto boundary. The IdP signs SAML assertions or OIDC JWTs, and the service provider validates them. A compromised IdP signing key = full impersonation.

| Component | Protocol Used | Crypto Used | PQC Concern | Scanner Approach |
|---|---|---|---|---|
| **Active Directory (AD)** | LDAP/LDAPS (TCP/389/636), Kerberos (TCP/88), DNS, Global Catalog (TCP/3268/3269) | LDAPS (TLS), Kerberos (AES-256-CTS-HMAC-SHA1, RC4-HMAC legacy), NTLM (MD5, legacy) | **HIGH** — Kerberos TGT signing, LDAPS TLS, AD CS cert issuance. RC4-HMD5 is quantum-vulnerable. | LDAP query for domain controllers; LDAPS handshake test; Kerberos encryption type enumeration |
| **Entra ID (Azure AD)** | HTTPS (REST API), SAML, OIDC, OAuth2 | TLS 1.2/1.3, SAML signing (RSA/ECDSA), OIDC JWT signing (RS256, ES256), token encryption | **HIGH** — IdP signing keys; SAML assertion in transit; token signing | External TLS scan; Entra ID admin API for signing key inventory; CT log for SAML certs |
| **Okta** | HTTPS (REST API), SAML, OIDC, OAuth2 | TLS 1.3, SAML signing, OIDC JWT signing, API token | **HIGH** — Same as above; Okta is a major IdP | External TLS scan; Okta admin API for app and key inventory |
| **Auth0** | HTTPS (REST API), SAML, OIDC, OAuth2 | TLS, SAML signing, OIDC JWT signing, HS256 (shared secret), RS256/ES256 | **HIGH** — Same as above | External TLS scan; Auth0 Management API |
| **Keycloak** | HTTPS (REST API), SAML, OIDC, OAuth2 | TLS, SAML signing, OIDC JWT signing, RSA/ECDSA | **HIGH** — Self-hosted IdP; key material is in customer's control | Agent or API scan; check Keycloak signing key config |
| **ADFS** | HTTPS (SAML), WS-Federation, OAuth2 | TLS, SAML signing (RSA/ECDSA), token signing cert | **HIGH** — ADFS signing cert is critical; cert rollover is common pain point | AD CS query for ADFS signing certs; ADFS PowerShell enumeration |
| **Credential managers** | HTTPS (API), desktop agent | TLS, AES-256 at-rest (Vault), HMAC integrity | **MEDIUM** — Credential vault is a high-value target; vault encryption is symmetric (not PQC-critical for KEX) | Vault API query for secrets engine config; check seal status and encryption type |
| **Certificate-based auth (mTLS)** | TLS (client cert) | Client cert: RSA/ECDSA, cert chain validation | **HIGH** — mTLS certs need PQC migration; both client and server sides | CT log monitoring; CA enumeration; cert inventory |
| **FIDO2/WebAuthn** | HTTPS (challenge-response), CTAP2 (USB/NFC) | Ed25519 (FIDO2), ECDSA (P-256), RSA (legacy) | **LOW-MEDIUM** — FIDO2 uses Ed25519 (not quantum-vulnerable); authenticator firmware update is the concern | Hardware token inventory; firmware version check |
| **OAuth2 / OIDC tokens** | HTTPS (token endpoint), Bearer token in Authorization header | TLS, JWT signing (RS256, ES256, PS256), HMAC (HS256 for confidential clients) | **HIGH** — JWT signing keys; token replay risk; refresh token rotation | IdP signing key inventory; token lifetime and rotation config |

### Authentication Flow Diagram (SAML SSO Example)

```
User Browser
    │
    │ ① Access app (https://app.example.com)
    ▼
Service Provider (SP) — the web application
    │
    │ ② Redirect to IdP with SAML AuthnRequest (HTTP Redirect/POST)
    │    Signed with SP's private key (RSA/ECDSA)
    │    Protocol: HTTPS redirect to IdP SSO URL
    ▼
Identity Provider (IdP) — Okta, Entra ID, ADFS, Keycloak
    │
    │ ③ User authenticates (password, MFA, certificate)
    │    IdP issues SAML Response with Assertion
    │    Assertion signed with IdP's private key (RSA/ECDSA)
    │    Assertion may be encrypted with SP's public key (RSA/OAEP)
    │    Protocol: HTTPS POST back to SP's ACS URL
    ▼
Service Provider (SP) — the web application
    │
    │ ④ SP validates SAML Assertion signature
    │    Checks IdP signing cert against trusted CA
    │    Creates session (JWT or opaque session ID)
    │    Crypto: RSA/ECDSA signature verification
    ▼
User is authenticated
    │
    │ ⑤ Subsequent requests use session token (JWT or cookie)
    │    JWT signed with SP's signing key (RS256/ES256)
    │    Protocol: HTTPS with cookie or Authorization header
    ▼
Application serves requests
```

**PQC impact on SAML SSO**:
- Step ②: SP's AuthnRequest signature → needs PQC signing key (ML-DSA-44)
- Step ③: IdP's Assertion signature → needs PQC signing key (ML-DSA-44)
- Step ③: Assertion encryption (if used) → needs PQC KEM (ML-KEM-768)
- Step ④: SP's signature verification → needs PQC verification key support
- TLS at every HTTPS hop → needs PQC KEX (ML-KEM-768)

### Authentication Flow Diagram (OIDC/OAuth2 Example)

```
User Browser
    │
    │ ① Access app (https://app.example.com)
    ▼
Application (Client)
    │
    │ ② Redirect to Authorization Server (AS) with OAuth2 Authorization Request
    │    Parameters: client_id, redirect_uri, scope, state, code_challenge (PKCE)
    │    Protocol: HTTPS redirect
    ▼
Authorization Server (Okta, Auth0, Entra ID)
    │
    │ ③ User authenticates (password, MFA, FIDO2)
    │    AS issues Authorization Code
    │    Protocol: HTTPS redirect back to app with code
    ▼
Application (Client)
    │
    │ ④ Exchange code for tokens at AS Token Endpoint
    │    POST to /token with code, client_id, client_secret, code_verifier (PKCE)
    │    AS returns: access_token (JWT), id_token (JWT), refresh_token
    │    JWTs signed with AS's private key (RS256, ES256, PS256)
    │    Protocol: HTTPS (server-to-server)
    ▼
Application (Client)
    │
    │ ⑤ Use access_token to call Resource Server (API)
    │    Authorization: Bearer <access_token>
    │    Resource Server validates JWT signature against AS's JWKS
    │    Protocol: HTTPS
    ▼
Resource Server (API)
    │
    │ ⑥ Validate JWT: check signature, expiry, issuer, audience
    │    Fetch JWKS from AS if not cached
    │    Crypto: RSA/ECDSA signature verification
    ▼
API Response
```

**PQC impact on OIDC/OAuth2**:
- Step ②: TLS to AS → needs PQC KEX
- Step ④: TLS to AS token endpoint → needs PQC KEX
- Step ④: JWT signing by AS → needs PQC signing key (ML-DSA-44)
- Step ⑤: TLS to Resource Server → needs PQC KEX
- Step ⑥: JWT signature verification → needs PQC verification key support
- JWKS endpoint: AS publishes public keys; must include PQC keys

### Summary: Complete Crypto Inventory for a Web Application

| Layer | Component | Protocol Used | Crypto Used | PQC Priority | Scanner Method |
|---|---|---|---|---|---|
| L7 | Web server (TLS termination) | HTTPS (TLS 1.2/1.3) | X25519/ECDHE KEX, RSA/ECDSA certs, AES-GCM | **HIGH** | Active TLS handshake (sslyze) + config audit |
| L7 | CDN / WAF | HTTPS, HTTP/3 (QUIC) | TLS 1.3, X25519, ECDSA | **HIGH** | External TLS scan + CT log |
| L7 | Application code | HTTP/2, gRPC, WebSocket | JWT signing (RS256/ES256), session crypto | **MEDIUM** | SAST + SBOM (crypto library versions) |
| L7 | 3rd-party APIs | HTTPS (REST) | TLS, OAuth2, HMAC | **MEDIUM** | External TLS scan + API auth audit |
| L7 | Email | SMTP/SMTPS, IMAP/IMAPS | STARTTLS, S/MIME, DKIM | **MEDIUM** | External TLS scan + DKIM check |
| L5 | IdP / SSO | HTTPS, SAML, OIDC | SAML signing, OIDC JWT signing | **HIGH** | IdP admin API + signing key inventory |
| L5 | Session manager | HTTPS, Redis protocol | JWT signing, session token crypto | **MEDIUM** | API query + config audit |
| L4 | Load balancer | TCP, TLS | TLS termination, cert management | **HIGH** | Active TLS handshake |
| L4 | API gateway | HTTPS, gRPC | TLS, JWT validation, mTLS | **HIGH** | Active TLS handshake + API audit |
| L4 | Service mesh | TCP, TLS | mTLS, cert rotation | **MEDIUM** | K8s API + mTLS probe |
| L3 | VPN / IPsec | IKEv2, ESP | IKEv2, ESP, RSA/ECDSA | **HIGH** | ike-scan + config audit |
| L3 | Firewall (TLS inspection) | TCP, TLS | TLS interception (MITB) | **MEDIUM** | Config audit (firewall admin API) |
| L2 | 802.1X / RADIUS | 802.1X, RADIUS (UDP/1812) | EAP-TLS, RADIUS | **LOW** | RADIUS server config audit |
| L1 | HSM | PKCS#11, KMIP | Key storage, signing | **HIGH** | PKCS#11 enumeration |
| L1 | TPM | TPM 2.0 TSS | Attestation, disk encryption keys | **HIGH** | Agent-based TPM query |
| Cross | CA / PKI | HTTPS, LDAP, SCEP, EST | Cert issuance, signing chains | **HIGH** | CA API + cert inventory |
| Cross | KMS | HTTPS (API) | Symmetric + asymmetric key storage | **HIGH** | Cloud KMS API |
| Cross | Database | DB wire protocol + TLS | TLS in transit, TDE (AES-256) | **MEDIUM** | DB config query + TLS probe |
| Cross | Cache (Redis) | Redis protocol + TLS | AUTH + TLS | **LOW** | Config audit |
| Cross | Queue (Kafka) | Kafka protocol + TLS | TLS, SASL | **LOW** | Config audit |

---

## 2. Where the Components Are Located (Hosting Model)

For a very large organization, the hosting model determines how you scan. The same component (e.g., a TLS endpoint) is scanned differently depending on where it lives.

| Hosting model | Examples | Protocol Used | Scanning approach |
|---|---|---|---|
| On-premises data center | Bare-metal servers, VMware, Hyper-V, KVM | SSH (TCP/22), WinRM (TCP/5985/5986), HTTPS (vCenter API) | Agent-based or SSH/WinRM remote exec |
| Private cloud | OpenStack, VMware vSphere, on-prem Kubernetes | HTTPS (OpenStack API, vCenter API, K8s API) | API-based + agent |
| Public cloud — IaaS | AWS EC2, Azure VMs, GCP Compute | HTTPS (cloud provider API) | Cloud provider API (AWS Config, Azure Resource Graph, GCP Asset Inventory) + agent |
| Public cloud — PaaS | AWS RDS, Azure App Service, GCP Cloud SQL | HTTPS (cloud provider API) | Cloud provider API; no agent access |
| Public cloud — SaaS | M365, Salesforce, Workday, Okta, ServiceNow | HTTPS (vendor admin API) | Vendor admin API only; no host access |
| Public cloud — serverless | AWS Lambda, Azure Functions | HTTPS (cloud provider API) | Cloud provider API; static analysis of deployment packages |
| Public cloud — containers | EKS, AKS, GKE, ECS, Fargate | HTTPS (K8s API), Docker Registry API (HTTPS) | K8s API + container image SBOM scan |
| 3rd-party vendor | Any external service your org uses | HTTPS (external) | External TLS scan + CT log monitoring + vendor questionnaires |
| Embedded / OT / IoT | PLCs, RTUs, network equipment, medical devices, vehicles | Proprietary protocols (Modbus, DNP3, BACnet), SSH, HTTPS (if web-managed) | Vendor firmware analysis + serial/SSH access where available |
| Endpoint devices | Laptops, desktops, mobile, BYOD | MDM API (HTTPS), agent communication (HTTPS) | MDM/UEM API + endpoint agent |
| Backup and archive | Tape libraries, object storage (S3 Glacier, Azure Archive) | S3 API (HTTPS), proprietary backup protocol | Encrypted at rest — scan catalog metadata |
| Partner / B2B | EDI gateways, partner APIs, SFTP servers | SFTP (SSH), EDI (AS2/HTTPS), partner API (HTTPS) | External TLS scan + protocol-specific probes |

### The Practical Implication

A scanner designed for one hosting model (e.g., on-prem network scan) gives you maybe 20-30% coverage in a typical large enterprise. The other 70-80% requires cloud APIs, K8s APIs, vendor admin APIs, and endpoint agents. This is the strongest argument for a CMDB-driven or CMDB-backed approach: the CMDB (or its cloud equivalents — AWS Config, Azure Resource Graph) already knows where everything lives, classified by hosting model.

---

## 3. Which Components Need to Be Scanned

For a presentation, the prioritization framework matters more than the exhaustive list. The rule is: **scan anything that holds, uses, transports, or signs a key. Defer or sample-scan anything that is only a transport for other components' data.**

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

### Out of Scope (Non-PQC-Relevant)

- Layer 1 physical security (cabinet locks, mantraps) — not cryptography
- Compliance attestations that don't require crypto (SOC 2 controls unrelated to crypto)
- **TCP/UDP load balancers (L4 pass-through)** — no crypto termination, just routing
- **NAT devices** — address translation only, no crypto
- **Standard switches and hubs** — clear-text L2, no crypto
- **DNS resolvers (without DoH/DoT/DNSSEC)** — standard DNS is unencrypted
- **NTP servers (without NTS)** — standard NTP is unencrypted
- **SNMP management** — rarely uses crypto; network management traffic
- **Compression libraries** — zlib, gzip, zstd, Brotli — no crypto
- **Physical access control** — badge readers, biometrics — physical security, not network crypto
- **Serial / console access** — RS-232, USB serial — clear-text
- **Standard routers (without IPsec/BGPsec)** — OSPF/EIGRP routing, not crypto
- **Fibre Channel switches** — SAN fabric, rarely uses crypto
- **VLAN / VXLAN / GRE** — network encapsulation, not encryption

---

## 4–10. (Sections 4–10 from v1 remain unchanged)

The following sections from v1 are carried forward without modification:

- **Section 4**: CMDB-Based PQC Scanner: Filter and Classify by Scanning Mechanism
- **Section 5**: No-CMDB: Build CMDB from Scratch
- **Section 6**: Normalized CMDB Connector — The Multi-Vendor Question
- **Section 7**: How Will Asset Discovery Happen?
- **Section 8**: How Will Scanning Happen?
- **Section 9**: What Credentials Are Required?
- **Section 10**: Agent vs Agentless — Where to Use Which?

Refer to `pqc-scanner-technical-strategy.md` (v1) for the full text of these sections.

---

## Summary for the Presentation

| Technical question | One-line answer |
|---|---|
| What components exist in a large org? | Every OSI layer has crypto-bearing components; 70-80% of the surface is at Layer 7 (apps), Layer 4 (TLS), and cross-layer cloud/SaaS. Non-crypto components (switches, NAT, hubs) are explicitly excluded to reduce scanner noise. |
| Where are they located? | On-prem, public cloud (IaaS/PaaS/SaaS/serverless), K8s, endpoints, vendor SaaS, OT/IoT, B2B partners. Each location needs a different scanning approach. |
| Which need scanning? | Anything that holds, uses, transports, or signs a key. Internet-facing TLS, PKI roots, HSMs, KMS, identity provider signing keys, and code signing are the highest priority. |
| What protocols are involved? | Every component uses specific protocols (HTTPS, TLS, SSH, SAML, OIDC, AMQP, Redis, DB wire protocols). The "Protocol Used" column identifies which protocols each component uses, enabling protocol-specific scanning. |
| How does web app data flow? | Browser → CDN/WAF → Load Balancer → Web Server → Database/Cache. Each hop has its own TLS boundary and crypto. Web server → DB uses DBSS (DB SSL). Cache (Redis) uses AUTH + TLS. Queues (Kafka, RabbitMQ) use TLS in transit. |
| How does SaaS authentication work? | SAML SSO: SP redirects to IdP → IdP signs assertion → SP validates. OIDC: App redirects to AS → AS issues JWT → API validates JWT. Both require PQC signing keys (ML-DSA-44) at IdP/AS, and PQC TLS at every HTTPS hop. |
| Can we use CMDB as source? | Yes — query CMDB, filter for crypto-relevant CIs, classify each CI by which scan mechanism applies, run the right scan, write findings back. |
| What if no CMDB? | Build the CMDB from scratch using the 6-phase rollout (public crypto → CAs → internal network → key stores → software/SBOM → code/cloud). Reconcile overlapping sources. |
| Can we normalize across CMDBs? | Yes — adapter framework with a common internal model aligned to CSDM/CDM (general asset) and CycloneDX CBOM (crypto). Each new CMDB vendor is a 200-800 line adapter. |
| How does asset discovery happen? | Multi-source: CMDB + cloud APIs + network probes + CT logs + CA/HSM/KMS APIs + code repo APIs + DNS + MDM. Reconciled into one asset graph, then filtered to crypto-relevant nodes. |
| How does scanning happen? | Per-CI scan selection: active TLS/SSH/IPsec probes, cert deep-parse, config audit, cloud KMS/secret scan, SBOM analysis, SAST, PQC capability assertion. Output is a structured finding, not a boolean. |
| What credentials are required? | Tiered least-privilege, 7 tiers (0-6): none for public scan; read-only service account for CMDB/CA/SSHD; local/domain admin for OS cert stores; HSM auditor partition; cloud read IAM; vendor API token; repo read PAT. No domain admin, no HSM crypto officer, no app admin. |
| Agent vs agentless — where to use which? | Agentless-first (covers ~80%): internet-facing, cloud, network devices, HSM/KMS/CA, code repos, K8s API, container registries, CT logs. Agents for the host-local long tail: endpoint disk encryption, local cert stores, TPM, installed crypto libs, process-level crypto, air-gapped/OT, continuous monitoring. Hybrid is the production default. |

The strategic message: a CMDB-agnostic, adapter-based PQC scanner is deployable into any customer's environment, regardless of which CMDB they run or whether they have one at all. That portability is the architectural moat.
