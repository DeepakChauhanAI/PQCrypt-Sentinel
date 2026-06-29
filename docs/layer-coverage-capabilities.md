# PQCrypt Sentinel — Layer-Based Coverage Capabilities

> **Status:** Current as of v0.9.0
> **Scope:** Maps the existing scanners, connectors, and orchestrator hooks in
> `backend/app/scanners/` and `backend/app/connectors/` to the 7-layer
> infrastructure model used by the dashboard's `/api/v1/dashboard/layer-coverage`
> heatmap.

---

## 1. The 7-Layer Model

| Layer | Name | Description |
|-------|------|-------------|
| L1 | Network | TLS, SSH, VPN/IKEv2, DNSSEC, OCSP, SMTP STARTTLS |
| L2 | PKI | Root CA, Intermediate CAs, TLS Server Certs, Code-signing, TSA |
| L3 | HSM/KMS | General HSMs, Payment HSMs (3DES), Cloud KMS |
| L4 | Application | JWT Algorithms, Container Images, API Crypto |
| L5 | Data | TDE Algorithms, Backup Encryption, Column-level Encryption |
| L6 | Infrastructure | SSH Host Keys, Kerberos RC4, Windows CNG/Schannel |
| L7 | Endpoint | Windows Cert Store, BitLocker, Firmware Signing |

The mapping from `asset_type` / `discovery_source` to layer lives in
`backend/app/api/dashboard.py:258-304` (`ASSET_TO_LAYER`) and
`backend/app/services/layer_service.py:61-67`.

---

## 2. Capability Matrix

| Layer | Capability present | How to trigger it | Coverage notes |
|------|-------------------|------------------|----------------|
| **L1 Network** | TLS (`tls_scanner`, `sslyze_scanner`), SSH (`ssh_scanner`), IKEv2 (`ike_scanner`), SMTP STARTTLS (`mail_scanner`), DNSSEC + OCSP (`ocsp_dnssec_scanner`), passive pcap (`pyshark_capture`), nmap discovery (`network_discovery`) | `POST /api/v1/scans` with `scan_type=full` / `tls_only` / `ssh_only` / `targeted` / `passive`; `POST /api/v1/scans/{id}/l1-probe` for OCSP/DNSSEC | Complete |
| **L2 PKI** | CT-log monitor (`ct_log_scanner`), `cert_parser` for any cert, CA inventory via CSV/PEM upload (`csv_connector`), `ca_sync` handler inside `sast_connector` for code-signing certs, `vendor_pqc_db` for vendor readiness, ADCS via PKCS#11 connector (`adcs_ldap`) | `scan_type=ct_monitor`; `POST /api/v1/connectors/csv` to upload a CA bundle; `POST /api/v1/connectors/pkcs11` with `provider=adcs_ldap` | **Partial gap:** no dedicated TSA (time-stamping) scanner; no standalone code-signing cert scanner (relies on CA inventory + CT) |
| **L3 HSM/KMS** | `pkcs11_connector` (PKCS#11 HSM, KMIP, ADCS-LDAP), `cloud_kms_connector` (AWS KMS, Azure Key Vault, GCP KMS), `vault_helper` for creds | `POST /api/v1/connectors/{pkcs11,aws-kms,azure-kv,gcp-kms,kmip}` | Complete |
| **L4 Application** | `jwt_connector` (offline or endpoint), `sast_connector` (Semgrep source-code crypto audit incl. Kerberos config files), `k8s_connector` (cluster crypto config), `saml_connector` (SAML auth crypto), `git_secrets_connector` (git repo secret scanning) | `POST /api/v1/connectors/{jwt,sast,kubernetes,saml,git-secrets}` | **Partial gap:** `kubernetes_cluster` and `saml` aren't in `ASSET_TO_LAYER`, so their assets currently fall through to the L1 default (cosmetic dashboard bug) |
| **L5 Data** | `tde_connector` (Oracle TDE, SQL Server TDE) | `POST /api/v1/connectors/{oracle-tde,sqlserver-tde}` | **Gap:** no dedicated backup-encryption scanner (TDE only covers at-rest database encryption) |
| **L6 Infrastructure** | `ssh_connector` agentless inventory (host keys, OpenSSL, Kerberos config, TPM), `winrm_connector` (CNG/Schannel, IIS bindings, TPM), Kerberos config scanning inside `sast_connector` | `POST /api/v1/connectors/{ssh,winrm,sast}` | **Partial gap:** Kerberos RC4 detection is config-file only (`krb5.conf` audit), not an active AS-REQ/TGS-REQ capture |
| **L7 Endpoint** | `winstore_connector` (Windows cert store via `certutil` dump or live), `winrm_connector` (BitLocker status + UEFI/firmware + TPM info), `vendor_pqc_db` (HSM firmware PQC availability) | `POST /api/v1/connectors/{windows-cert-store,winrm}` | **Partial gap:** no active firmware-signing verifier — only inventory/UEFI metadata |

---

## 3. Underlying Modules

### Scanners (`backend/app/scanners/`)
| File | Used by | Layer contribution |
|------|---------|--------------------|
| `tls_scanner.py` | `scan_type=full` / `tls_only` / `targeted` | L1 |
| `sslyze_scanner.py` | `advanced_tools=True` TLS deep scan | L1 |
| `ssh_scanner.py` | `scan_type=full` / `ssh_only` / `targeted` | L1 |
| `ike_scanner.py` | `scan_type=targeted` (port 500) | L1 |
| `mail_scanner.py` | `scan_type=targeted` (ports 25/465/587) | L1 |
| `ocsp_dnssec_scanner.py` | `POST /scans/{id}/l1-probe` | L1 |
| `ct_log_scanner.py` | `scan_type=ct_monitor` | L2 |
| `cert_parser.py` | Helper for TLS/CSV/CA inventory | L1/L2 |
| `network_discovery.py` | CIDR / DNS enumeration during `scan_type=full` | L1 |
| `pyshark_capture.py` | `scan_type=passive` | L1 |
| `scapy_probe.py` | `advanced_tools=True` PQC group probe | L1 |
| `vendor_pqc_db.py` | Reference data, used by multiple modules | L2/L7 context |

### Connectors (`backend/app/connectors/`)
| File | Endpoint prefix | Layer contribution |
|------|-----------------|--------------------|
| `cloud_kms_connector.py` | `/connectors/{aws-kms,azure-kv,gcp-kms}` | L3 |
| `pkcs11_connector.py` | `/connectors/{pkcs11,kmip,adcs}` | L3 (and L2 via ADCS-LDAP) |
| `vault_helper.py` | (helper, no public endpoint) | L3 (cred injection) |
| `jwt_connector.py` | `/connectors/jwt` | L4 |
| `sast_connector.py` | `/connectors/sast` | L4 (and L6 Kerberos config + L2 code-signing via `ca_sync`) |
| `k8s_connector.py` | `/connectors/kubernetes` | L4 (defaulted to L1 in dashboard — see gap) |
| `saml_connector.py` | `/connectors/saml` | L4 (defaulted to L1 — see gap) |
| `vault_scanner.py` | `/connectors/vault-scanner` | L3 (enterprise secrets manager crypto inventory) |
| `git_secrets_connector.py` | `/connectors/git-secrets` | L4 (source-code / CI embedded secrets) |
| `tde_connector.py` | `/connectors/{oracle-tde,sqlserver-tde}` | L5 |
| `ssh_connector.py` | `/connectors/ssh` | L6 (and partial L1 SSH host inventory) |
| `winrm_connector.py` | `/connectors/winrm` | L6 + L7 (CNG/Schannel/BitLocker/firmware) |
| `winstore_connector.py` | `/connectors/windows-cert-store` | L7 |
| `csv_connector.py` | `/connectors/csv` | Any layer (depends on uploaded inventory) |

---

## 4. Known Gaps

1. **TSA (time-stamp authority)** — no module anywhere. Code-signing PKI
   timestamps cannot be validated or audited.
2. **Backup encryption** — no scanner. L5 currently relies solely on
   database TDE connectors; backup tapes / object-store / snapshot
   encryption is unaddressed.
3. **Active Kerberos RC4** — only static `krb5.conf` audit via
   `sast_connector` and `ssh_connector`. There is no AS-REQ / TGS-REQ
   crypto capture.
4. **Active code-signing verification** — relies on ingesting certs via
   CA inventory / ADCS / CT. No direct signature validation of binaries.
5. **Firmware signing verification** — only metadata collection from
   WinRM (Secure Boot, UEFI info). No actual signature check of firmware
   images.
6. **Layer-mapping gaps** — `kubernetes_cluster`, `saml`, and any
   unknown `asset_type` fall through to L1 by default
   (`_determine_layer_for_asset` in `dashboard.py:307`), which
   pollutes the L1 heatmap when K8s or SAML connectors are used.

---

## 5. Recommended Next Steps

- **Quick win:** add `kubernetes_cluster` → L4 and `saml` → L4 entries to
  `ASSET_TO_LAYER` (`backend/app/api/dashboard.py:258`) and
  `layer_service.py:61` to fix the L4 dashboard bucket.
- **Medium:** implement a TSA scanner module (`scanners/tsa_scanner.py`)
  that fetches TSA certificates, validates chains, and classifies
  signature algorithms through `cert_parser`.
- **Medium:** add a backup-encryption scanner that inventories backup
  software config (Veeam, Commvault, native DB RMAN) via the
  `csv_connector` schema extension or a new `backup_connector.py`.
- **Long-term:** add an active Kerberos scanner that performs an
  AS-REQ and inspects the returned encryption types to surface RC4 in
  use, not just configured.
- **Long-term:** add a firmware-signing verifier that downloads
  vendor firmware and checks detached signatures against the vendor
  PQC DB.
