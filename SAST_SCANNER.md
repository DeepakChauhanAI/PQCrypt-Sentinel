# SAST Scanner

The SAST scanner is a native static-analysis connector that walks a local source tree and flags cryptographic usage with regex. It lives in `backend/app/connectors/sast_connector.py` and is invoked through the `/api/connectors/sync/sast` endpoint or the SAST card on the Connectors page.

## How it works

1. **Discovery** – The target directory is walked with `os.walk`, pruning any directory listed in `EXCLUDED_DIRS` (`node_modules`, `.git`, `__pycache__`, `.venv`, `target`, `build`, `dist`, etc.).
2. **Phased scanning** – For each language, files are enumerated (capped at 200 per pattern) and read as UTF-8 text. Regexes are applied with `re.IGNORECASE`. The phases run in this order:
   1. Python (`*.py`)
   2. Java (`*.java`)
   3. Go (`*.go`)
   4. JavaScript / TypeScript (`*.js`, `*.ts`, `*.jsx`, `*.tsx`, `*.mjs`, `*.cjs`)
   5. Dependency manifests (`requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `pom.xml`, `build.gradle*`, `go.mod`, `go.sum`, `package.json`, `yarn.lock`, `pnpm-lock.yaml`)
   6. Semgrep (`p/crypto`, `p/secrets`) if the binary is installed
   7. Container files (`Dockerfile`, `Containerfile`, `docker-compose*`)
   8. Kerberos config files (`krb5.conf`, `*.krb5`, `*kerberos*`)
3. **Findings** – Each match becomes a finding dict containing `file`, `line`, `category`, `pattern`, `code_snippet`, and `language`.
4. **Persistence** – The connector creates or updates one `Asset` named `sast:<target_folder>`, deletes any previous `Finding` rows for that asset+scan, then inserts new `Finding` rows. Every finding gets `finding_type=code_weak_crypto` (or `sbom_vulnerable_lib` for manifests), `severity=high`, `pqc_status=vulnerable`, `recommended_algorithm=ML-DSA-65`, and a risk score from `calculate_risk_score`. The asset’s `last_verified_at` is set to now.
5. **Logging** – A `ScanLog` row is written for each phase so the Live Execution Console shows progress.

## What it looks for

| Category | What it flags |
|---|---|
| `rsa_keygen` / `ec_keygen` / `dsa_keygen` / `dh_keygen` | Classical key generation (`RSA.generate`, `KeyPairGenerator.getInstance("RSA")`, `rsa.GenerateKey`, `generateKeyPair.*rsa`, etc.) |
| `weak_hash` | `hashlib.md5/sha1`, `MessageDigest.getInstance("MD5"/"SHA-1")`, `crypto/md5`, `crypto/sha1`, `createHash('md5'/'sha1')` |
| `weak_cipher` | `DES`/`DESede`/`RC4`/`Blowfish` references, `createCipher`/`createCipheriv` with those algorithm names, `crypto/des`, `crypto/rc4` |
| `hardcoded_key` | `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, etc. |
| `bouncycastle` / `pqc_libs` | `org.bouncycastle`, `org.bouncycastle.pqc`, `com.google.crypto.tink`, `golang.org/x/crypto/(kyber|dilithium|sphincs|falcon)`, `filippo.io/.*pqc` |
| `pqc_algorithms` | `ML-KEM`, `ML-DSA`, `SLH-DSA`, `MLKEM`, `MLDSA`, `SLHDSA`, `Kyber`, `Dilithium`, `Falcon`, `SPHINCS+`, `FrodoKEM`, `Classic McEliece`, `NTRU`, `BIKE`, `HQC` |
| `pqc_hybrid` | `X25519Kyber`, `X25519MLKEM`, `SecP256r1MLKEM`, `SecP384r1MLKEM1024` |
| `vulnerable_dependency` | Known-bad packages in manifests (`pycrypto`, `m2crypto`, `bcprov-jdk15on`, `node-rsa`, etc.) |
| `weak_base_image` / `insecure_container_package` / `weak_protocol_reference` | Old Ubuntu bases, `openssl-1.0`, `TLSv1`/`SSLv3` references in Dockerfiles |
| `weak_kerberos_encryption` / `weak_kerberos_encryption_policy` | `des-cbc-crc`, `rc4-hmac`, etc. in `krb5.conf` |

## PQC coverage

- **Libraries detected** – `oqs`, `liboqs`, `pqcrypto`, `open-quantum-safe`, `pqclean`, `noble-post-quantum`, `post-quantum`, `golang.org/x/crypto/(kyber|dilithium|sphincs|falcon)`, `filippo.io/.*pqc`, `org.bouncycastle.pqc`, `com.google.crypto.tink`.
- **Algorithm names detected** – All NIST FIPS 203/204/205 algorithms plus 4th-round candidates and common hybrids.
- **Status of PQC findings** – They are recorded with `category=pqc_libs` / `pqc_algorithms` / `pqc_hybrid`; the connector still tags them as `vulnerable` in the DB today (the registry is the source of truth for their proper `pqc_status`; the SAST connector does not currently cross-reference `pqc_algorithm_registry.json`).

## Limitations

- Regex-based only – no real AST parsing despite the docstring.
- 200-file cap per language/extension.
- The project’s `pqc_algorithm_registry.json` is the authoritative classification source, but the SAST connector does not load it; the `pqc_status` it writes is always `vulnerable`.
