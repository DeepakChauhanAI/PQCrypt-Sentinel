import asyncio
import logging
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from datetime import datetime, timezone
from itertools import islice
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset, ScanLog

logger = logging.getLogger(__name__)


class SASTConnector(BaseConnector):
    """
    Native SAST connector for crypto detection.
    Supports:
    - Python AST analysis (cryptography, pyca/cryptography, M2Crypto, liboqs, etc.)
    - Java AST analysis (JCA, BouncyCastle, etc.)
    - Go AST analysis (crypto/* packages)
    - JavaScript / TypeScript analysis (Node.js, React/JSX, browser crypto, PQC npm libs)
    - Dependency manifest scanning (requirements.txt, pom.xml, build.gradle, go.mod, package.json)
    """


    # Directories to skip entirely — these bloat the file tree and never contain project source.
    EXCLUDED_DIRS: Set[str] = {
        "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
        "target", "build", "dist", ".idea", ".vscode", ".tox", "vendor",
        "coverage", "htmlcov", ".pytest_cache", ".mypy_cache", ".eggs",
        "*.egg-info", ".terraform", ".next", ".nuxt", ".parcel-cache",
        ".gradle", "out", "bin", "obj", "Debug", "Release",
        "Pods", "DerivedData", "xcuserdata", ".hg", ".svn", "CVS",
        "site-packages", "dist-packages", "bower_components",
        ".yarn", ".pnpm-store", ".cache", "tmp", "temp", "logs",
    }

    # Python crypto patterns
    PYTHON_CRYPTO_PATTERNS = {
        "rsa_keygen": [r"RSA\.generate", r"RSA\.generate_private_key", r"generate_private_key.*RSA"],
        "ec_keygen": [r"EC\.generate", r"EllipticCurvePrivateKey", r"generate_private_key.*EC"],
        "dsa_keygen": [r"DSA\.generate", r"DSAParameterNumbers"],
        "dh_keygen": [r"DH\.generate", r"DHParameterNumbers"],
        "weak_hash": [r"hashlib\.(md5|sha1)\(", r"MD5\.new\(", r"SHA1\.new\("],
        "weak_cipher": [r"DES\.", r"TripleDES", r"3DES", r"RC4", r"ARC4", r"Blowfish"],
        "hardcoded_key": [r"PRIVATE KEY", r"BEGIN RSA PRIVATE KEY", r"BEGIN EC PRIVATE KEY"],
        "pqc_libs": [r"oqs", r"liboqs", r"pqcrypto", r"kyber", r"dilithium", r"falcon", r"sphincs",
                     r"open-quantum-safe", r"oqs-python", r"pqclean"],
        "pqc_algorithms": [r"ML-KEM", r"ML-DSA", r"SLH-DSA", r"MLKEM", r"MLDSA", r"SPHINCS\+",
                           r"FrodoKEM", r"Classic McEliece", r"NTRU", r"BIKE", r"HQC"],
    }

    # Java crypto patterns
    JAVA_CRYPTO_PATTERNS = {
        "rsa_keygen": [r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']'],
        "ec_keygen": [r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']'],
        "dsa_keygen": [r'KeyPairGenerator\.getInstance\s*\(\s*["\']DSA["\']'],
        "dh_keygen": [r'KeyPairGenerator\.getInstance\s*\(\s*["\']DH["\']'],
        "weak_hash": [r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1)["\']'],
        "weak_cipher": [r'Cipher\.getInstance\s*\(\s*["\'](DES|DESede|RC4|Blowfish)'],
        "bouncycastle": [r"org\.bouncycastle"],
        "pqc_libs": [r"org\.bouncycastle\.pqc", r"com\.google\.crypto\.tink"],
    }

    # Go crypto patterns
    GO_CRYPTO_PATTERNS = {
        "rsa_keygen": [r"rsa\.GenerateKey", r"rsa\.GenerateMultiPrimeKey"],
        "ec_keygen": [r"ecdsa\.GenerateKey", r"elliptic\.GenerateKey"],
        "weak_hash": [r"crypto/md5", r"crypto/sha1"],
        "weak_cipher": [r"crypto/des", r"crypto/rc4", r"golang\.org/x/crypto/blowfish"],
        "pqc_libs": [r"golang\.org/x/crypto/(kyber|dilithium|sphincs|falcon)", r"filippo\.io/.*pqc"],
    }

    # JavaScript / TypeScript crypto patterns (React/Node/Browser)
    JS_TS_CRYPTO_PATTERNS = {
        "rsa_keygen": [r"node-rsa", r"jsrsasign", r"RSAKey", r"generateKeyPair.*rsa", r"crypto\.generateKeyPair.*rsa"],
        "ec_keygen": [r"ecdsa", r"elliptic", r"generateKeyPair.*ec", r"crypto\.generateKeyPair.*ec"],
        "weak_hash": [r"createHash\s*\(\s*['\"](md5|sha1)['\"]", r"crypto\.subtle\.digest\s*\(\s*['\"](SHA-1|MD5)['\"]"],
        "weak_cipher": [
            r"\b(3DES|TripleDES|RC4|ARC4|Blowfish)\b",
            r"(?:createCipher|createCipheriv|createDecipher|createDecipheriv)\s*\(\s*['\"](?:des|des-ede3|rc4)['\"]",
        ],
        "pqc_libs": [
            r"oqs", r"liboqs", r"pqcrypto", r"post-quantum", r"post_quantum",
            r"@open-quantum-safe", r"open-quantum-safe",
        ],
        "pqc_algorithms": [
            r"ML-KEM", r"ML-DSA", r"SLH-DSA", r"MLKEM", r"MLDSA", r"SLHDSA",
            r"Kyber", r"Dilithium", r"Falcon", r"SPHINCS\+", r"SPHINCS",
            r"FrodoKEM", r"Classic McEliece", r"NTRU", r"BIKE", r"HQC",
        ],
        "pqc_hybrid": [
            r"X25519Kyber", r"X25519MLKEM", r"SecP256r1MLKEM", r"SecP384r1MLKEM1024",
            r"hybrid.*kem", r"hybrid.*kyber",
        ],
    }

    # Manifest files to scan
    MANIFEST_FILES = {
        "requirements.txt": "python",
        "setup.py": "python",
        "pyproject.toml": "python",
        "Pipfile": "python",
        "poetry.lock": "python",
        "pom.xml": "java",
        "build.gradle": "java",
        "build.gradle.kts": "java",
        "go.mod": "go",
        "go.sum": "go",
        "package.json": "nodejs",
        "yarn.lock": "nodejs",
        "pnpm-lock.yaml": "nodejs",
    }

    # Known vulnerable crypto packages
    VULNERABLE_PACKAGES = {
        "python": {
            "pycrypto": "Unmaintained, use pycryptodome",
            "m2crypto": "Check version for vulnerabilities",
            "rsa": "Use cryptography.io instead",
        },
        "java": {
            "bcprov-jdk15on": "Check BouncyCastle version",
            "jce": "Ensure unlimited strength policy",
        },
        "go": {
            "golang.org/x/crypto": "Check for vulnerable versions",
        },
        "nodejs": {
            "crypto": "Built-in, check Node version",
            "node-rsa": "Use native crypto",
        }
    }

    def __init__(
        self,
        target_path: str,
        credentials_ref: Optional[Any] = None,
    ):
        super().__init__(f"SAST ({target_path})")
        self.target_path = Path(target_path).resolve()
        self.credentials_ref = credentials_ref
        self._scan_id: Optional[str] = None
        self._session: Optional[AsyncSession] = None
        self._files_scanned = 0
        self._findings_found = 0

    async def _get_credentials(self) -> Dict[str, Any]:
        if not self.credentials_ref:
            return {}
        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)
        return await get_vault_secret(vault_path, version)

    # ── Logging & Progress helpers ────────────────────────────────────────

    async def _log_event(self, level: str, phase: str, message: str, details: Optional[dict] = None) -> None:
        """Write a ScanLog row if we have a scan_id and session."""
        if not self._scan_id or not self._session:
            return
        try:
            self._session.add(
                ScanLog(
                    scan_id=self._scan_id,
                    level=level,
                    phase=phase,
                    message=message,
                    details=details,
                )
            )
            await self._session.flush()
        except Exception as exc:
            logger.debug(f"ScanLog write failed: {exc}")

    def _is_excluded_path(self, path: Path) -> bool:
        """Check whether any component of *path* is in the exclusion list."""
        try:
            rel = path.relative_to(self.target_path)
        except ValueError:
            rel = path
        return any(part in self.EXCLUDED_DIRS for part in rel.parts)

    def _filtered_rglob(self, pattern: str):
        """
        Yield paths matching *pattern* while skipping excluded directories.
        Uses os.walk so we prune excluded dirs before recursing into them.
        """
        import fnmatch
        target = str(self.target_path)
        for root, dirs, files in os.walk(target):
            # Prune excluded directories in-place so os.walk doesn't recurse into them
            dirs[:] = [d for d in dirs if d not in self.EXCLUDED_DIRS]
            for fname in files:
                if fnmatch.fnmatch(fname, pattern):
                    yield Path(root) / fname

    async def _run_phase(self, name: str, coro) -> Any:
        """Await a scan phase coroutine, catching exceptions and logging them."""
        try:
            return await coro
        except Exception as exc:
            await self._log_event("warn", "discovery", f"{name} scan failed: {exc}")
            return exc

    # ── Source scanners ───────────────────────────────────────────────────

    async def _scan_python_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        files = islice(self._filtered_rglob("*.py"), 200)
        count = 0
        for py_file in files:
            count += 1
            if self._is_excluded_path(py_file):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = py_file.relative_to(self.target_path)
                for category, patterns in self.PYTHON_CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches:
                            line_no = content[:match.start()].count('\n') + 1
                            findings.append({
                                "file": str(rel_path),
                                "line": line_no,
                                "category": category,
                                "pattern": pattern,
                                "matched_text": match.group(0),
                                "code_snippet": content[max(0, match.start()-50):match.end()+50].strip(),
                                "language": "python",
                            })
            except Exception as e:
                logger.debug(f"Failed to scan {py_file}: {e}")
        self._files_scanned += count
        return findings

    async def _scan_java_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        files = islice(self._filtered_rglob("*.java"), 200)
        count = 0
        for java_file in files:
            count += 1
            if self._is_excluded_path(java_file):
                continue
            try:
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = java_file.relative_to(self.target_path)
                for category, patterns in self.JAVA_CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches:
                            line_no = content[:match.start()].count('\n') + 1
                            findings.append({
                                "file": str(rel_path),
                                "line": line_no,
                                "category": category,
                                "pattern": pattern,
                                "matched_text": match.group(0),
                                "code_snippet": content[max(0, match.start()-50):match.end()+50].strip(),
                                "language": "java",
                            })
            except Exception as e:
                logger.debug(f"Failed to scan {java_file}: {e}")
        self._files_scanned += count
        return findings

    async def _scan_go_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        files = islice(self._filtered_rglob("*.go"), 200)
        count = 0
        for go_file in files:
            count += 1
            if self._is_excluded_path(go_file):
                continue
            try:
                content = go_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = go_file.relative_to(self.target_path)
                for category, patterns in self.GO_CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches:
                            line_no = content[:match.start()].count('\n') + 1
                            findings.append({
                                "file": str(rel_path),
                                "line": line_no,
                                "category": category,
                                "pattern": pattern,
                                "matched_text": match.group(0),
                                "code_snippet": content[max(0, match.start()-50):match.end()+50].strip(),
                                "language": "go",
                            })
            except Exception as e:
                logger.debug(f"Failed to scan {go_file}: {e}")
        self._files_scanned += count
        return findings

    async def _scan_js_ts_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        count = 0
        for pattern in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs"):
            files = islice(self._filtered_rglob(pattern), 200)
            for js_file in files:
                count += 1
                if self._is_excluded_path(js_file):
                    continue
                try:
                    content = js_file.read_text(encoding="utf-8", errors="ignore")
                    rel_path = js_file.relative_to(self.target_path)
                    ext = js_file.suffix.lower()
                    language = "typescript" if ext in (".ts", ".tsx") else "javascript"
                    for category, patterns in self.JS_TS_CRYPTO_PATTERNS.items():
                        for rx in patterns:
                            matches = list(re.finditer(rx, content, re.IGNORECASE))
                            for match in matches:
                                line_no = content[:match.start()].count('\n') + 1
                                findings.append({
                                    "file": str(rel_path),
                                    "line": line_no,
                                    "category": category,
                                    "pattern": rx,
                                    "matched_text": match.group(0),
                                    "code_snippet": content[max(0, match.start()-50):match.end()+50].strip(),
                                    "language": language,
                                })
                except Exception as e:
                    logger.debug(f"Failed to scan {js_file}: {e}")
        self._files_scanned += count
        return findings

    async def _scan_manifests(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        count = 0
        for manifest_file, lang in self.MANIFEST_FILES.items():
            for manifest_path in self.target_path.rglob(manifest_file):
                count += 1
                if self._is_excluded_path(manifest_path):
                    continue
                try:
                    content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                    rel_path = manifest_path.relative_to(self.target_path)
                    vuln_packages = self.VULNERABLE_PACKAGES.get(lang, {})
                    for pkg, warning in vuln_packages.items():
                        if pkg in content:
                            line_no = 1
                            for i, line in enumerate(content.split('\n')):
                                if pkg in line:
                                    line_no = i + 1
                                    break
                            findings.append({
                                "file": str(rel_path),
                                "line": line_no,
                                "category": "vulnerable_dependency",
                                "package": pkg,
                                "warning": warning,
                                "language": lang,
                                "manifest": manifest_file,
                            })
                except Exception as e:
                    logger.debug(f"Failed to scan {manifest_path}: {e}")
        self._files_scanned += count
        return findings

    async def _run_semgrep(self) -> List[Dict[str, Any]]:
        if not shutil.which("semgrep"):
            await self._log_event("info", "advanced", "semgrep not installed — skipping.")
            return []
        await self._log_event("info", "advanced", "Starting semgrep scan...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--json", "--quiet",
                "--config", "p/secrets",
                "--config", "p/crypto",
                str(self.target_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode in (0, 1):  # 1 = findings found
                result = json.loads(stdout.decode())
                findings = result.get("results", [])
                await self._log_event("info", "advanced", f"semgrep finished — {len(findings)} findings.",
                                      {"tool": "semgrep", "findings": len(findings)})
                return findings
        except Exception as e:
            await self._log_event("warn", "advanced", f"semgrep scan failed: {e}")
        return []

    async def _scan_container_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        container_files: List[Path] = []
        target = str(self.target_path)

        if self.target_path.exists():
            for root, dirs, files in os.walk(target):
                # Prune excluded directories so we never recurse into them
                dirs[:] = [d for d in dirs if d not in self.EXCLUDED_DIRS]
                for fname in files:
                    name_lower = fname.lower()
                    if "dockerfile" in name_lower or name_lower == "containerfile" or "docker-compose" in name_lower:
                        container_files.append(Path(root) / fname)

        await self._log_event("info", "discovery", f"Scanning {len(container_files[:200])} container files...")
        count = 0
        for c_file in container_files[:200]:
            count += 1
            try:
                content = c_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = c_file.relative_to(self.target_path)
                # Check base images
                for match in re.finditer(r"FROM\s+(\S+)", content, re.IGNORECASE):
                    image_tag = match.group(1)
                    line_no = content[:match.start()].count('\n') + 1
                    weak_base_patterns = [
                        r":12\.04", r":14\.04", r":16\.04",
                        r":6", r":7", r":8",
                        r":3\.[0-7]",
                        r"@sha1:",
                    ]
                    if any(re.search(pat, image_tag) for pat in weak_base_patterns):
                        findings.append({
                            "file": str(rel_path),
                            "line": line_no,
                            "category": "weak_base_image",
                            "pattern": f"FROM {image_tag}",
                            "code_snippet": f"FROM {image_tag}",
                            "language": "docker",
                            "warning": f"Base image {image_tag} uses a deprecated/weak version or SHA-1 digest.",
                        })
                # Check insecure RUN commands
                for match in re.finditer(r"RUN\s+(.*)", content, re.IGNORECASE):
                    run_cmd = match.group(1)
                    line_no = content[:match.start()].count('\n') + 1
                    weak_pkgs = ["openssl-1.0", "libssl1.0.0", "telnet", "rsh-client"]
                    for pkg in weak_pkgs:
                        if pkg in run_cmd:
                            findings.append({
                                "file": str(rel_path),
                                "line": line_no,
                                "category": "insecure_container_package",
                                "pattern": pkg,
                                "code_snippet": f"RUN {run_cmd[:50]}...",
                                "language": "docker",
                                "warning": f"Installing insecure package {pkg}.",
                            })
                # Check weak protocols
                weak_protocols = ["TLSv1", "TLSv1.1", "SSLv3", "RC4", "3DES"]
                for proto in weak_protocols:
                    for match in re.finditer(r"\b" + re.escape(proto) + r"\b", content, re.IGNORECASE):
                        line_no = content[:match.start()].count('\n') + 1
                        findings.append({
                            "file": str(rel_path),
                            "line": line_no,
                            "category": "weak_protocol_reference",
                            "pattern": proto,
                            "code_snippet": content[max(0, match.start()-30):match.end()+30].strip(),
                            "language": "docker",
                            "warning": f"Reference to weak protocol '{proto}' in container config.",
                        })
            except Exception as e:
                logger.debug(f"Failed to scan container file {c_file}: {e}")

        self._files_scanned += count
        return findings

    async def _scan_kerberos_files(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        krb_files: List[Path] = []
        target = str(self.target_path)

        if self.target_path.exists():
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in self.EXCLUDED_DIRS]
                for fname in files:
                    name_lower = fname.lower()
                    if name_lower == "krb5.conf" or name_lower.endswith(".krb5") or "kerberos" in name_lower:
                        krb_files.append(Path(root) / fname)

        await self._log_event("info", "discovery", f"Scanning {len(krb_files[:200])} Kerberos config files...")
        count = 0
        for k_file in krb_files[:200]:
            count += 1
            try:
                content = k_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = k_file.relative_to(self.target_path)
                weak_enctypes = [
                    "des-cbc-crc", "des-cbc-md5", "des-cbc-md4", "des3-cbc-sha1",
                    "des3-hmac-sha1", "rc4-hmac", "arcfour-hmac", "arcfour-hmac-md5"
                ]
                for enctype in weak_enctypes:
                    for match in re.finditer(r"\b" + re.escape(enctype) + r"\b", content, re.IGNORECASE):
                        line_no = content[:match.start()].count('\n') + 1
                        findings.append({
                            "file": str(rel_path),
                            "line": line_no,
                            "category": "weak_kerberos_encryption",
                            "pattern": enctype,
                            "code_snippet": content[max(0, match.start()-30):match.end()+30].strip(),
                            "language": "kerberos",
                            "warning": f"Kerberos config allows weak encryption type '{enctype}'.",
                        })
                for match in re.finditer(r"(permitted_enctypes|default_tkt_enctypes|default_tgs_enctypes)\s*=\s*(.*)", content, re.IGNORECASE):
                    prop = match.group(1)
                    val = match.group(2)
                    line_no = content[:match.start()].count('\n') + 1
                    if not any(modern in val.lower() for modern in ["aes256-cts", "aes128-cts"]):
                        findings.append({
                            "file": str(rel_path),
                            "line": line_no,
                            "category": "weak_kerberos_encryption_policy",
                            "pattern": prop,
                            "code_snippet": f"{prop} = {val[:50]}",
                            "language": "kerberos",
                            "warning": f"Kerberos property '{prop}' does not require strong AES encryption.",
                        })
            except Exception as e:
                logger.debug(f"Failed to scan Kerberos file {k_file}: {e}")

        self._files_scanned += count
        return findings

    # ── Main sync entrypoint ──────────────────────────────────────────────

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        errors: List[str] = []
        all_findings: List[Dict[str, Any]] = []
        self._session = session
        self._scan_id = kwargs.get("scan_id")
        self._files_scanned = 0
        self._findings_found = 0

        await self._log_event(
            "info", "discovery",
            f"SAST scan started for {self.target_path}",
            {"target_path": str(self.target_path), "excluded_dirs": list(self.EXCLUDED_DIRS)},
        )

        try:
            # Resolve scan_id early so every child scan can log
            if not self._scan_id:
                from app.models.models import Scan
                res_scan = await session.execute(
                    select(Scan).order_by(Scan.created_at.desc()).limit(1)
                )
                last_scan = res_scan.scalar_one_or_none()
                if last_scan:
                    self._scan_id = last_scan.id
                else:
                    placeholder_scan = Scan(
                        scan_type="ca_sync",
                        target="sast",
                        target_kind="code_repo",
                        target_label="sast",
                        status="completed",
                        assets_found=1,
                        findings_created=0,
                    )
                    session.add(placeholder_scan)
                    await session.flush()
                    await session.refresh(placeholder_scan)
                    self._scan_id = placeholder_scan.id

            # 1. Python
            await self._log_event("info", "discovery", "Scanning Python files...")
            python_findings = await self._run_phase("python", self._scan_python_files())
            if not isinstance(python_findings, Exception):
                self._findings_found += len(python_findings)
            await self._log_event("info", "discovery", f"Python scan complete — {len(python_findings) if not isinstance(python_findings, Exception) else 0} findings.")

            # 2. Java
            await self._log_event("info", "discovery", "Scanning Java files...")
            java_findings = await self._run_phase("java", self._scan_java_files())
            if not isinstance(java_findings, Exception):
                self._findings_found += len(java_findings)
            await self._log_event("info", "discovery", f"Java scan complete — {len(java_findings) if not isinstance(java_findings, Exception) else 0} findings.")

            # 3. Go
            await self._log_event("info", "discovery", "Scanning Go files...")
            go_findings = await self._run_phase("go", self._scan_go_files())
            if not isinstance(go_findings, Exception):
                self._findings_found += len(go_findings)
            await self._log_event("info", "discovery", f"Go scan complete — {len(go_findings) if not isinstance(go_findings, Exception) else 0} findings.")

            # 4. JavaScript / TypeScript (React, Node, browser)
            await self._log_event("info", "discovery", "Scanning JavaScript / TypeScript files...")
            js_ts_findings = await self._run_phase("js_ts", self._scan_js_ts_files())
            if not isinstance(js_ts_findings, Exception):
                self._findings_found += len(js_ts_findings)
            await self._log_event("info", "discovery", f"JavaScript/TypeScript scan complete — {len(js_ts_findings) if not isinstance(js_ts_findings, Exception) else 0} findings.")

            # 5. Manifests
            await self._log_event("info", "discovery", "Scanning dependency manifests...")
            manifest_findings = await self._run_phase("manifests", self._scan_manifests())
            if not isinstance(manifest_findings, Exception):
                self._findings_found += len(manifest_findings)
            await self._log_event("info", "discovery", f"Manifest scan complete — {len(manifest_findings) if not isinstance(manifest_findings, Exception) else 0} findings.")

            # 5. Semgrep
            await self._log_event("info", "advanced", "Running semgrep (if available)...")
            semgrep_findings = await self._run_phase("semgrep", self._run_semgrep())
            if not isinstance(semgrep_findings, Exception):
                self._findings_found += len(semgrep_findings)
            await self._log_event("info", "advanced", f"Semgrep scan complete — {len(semgrep_findings) if not isinstance(semgrep_findings, Exception) else 0} findings.")

            # 6. Container files
            container_findings = await self._run_phase("container", self._scan_container_files())
            if not isinstance(container_findings, Exception):
                self._findings_found += len(container_findings)
            await self._log_event("info", "discovery", f"Container scan complete — {len(container_findings) if not isinstance(container_findings, Exception) else 0} findings.")

            # 7. Kerberos files
            kerberos_findings = await self._run_phase("kerberos", self._scan_kerberos_files())
            if not isinstance(kerberos_findings, Exception):
                self._findings_found += len(kerberos_findings)
            await self._log_event("info", "discovery", f"Kerberos scan complete — {len(kerberos_findings) if not isinstance(kerberos_findings, Exception) else 0} findings.")

            all_findings: List[Dict[str, Any]] = []
            for name, result in [
                ("python", python_findings), ("java", java_findings),
                ("go", go_findings), ("js_ts", js_ts_findings),
                ("manifests", manifest_findings),
                ("semgrep", semgrep_findings), ("container", container_findings),
                ("kerberos", kerberos_findings),
            ]:
                if isinstance(result, Exception):
                    logger.warning(f"{name} scan failed: {result}")
                    errors.append(f"{name}: {result}")
                else:
                    all_findings.extend(result)

            crypto_findings = [f for f in all_findings if f.get("category") != "vulnerable_dependency"]
            dep_findings = [f for f in all_findings if f.get("category") == "vulnerable_dependency"]

            await self._log_event(
                "info", "discovery",
                f"Source scan summary: {self._files_scanned} files examined, {len(all_findings)} total findings.",
                {
                    "files_scanned": self._files_scanned,
                    "total_findings": len(all_findings),
                    "crypto_findings": len(crypto_findings),
                    "dependency_findings": len(dep_findings),
                    "by_language": {
                        "python": len([f for f in crypto_findings if f.get("language") == "python"]),
                        "java": len([f for f in crypto_findings if f.get("language") == "java"]),
                        "go": len([f for f in crypto_findings if f.get("language") == "go"]),
                        "javascript": len([f for f in crypto_findings if f.get("language") == "javascript"]),
                        "typescript": len([f for f in crypto_findings if f.get("language") == "typescript"]),
                        "docker": len([f for f in crypto_findings if f.get("language") == "docker"]),
                        "kerberos": len([f for f in crypto_findings if f.get("language") == "kerberos"]),
                    },
                },
            )

            # Create/update asset record
            asset_name = f"sast:{self.target_path.name}"
            stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            metadata = {
                "provider": "sast_native",
                "target_path": str(self.target_path),
                "total_findings": len(all_findings),
                "crypto_findings": len(crypto_findings),
                "dependency_findings": len(dep_findings),
                "files_scanned": self._files_scanned,
                "findings_by_language": {
                    "python": len([f for f in crypto_findings if f.get("language") == "python"]),
                    "java": len([f for f in crypto_findings if f.get("language") == "java"]),
                    "go": len([f for f in crypto_findings if f.get("language") == "go"]),
                    "javascript": len([f for f in crypto_findings if f.get("language") == "javascript"]),
                    "typescript": len([f for f in crypto_findings if f.get("language") == "typescript"]),
                    "docker": len([f for f in crypto_findings if f.get("language") == "docker"]),
                    "kerberos": len([f for f in crypto_findings if f.get("language") == "kerberos"]),
                },
                "findings_by_category": {
                    cat: len([f for f in crypto_findings if f.get("category") == cat])
                    for cat in set(f.get("category") for f in crypto_findings)
                },
                "vulnerable_dependencies": dep_findings,
                "sample_findings": crypto_findings[:50],
            }

            if existing:
                asset = existing
                asset.asset_type = "source_code"
                asset.asset_metadata = metadata
                asset.last_verified_at = datetime.now(timezone.utc)
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="source_code",
                    environment="development",
                    discovery_source="sast_native",
                    asset_metadata=metadata,
                    last_verified_at=datetime.now(timezone.utc),
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)

            # Persist findings to DB
            from app.models.models import Finding
            from sqlalchemy import delete
            from app.services.layer_service import layer_for_finding
            from app.services.risk_service import calculate_risk_score

            scan_id = self._scan_id
            await session.execute(
                delete(Finding).where(Finding.asset_id == asset.id, Finding.scan_id == scan_id)
            )

            findings_created_count = 0
            for f in all_findings:
                if f.get("category") == "vulnerable_dependency":
                    finding_type = "sbom_vulnerable_lib"
                    severity = "medium"
                    title = f"Vulnerable Dependency in {f.get('manifest')}: {f.get('package')}"
                    description = f"The package manifest '{f.get('file')}' at line {f.get('line')} includes the package '{f.get('package')}', which is deprecated or known to have cryptographic vulnerabilities: {f.get('warning')}."
                    algorithm = f.get("package")
                    pqc_status = "vulnerable"
                else:
                    finding_type = "code_weak_crypto"
                    severity = "high"
                    category = f.get("category")
                    file_name = f.get("file")
                    line_no = f.get("line")
                    code_snippet = f.get("code_snippet")
                    lang = f.get("language")
                    title = f"Weak Cryptographic Pattern in {lang.capitalize()} code ({category})"
                    description = f"In file {file_name} at line {line_no}: cryptographic signature or usage matches category '{category}'. Snippet: '{code_snippet}'."
                    
                    matched = f.get("matched_text")
                    if matched:
                        algorithm = matched
                    else:
                        algorithm = f.get("pattern", "unknown")
                    
                    from app.analysis.algo_classifier import classify_algorithm
                    cls_res = classify_algorithm(algorithm)
                    pqc_status = cls_res.get("pqc_status", "vulnerable")

                risk_score = calculate_risk_score(
                    hndl_exposure="high" if pqc_status == "vulnerable" else "low",
                    system_exposure="internal",
                    pqc_status=pqc_status,
                    replaceability="medium",
                    years_to_deadline=10,
                )

                session.add(
                    Finding(
                        asset_id=asset.id,
                        scan_id=scan_id,
                        finding_type=finding_type,
                        severity=severity,
                        title=title,
                        description=description,
                        algorithm=algorithm,
                        pqc_status=pqc_status,
                        risk_score=risk_score,
                        layer=layer_for_finding(finding_type=finding_type, asset=asset),
                        hndl_exposure="high",
                        evidence=f,
                        remediation="Migrate this usage to secure post-quantum primitives (e.g. ML-KEM, ML-DSA) or update dependencies.",
                        recommended_algorithm="ML-DSA-65",
                        status="open",
                        first_detected_at=datetime.now(timezone.utc),
                    )
                )
                findings_created_count += 1

            await session.flush()

            await self._log_event(
                "info", "reporting",
                f"SAST scan finished. {self._files_scanned} files scanned, {findings_created_count} findings persisted.",
                {
                    "files_scanned": self._files_scanned,
                    "findings_created": findings_created_count,
                    "errors": errors,
                },
            )

            if existing:
                return {
                    "status": "success",
                    "updated": 1,
                    "imported": 0,
                    "errors": errors,
                    "findings_created": findings_created_count,
                    "files_scanned": self._files_scanned,
                }
            else:
                return {
                    "status": "success",
                    "updated": 0,
                    "imported": 1,
                    "errors": errors,
                    "findings_created": findings_created_count,
                    "files_scanned": self._files_scanned,
                }

        except Exception as exc:
            logger.exception("SAST sync failed")
            await self._log_event("error", "reporting", f"SAST scan crashed: {exc}")
            return {"status": "error", "imported": 0, "updated": 0, "errors": [str(exc)]}
