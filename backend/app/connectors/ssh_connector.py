import asyncio
import logging
import os
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset

logger = logging.getLogger(__name__)


class SSHConnector(BaseConnector):
    """
    Agentless SSH connector for Linux hosts.
    Enumerates:
    - Keystores (JKS, PKCS12, PEM)
    - Certificate files
    - OpenSSL version and config
    - SSH server/client config
    - Kerberos configuration
    """

    def __init__(
        self,
        credentials_ref: Any,
        host: str,
        port: int = 22,
        sudo: bool = False,
        sudo_password_ref: Optional[Any] = None,
    ):
        super().__init__(f"SSH Agentless ({host}:{port})")
        self.credentials_ref = credentials_ref
        self.host = host
        self.port = port
        self.sudo = sudo
        self.sudo_password_ref = sudo_password_ref

    async def _get_ssh_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference for SSH."""
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref
            or "password" in self.credentials_ref
            or "private_key" in self.credentials_ref
        ):
            return self.credentials_ref

        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)

        return await get_vault_secret(vault_path, version)

    async def _run_ssh_command(
        self, client, command: str, sudo: bool = False
    ) -> Dict[str, Any]:
        """Execute a command over SSH and return stdout/stderr/exit_code."""
        full_cmd = f"sudo -S {command}" if sudo else command

        try:
            stdin, stdout, stderr = client.exec_command(full_cmd, timeout=30)
            if sudo:
                sudo_pwd = ""
                if self.sudo_password_ref:
                    sudo_creds = await self._get_ssh_credentials()
                    sudo_pwd = sudo_creds.get("sudo_password", "")
                if sudo_pwd:
                    stdin.write(sudo_pwd + "\n")
                    stdin.flush()
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode("utf-8", errors="ignore").strip()
            stderr_data = stderr.read().decode("utf-8", errors="ignore").strip()
            return {
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
            }

    async def _enumerate_keystores(self, client) -> List[Dict[str, Any]]:
        """Find and analyze keystore files."""
        keystores = []

        # Common keystore locations
        find_cmd = (
            "find /opt /usr /etc /home /var -maxdepth 4 "
            "-type f \\( -name '*.jks' -o -name '*.keystore' -o -name '*.p12' "
            "-o -name '*.pfx' -o -name '*.pem' -o -name '*.crt' -o -name '*.cer' \\) 2>/dev/null"
        )
        result = await self._run_ssh_command(client, find_cmd, sudo=True)
        if result["exit_code"] == 0 and result["stdout"]:
            for path in result["stdout"].splitlines():
                path = path.strip()
                if not path:
                    continue
                ks_info = await self._analyze_keystore(client, path)
                if ks_info:
                    keystores.append(ks_info)

        return keystores

    async def _analyze_keystore(self, client, path: str) -> Optional[Dict[str, Any]]:
        """Determine keystore type and extract metadata."""
        # Check file type
        file_cmd = f"file '{path}'"
        result = await self._run_ssh_command(client, file_cmd)
        file_type = result.get("stdout", "")

        ks_data = {
            "path": path,
            "file_type": file_type,
            "format": "unknown",
            "entries": [],
        }

        if "Java KeyStore" in file_type or path.endswith((".jks", ".keystore")):
            ks_data["format"] = "JKS"
            # Try keytool to list entries (no password = just count)
            list_cmd = f"keytool -list -keystore '{path}' -storepass '' 2>&1 | head -30"
            result = await self._run_ssh_command(client, list_cmd)
            ks_data["entries_raw"] = result.get("stdout", "")
        elif "PKCS#12" in file_type or path.endswith((".p12", ".pfx")):
            ks_data["format"] = "PKCS12"
            list_cmd = (
                f"openssl pkcs12 -info -in '{path}' -passin pass:'' 2>&1 | head -30"
            )
            result = await self._run_ssh_command(client, list_cmd)
            ks_data["entries_raw"] = result.get("stdout", "")
        elif "PEM" in file_type or path.endswith((".pem", ".crt", ".cer")):
            ks_data["format"] = "PEM"
            # Extract cert info
            cert_cmd = f"openssl x509 -in '{path}' -text -noout 2>&1 | head -50"
            result = await self._run_ssh_command(client, cert_cmd)
            ks_data["entries_raw"] = result.get("stdout", "")

        return ks_data

    async def _get_openssl_info(self, client) -> Dict[str, Any]:
        """Get OpenSSL version and configuration."""
        info = {}
        result = await self._run_ssh_command(client, "openssl version -a")
        if result["exit_code"] == 0:
            info["version_output"] = result["stdout"]
            # Parse version
            for line in result["stdout"].splitlines():
                if line.startswith("OpenSSL"):
                    info["version"] = (
                        line.split()[1] if len(line.split()) > 1 else "unknown"
                    )

        # Get OpenSSL config location
        result = await self._run_ssh_command(client, "openssl version -d")
        if result["exit_code"] == 0:
            info["config_dir"] = result["stdout"]

        return info

    async def _get_ssh_config(self, client) -> Dict[str, Any]:
        """Parse SSH server and client configs."""
        configs: Dict[str, Any] = {"server": {}, "client": {}}

        # Server config
        server_paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
        for sp in server_paths:
            result = await self._run_ssh_command(
                client, f"cat {sp} 2>/dev/null", sudo=True
            )
            if result["exit_code"] == 0 and result["stdout"]:
                configs["server"][sp] = result["stdout"]

        # Client config
        client_paths = ["/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d/*.conf"]
        for cp in client_paths:
            result = await self._run_ssh_command(client, f"cat {cp} 2>/dev/null")
            if result["exit_code"] == 0 and result["stdout"]:
                configs["client"][cp] = result["stdout"]

        return configs

    async def _get_kerberos_config(self, client) -> Dict[str, Any]:
        """Get Kerberos configuration and check for RC4."""
        krb = {}
        result = await self._run_ssh_command(client, "cat /etc/krb5.conf 2>/dev/null")
        if result["exit_code"] == 0:
            krb["krb5_conf"] = result["stdout"]
            # Check for RC4 encryption types
            if (
                "rc4" in result["stdout"].lower()
                or "arcfour" in result["stdout"].lower()
            ):
                krb["has_rc4"] = True
            else:
                krb["has_rc4"] = False

        # Check keytabs
        result = await self._run_ssh_command(
            client, "ls -la /etc/krb5.keytab /etc/krb5.keytab.* 2>/dev/null", sudo=True
        )
        if result["exit_code"] == 0:
            krb["keytabs"] = result["stdout"]

        return krb

    async def _get_tpm_info(self, client) -> Dict[str, Any]:
        """Get TPM status and version information."""
        result = await self._run_ssh_command(
            client, "tpm2_getcap properties-fixed 2>/dev/null"
        )
        if result["exit_code"] != 0 or not result["stdout"]:
            return {}

        tpm_info = {
            "manufacturer": "unknown",
            "firmware_version": "unknown",
            "algorithms": [],
        }

        # Parse properties-fixed output
        stdout = result["stdout"]
        import re

        # Extract Manufacturer
        man_match = re.search(
            r"TPM2_PT_MANUFACTURER:\s*\n\s*raw:\s*(0x[0-9A-Fa-f]+)\s*\n\s*value:\s*\"([^\"]+)\"",
            stdout,
        )
        if man_match:
            tpm_info["manufacturer"] = man_match.group(2).strip()
        else:
            man_match_raw = re.search(
                r"TPM2_PT_MANUFACTURER:\s*\n\s*raw:\s*(0x[0-9A-Fa-f]+)", stdout
            )
            if man_match_raw:
                try:
                    raw_val = man_match_raw.group(1)
                    val = (
                        bytes.fromhex(raw_val[2:])
                        .decode("utf-8", errors="ignore")
                        .strip()
                    )
                    tpm_info["manufacturer"] = val if val else raw_val
                except Exception:
                    tpm_info["manufacturer"] = man_match_raw.group(1)

        # Extract Firmware Version
        fw1_match = re.search(
            r"TPM2_PT_FIRMWARE_VERSION_1:\s*\n\s*raw:\s*(0x[0-9A-Fa-f]+)", stdout
        )
        fw2_match = re.search(
            r"TPM2_PT_FIRMWARE_VERSION_2:\s*\n\s*raw:\s*(0x[0-9A-Fa-f]+)", stdout
        )
        if fw1_match and fw2_match:
            try:
                v1 = int(fw1_match.group(1), 16)
                v2 = int(fw2_match.group(1), 16)
                tpm_info["firmware_version"] = (
                    f"{(v1 >> 16) & 0xffff}.{v1 & 0xffff}.{(v2 >> 16) & 0xffff}.{v2 & 0xffff}"
                )
            except Exception:
                tpm_info["firmware_version"] = (
                    f"{fw1_match.group(1)}.{fw2_match.group(1)}"
                )
        elif fw1_match:
            tpm_info["firmware_version"] = fw1_match.group(1)

        # Parse algorithms
        alg_result = await self._run_ssh_command(
            client, "tpm2_getcap algorithms 2>/dev/null"
        )
        if alg_result["exit_code"] == 0 and alg_result["stdout"]:
            algorithms = []
            for line in alg_result["stdout"].splitlines():
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                match_colon = re.match(r"^([a-zA-Z0-9_\-]+):", line_stripped)
                match_paren = re.match(r"^([a-zA-Z0-9_\-]+)\s*\(", line_stripped)
                if match_colon:
                    name = match_colon.group(1).lower()
                    if name not in [
                        "raw",
                        "value",
                        "symmetric",
                        "hash",
                        "object",
                        "signing",
                        "decrypting",
                        "method",
                    ]:
                        algorithms.append(name)
                elif match_paren:
                    algorithms.append(match_paren.group(1).lower())
            tpm_info["algorithms"] = sorted(list(set(algorithms)))

        return tpm_info

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        import paramiko

        creds = await self._get_ssh_credentials()
        username = creds.get("username") or creds.get("user")
        password = creds.get("password") or creds.get("ssh_password")
        private_key = creds.get("private_key")
        key_passphrase = creds.get("key_passphrase")

        if not username or (not password and not private_key):
            raise RuntimeError(
                "SSH connector requires username + password or private_key from vault"
            )

        client = paramiko.SSHClient()
        # Security: RejectPolicy is the safe default. Operators can opt in to
        # auto-acceptance (MITM-vulnerable) by setting
        # ``PQC_SSH_AUTO_ADD_HOST_KEY=1`` in the environment. Key-pinning
        # from CMDB can be added later via client.get_host_keys() / load.
        if os.environ.get("PQC_SSH_AUTO_ADD_HOST_KEY") == "1":
            logger.warning(
                "PQC_SSH_AUTO_ADD_HOST_KEY=1 — accepting unknown host keys. "
                "This is MITM-vulnerable; do not use in production."
            )
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            if private_key:
                from io import StringIO

                pkey = paramiko.RSAKey.from_private_key(
                    StringIO(private_key), password=key_passphrase
                )
                client.connect(
                    self.host,
                    port=self.port,
                    username=username,
                    pkey=pkey,
                    timeout=30,
                    banner_timeout=30,
                )
            else:
                client.connect(
                    self.host,
                    port=self.port,
                    username=username,
                    password=password,
                    timeout=30,
                    banner_timeout=30,
                )

            # Run enumeration tasks in parallel
            keystores, openssl_info, ssh_config, kerberos, tpm = await asyncio.gather(
                self._enumerate_keystores(client),
                self._get_openssl_info(client),
                self._get_ssh_config(client),
                self._get_kerberos_config(client),
                self._get_tpm_info(client),
                return_exceptions=True,
            )

            # Handle exceptions
            if isinstance(keystores, Exception):
                logger.warning(f"keystores enumeration failed: {keystores}")
                keystores = []
            if isinstance(openssl_info, Exception):
                logger.warning(f"openssl enumeration failed: {openssl_info}")
                openssl_info = {}
            if isinstance(ssh_config, Exception):
                logger.warning(f"ssh_config enumeration failed: {ssh_config}")
                ssh_config = {}
            if isinstance(kerberos, Exception):
                logger.warning(f"kerberos enumeration failed: {kerberos}")
                kerberos = {}
            if isinstance(tpm, Exception):
                logger.warning(f"tpm enumeration failed: {tpm}")
                tpm = {}

            # Create asset record
            asset_name = f"ssh:{self.host}:{self.port}"
            stmt = select(Asset).where(
                Asset.name == asset_name, Asset.deleted_at.is_(None)
            )
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            metadata = {
                "provider": "ssh_agentless",
                "host": self.host,
                "port": self.port,
                "openssl": (
                    openssl_info if not isinstance(openssl_info, Exception) else {}
                ),
                "ssh_config": (
                    ssh_config if not isinstance(ssh_config, Exception) else {}
                ),
                "kerberos": kerberos if not isinstance(kerberos, Exception) else {},
                "tpm": tpm if not isinstance(tpm, Exception) else {},
                "keystores_count": (
                    len(keystores) if not isinstance(keystores, Exception) else 0
                ),
                "keystores": keystores if not isinstance(keystores, Exception) else [],
            }

            if existing:
                existing.asset_type = "server"
                existing.asset_metadata = metadata
                # The model column is DateTime, but the loop clock is a float
                # epoch timestamp. Convert it before assignment.
                from datetime import datetime, timezone

                existing.last_verified_at = datetime.now(timezone.utc)
                await session.flush()
                return {"status": "success", "updated": 1, "imported": 0}
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="server",
                    ip_address=self.host,
                    port=self.port,
                    protocol="ssh",
                    environment="onprem",
                    discovery_source="ssh_agentless",
                    asset_metadata=metadata,
                )
                session.add(asset)
                await session.flush()
                return {"status": "success", "imported": 1, "updated": 0}

        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            return {"status": "error", "error": str(e), "imported": 0, "updated": 0}
        finally:
            client.close()
