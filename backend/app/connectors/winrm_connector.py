import asyncio
import logging
from typing import Any, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset

logger = logging.getLogger(__name__)


class WinRMConnector(BaseConnector):
    """
    Agentless WinRM connector for Windows hosts.
    Enumerates:
    - Windows Certificate Store (My, Root, CA, TrustedPublisher, etc.)
    - CNG/NCrypt key storage providers
    - Schannel/CNG registry settings
    - IIS SSL bindings
    - BitLocker status
    - Firmware/UEFI signing info
    """

    def __init__(
        self,
        credentials_ref: Any,
        host: str,
        port: int = 5985,
        transport: str = "ntlm",
        use_https: bool = False,
        verify_ssl: bool = True,
    ):
        super().__init__(f"WinRM Agentless ({host}:{port})")
        self.credentials_ref = credentials_ref
        self.host = host
        self.port = port
        self.transport = transport
        self.use_https = use_https
        self.verify_ssl = verify_ssl

    async def _get_credentials(self) -> Dict[str, Any]:
        """Resolve vault credential reference for WinRM."""
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref or "password" in self.credentials_ref
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

    async def _run_ps_command(self, protocol, command: str) -> Dict[str, Any]:
        """Execute a PowerShell command via WinRM."""
        try:
            from winrm.protocol import Protocol
        except ImportError as e:
            raise RuntimeError("pywinrm is required for WinRM connector") from e

        p = Protocol(
            endpoint=f"http{'s' if self.use_https else ''}://{self.host}:{self.port}/wsman",
            transport=self.transport,
            username=protocol["username"],
            password=protocol["password"],
            server_cert_validation="validate" if self.verify_ssl else "ignore",
        )

        try:
            shell_id = p.open_shell()
            command_id = p.run_command(
                shell_id, f"powershell -NoProfile -NonInteractive -Command {command}"
            )
            std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
            p.cleanup_command(shell_id, command_id)
            p.close_shell(shell_id)

            return {
                "exit_code": status_code,
                "stdout": (
                    std_out.decode("utf-8", errors="ignore").strip() if std_out else ""
                ),
                "stderr": (
                    std_err.decode("utf-8", errors="ignore").strip() if std_err else ""
                ),
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
            }

    async def _get_cert_store(self, protocol, store_name: str) -> List[Dict[str, Any]]:
        """Enumerate certificates in a Windows certificate store."""
        ps_cmd = f"""
        Get-ChildItem -Path Cert:\\LocalMachine\\{store_name} |
        Select-Object Thumbprint, Subject, Issuer, NotBefore, NotAfter,
        @{{Name='HasPrivateKey';Expression={{$_.HasPrivateKey}}}},
        @{{Name='FriendlyName';Expression={{$_.FriendlyName}}}},
        @{{Name='Extensions';Expression={{$_.Extensions}}}} |
        ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                certs = json.loads(result["stdout"])
                if not isinstance(certs, list):
                    certs = [certs]
                return certs
            except Exception:
                return []
        return []

    async def _get_all_cert_stores(self, protocol) -> Dict[str, List[Dict[str, Any]]]:
        """Enumerate all relevant certificate stores."""
        stores = [
            "My",
            "Root",
            "CA",
            "TrustedPublisher",
            "AuthRoot",
            "Disallowed",
            "TrustedPeople",
        ]
        results = {}
        for store in stores:
            certs = await self._get_cert_store(protocol, store)
            if certs:
                results[store] = certs
        return results

    async def _get_cng_keys(self, protocol) -> List[Dict[str, Any]]:
        """Enumerate CNG/NCrypt keys."""
        ps_cmd = """
        Get-ChildItem -Path "CNG:\\*" -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.PSIsContainer -eq $false} |
        Select-Object Name, PSPath, @{Name='Provider';Expression={$_.Provider.Name}},
        @{Name='Algorithm';Expression={$_.AlgorithmGroup}},
        @{Name='KeySize';Expression={$_.Length}},
        @{Name='ExportPolicy';Expression={$_.ExportPolicy}},
        @{Name='CreationTime';Expression={$_.CreationTime}} |
        ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                keys = json.loads(result["stdout"])
                if not isinstance(keys, list):
                    keys = [keys]
                return keys
            except Exception:
                return []
        return []

    async def _get_schannel_settings(self, protocol) -> Dict[str, Any]:
        """Get Schannel/CNG registry settings for TLS/SSL."""
        ps_cmd = """
        $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols'
        $protocols = Get-ChildItem $regPath -ErrorAction SilentlyContinue
        $result = @{}
        foreach ($proto in $protocols) {
            $settings = @{}
            foreach ($side in 'Client', 'Server') {
                $path = Join-Path $proto.PSPath $side
                if (Test-Path $path) {
                    $settings[$side] = @{
                        'Enabled' = (Get-ItemProperty $path -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
                        'DisabledByDefault' = (Get-ItemProperty $path -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
                    }
                }
            }
            $result[$proto.PSChildName] = $settings
        }
        $cngPath = 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider'
        $cng = Get-ChildItem $cngPath -ErrorAction SilentlyContinue | Select-Object Name
        $result['CNGProviders'] = $cng | ForEach-Object {$_.Name}
        $result | ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                return json.loads(result["stdout"])
            except Exception:
                return {}
        return {}

    async def _get_iis_bindings(self, protocol) -> List[Dict[str, Any]]:
        """Get IIS SSL bindings."""
        ps_cmd = """
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $sites = Get-Website -ErrorAction SilentlyContinue
        $bindings = @()
        foreach ($site in $sites) {
            $b = Get-WebBinding -Name $site.Name -ErrorAction SilentlyContinue
            foreach ($binding in $b) {
                if ($binding.Protocol -eq 'https') {
                    $cert = $binding.Certificate
                    $bindings += [PSCustomObject]@{
                        SiteName = $site.Name
                        IP = $binding.BindingInformation.Split(':')[0]
                        Port = $binding.BindingInformation.Split(':')[1]
                        HostName = $binding.BindingInformation.Split(':')[2]
                        CertThumbprint = $cert.GetCertHashString()
                        CertSubject = $cert.Subject
                        CertStore = $cert.StoreName
                    }
                }
            }
        }
        $bindings | ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                bindings = json.loads(result["stdout"])
                if not isinstance(bindings, list):
                    bindings = [bindings]
                return bindings
            except Exception:
                return []
        return []

    async def _get_bitlocker_status(self, protocol) -> Dict[str, Any]:
        """Get BitLocker encryption status."""
        ps_cmd = """
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $result = @()
        foreach ($vol in $volumes) {
            $result += [PSCustomObject]@{
                MountPoint = $vol.MountPoint
                VolumeStatus = $vol.VolumeStatus
                EncryptionMethod = $vol.EncryptionMethod
                KeyProtector = $vol.KeyProtector
                AutoUnlockEnabled = $vol.AutoUnlockEnabled
                EncryptionPercentage = $vol.EncryptionPercentage
            }
        }
        $result | ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                volumes = json.loads(result["stdout"])
                if not isinstance(volumes, list):
                    volumes = [volumes]
                return {"volumes": volumes}
            except Exception:
                return {"volumes": []}
        return {"volumes": []}

    async def _get_firmware_info(self, protocol) -> Dict[str, Any]:
        """Get UEFI/firmware signing and secure boot info."""
        ps_cmd = """
        $result = @{}
        # Secure Boot
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $result['SecureBoot'] = $sb

        # UEFI variables
        $uefi = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' -ErrorAction SilentlyContinue
        $result['UEFIState'] = @($uefi | Get-Member -MemberType NoteProperty | ForEach-Object {$_.Name})

        # Boot entries
        $boots = bcdedit /enum firmware 2>&1
        $result['BootEntries'] = $boots

        $result | ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                return json.loads(result["stdout"])
            except Exception:
                return {}
        return {}

    async def _get_tpm_info(self, protocol) -> Dict[str, Any]:
        """Get TPM status and endorsement key information."""
        ps_cmd = """
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        $ek = Get-TpmEndorsementKeyInfo -HasOwnerAuth -ErrorAction SilentlyContinue
        $result = @{
            'TpmPresent' = $tpm.TpmPresent
            'TpmReady' = $tpm.TpmReady
            'TpmEnabled' = $tpm.TpmEnabled
            'TpmActivated' = $tpm.TpmActivated
            'TpmOwned' = $tpm.TpmOwned
            'ManufacturerId' = $tpm.ManufacturerId
            'ManufacturerVersion' = $tpm.ManufacturerVersion
            'SpecVersion' = $tpm.SpecVersion
            'EndorsementKeyPublicKey' = $ek.PublicKey
            'EndorsementKeyAlgorithm' = $ek.Algorithm
        }
        $result | ConvertTo-Json -Depth 5
        """
        result = await self._run_ps_command(protocol, ps_cmd)
        if result["exit_code"] == 0 and result["stdout"]:
            try:
                import json

                return json.loads(result["stdout"])
            except Exception:
                return {}
        return {}

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        creds = await self._get_credentials()
        username = creds.get("username") or creds.get("user")
        password = creds.get("password") or creds.get("winrm_password")

        if not username or not password:
            raise RuntimeError(
                "WinRM connector requires username and password from vault"
            )

        protocol = {
            "username": username,
            "password": password,
        }

        # Run enumeration tasks in parallel
        cert_stores, cng_keys, schannel, iis_bindings, bitlocker, firmware, tpm = (
            await asyncio.gather(
                self._get_all_cert_stores(protocol),
                self._get_cng_keys(protocol),
                self._get_schannel_settings(protocol),
                self._get_iis_bindings(protocol),
                self._get_bitlocker_status(protocol),
                self._get_firmware_info(protocol),
                self._get_tpm_info(protocol),
                return_exceptions=True,
            )
        )

        # Handle exceptions
        if isinstance(cert_stores, Exception):
            logger.warning(f"cert_stores enumeration failed: {cert_stores}")
            cert_stores = {}
        if isinstance(cng_keys, Exception):
            logger.warning(f"cng_keys enumeration failed: {cng_keys}")
            cng_keys = []
        if isinstance(schannel, Exception):
            logger.warning(f"schannel enumeration failed: {schannel}")
            schannel = {}
        if isinstance(iis_bindings, Exception):
            logger.warning(f"iis_bindings enumeration failed: {iis_bindings}")
            iis_bindings = []
        if isinstance(bitlocker, Exception):
            logger.warning(f"bitlocker enumeration failed: {bitlocker}")
            bitlocker = {}
        if isinstance(firmware, Exception):
            logger.warning(f"firmware enumeration failed: {firmware}")
            firmware = {}
        if isinstance(tpm, Exception):
            logger.warning(f"tpm enumeration failed: {tpm}")
            tpm = {}

        # Create asset record
        asset_name = f"winrm:{self.host}:{self.port}"
        stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        metadata = {
            "provider": "winrm_agentless",
            "host": self.host,
            "port": self.port,
            "cert_stores": (
                cert_stores if not isinstance(cert_stores, Exception) else {}
            ),
            "cng_keys": cng_keys if not isinstance(cng_keys, Exception) else [],
            "schannel": schannel if not isinstance(schannel, Exception) else {},
            "iis_bindings": (
                iis_bindings if not isinstance(iis_bindings, Exception) else []
            ),
            "bitlocker": bitlocker if not isinstance(bitlocker, Exception) else {},
            "firmware": firmware if not isinstance(firmware, Exception) else {},
            "tpm": tpm if not isinstance(tpm, Exception) else {},
        }

        if existing:
            existing.asset_type = "endpoint"
            existing.asset_metadata = metadata
            await session.flush()
            return {"status": "success", "updated": 1, "imported": 0}
        else:
            asset = Asset(
                name=asset_name,
                asset_type="endpoint",
                ip_address=self.host,
                port=self.port,
                protocol="winrm",
                environment="onprem",
                discovery_source="winrm_agentless",
                asset_metadata=metadata,
            )
            session.add(asset)
            await session.flush()
            return {"status": "success", "imported": 1, "updated": 0}
