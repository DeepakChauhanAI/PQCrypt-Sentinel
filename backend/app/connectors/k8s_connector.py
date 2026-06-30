import asyncio
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset

logger = logging.getLogger(__name__)


class KubernetesConnector(BaseConnector):
    """
    Kubernetes cluster scanner.
    Enumerates:
    - TLS secrets across namespaces
    - etcd encryption configuration
    - API server certificate
    - Kubelet certificates
    - CSR (Certificate Signing Requests)
    """

    def __init__(
        self,
        credentials_ref: Any,
        context: Optional[str] = None,
        kubeconfig_path: Optional[str] = None,
    ):
        super().__init__(f"Kubernetes ({context or 'default'})")
        self.credentials_ref = credentials_ref
        self.context = context
        self.kubeconfig_path = kubeconfig_path

    async def _get_credentials(self) -> Dict[str, Any]:
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "kubeconfig" in self.credentials_ref or "token" in self.credentials_ref
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

    async def _create_k8s_client(self):
        try:
            from kubernetes import client, config
        except ImportError as exc:
            raise RuntimeError(
                "kubernetes client is required for Kubernetes connector"
            ) from exc

        creds = await self._get_credentials()

        # Support multiple auth methods
        if "kubeconfig" in creds:
            import tempfile
            import os

            kubeconfig_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".yaml", delete=False
                ) as f:
                    f.write(creds["kubeconfig"])
                    kubeconfig_path = f.name
                config.load_kube_config(
                    config_file=kubeconfig_path, context=self.context
                )
            finally:
                if kubeconfig_path and os.path.exists(kubeconfig_path):
                    os.unlink(kubeconfig_path)
        elif "token" in creds and "host" in creds:
            # Bearer token auth
            configuration = client.Configuration()
            configuration.host = creds["host"]
            configuration.api_key = {"authorization": f"Bearer {creds['token']}"}
            configuration.verify_ssl = creds.get("verify_ssl", False)
            configuration.ssl_ca_cert = creds.get("ca_cert")
            self.api_client = client.ApiClient(configuration)
            return
        elif self.kubeconfig_path:
            config.load_kube_config(
                config_file=self.kubeconfig_path, context=self.context
            )
        else:
            # Try in-cluster config
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config(context=self.context)

    async def _get_secrets(self) -> List[Dict[str, Any]]:
        """Get TLS secrets across all namespaces."""
        from kubernetes import client

        v1 = client.CoreV1Api()
        secrets = []

        try:
            ret = v1.list_secret_for_all_namespaces(watch=False)
            for secret in ret.items:
                if secret.type in ("kubernetes.io/tls", "tls") or (
                    secret.data
                    and any(
                        k.endswith((".crt", ".key", ".pem")) for k in secret.data.keys()
                    )
                ):
                    secret_data = {
                        "namespace": secret.metadata.namespace,
                        "name": secret.metadata.name,
                        "type": secret.type,
                        "creation_timestamp": (
                            str(secret.metadata.creation_timestamp)
                            if secret.metadata.creation_timestamp
                            else None
                        ),
                        "keys": list(secret.data.keys()) if secret.data else [],
                        "has_cert": any(
                            k.endswith(".crt") or k == "tls.crt"
                            for k in (secret.data or {})
                        ),
                        "has_key": any(
                            k.endswith(".key") or k == "tls.key"
                            for k in (secret.data or {})
                        ),
                    }
                    # Decode cert if present for analysis
                    if secret.data and "tls.crt" in secret.data:
                        import base64

                        try:
                            cert_pem = base64.b64decode(secret.data["tls.crt"]).decode(
                                "utf-8"
                            )
                            secret_data["cert_pem"] = cert_pem
                        except Exception:
                            pass
                    secrets.append(secret_data)
        except Exception as e:
            logger.warning(f"Failed to list secrets: {e}")

        return secrets

    async def _get_certificates(self) -> List[Dict[str, Any]]:
        """Get cert-manager certificates and CSRs."""
        from kubernetes import client

        certs = []

        try:
            # Try cert-manager Certificate CRD
            custom_api = client.CustomObjectsApi()
            try:
                certs_list = custom_api.list_cluster_custom_object(
                    group="cert-manager.io", version="v1", plural="certificates"
                )
                for cert in certs_list.get("items", []):
                    certs.append(
                        {
                            "namespace": cert.get("metadata", {}).get("namespace"),
                            "name": cert.get("metadata", {}).get("name"),
                            "spec": cert.get("spec", {}),
                            "status": cert.get("status", {}),
                        }
                    )
            except Exception:
                pass  # cert-manager not installed

            # CSRs
            v1 = client.CertificatesV1Api()
            csrs = v1.list_certificate_signing_request()
            for csr in csrs.items:
                certs.append(
                    {
                        "name": csr.metadata.name,
                        "username": csr.spec.username,
                        "groups": csr.spec.groups,
                        "usages": csr.spec.usages,
                        "status": (
                            {
                                "conditions": [
                                    {
                                        "type": c.type,
                                        "status": c.status,
                                        "reason": c.reason,
                                        "message": c.message,
                                    }
                                    for c in (csr.status.conditions or [])
                                ]
                            }
                            if csr.status
                            else {}
                        ),
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to list certificates/CSRs: {e}")

        return certs

    async def _get_etcd_encryption(self) -> Dict[str, Any]:
        """Check etcd encryption configuration."""
        from kubernetes import client

        result = {"encryption_enabled": False, "config": None}

        try:
            # Check static pod manifest for etcd encryption
            v1 = client.CoreV1Api()
            # Look for encryption-provider-config in kube-apiserver
            pods = v1.list_namespaced_pod(
                namespace="kube-system", label_selector="component=kube-apiserver"
            )
            for pod in pods.items:
                for container in pod.spec.containers:
                    for arg in container.command or []:
                        if "encryption-provider-config" in arg:
                            result["encryption_enabled"] = True
                            result["config_path"] = (
                                arg.split("=")[1] if "=" in arg else arg
                            )
        except Exception as e:
            logger.warning(f"Failed to check etcd encryption: {e}")

        return result

    async def _get_apiserver_cert(self) -> Dict[str, Any]:
        """Get API server certificate info."""
        from kubernetes import client

        result = {}

        try:
            v1 = client.CoreV1Api()
            pods = v1.list_namespaced_pod(
                namespace="kube-system", label_selector="component=kube-apiserver"
            )
            for pod in pods.items:
                for container in pod.spec.containers:
                    for arg in container.command or []:
                        if "tls-cert-file" in arg:
                            result["tls_cert_file"] = (
                                arg.split("=")[1] if "=" in arg else arg
                            )
                        if "tls-private-key-file" in arg:
                            result["tls_key_file"] = (
                                arg.split("=")[1] if "=" in arg else arg
                            )
        except Exception as e:
            logger.warning(f"Failed to get API server cert: {e}")

        return result

    async def _get_kubelet_certs(self) -> List[Dict[str, Any]]:
        """Get kubelet certificate info from nodes."""
        from kubernetes import client

        kubelets = []

        try:
            v1 = client.CoreV1Api()
            nodes = v1.list_node()
            for node in nodes.items:
                kubelet_info = {
                    "node": node.metadata.name,
                    "addresses": (
                        [addr.address for addr in node.status.addresses]
                        if node.status.addresses
                        else []
                    ),
                }
                kubelets.append(kubelet_info)
        except Exception as e:
            logger.warning(f"Failed to get kubelet info: {e}")

        return kubelets

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            await self._create_k8s_client()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Kubernetes client: {exc}") from exc

        errors: List[str] = []

        try:
            # Run all enumeration tasks
            secrets, certs, etcd_encryption, apiserver_cert, kubelets = (
                await asyncio.gather(
                    self._get_secrets(),
                    self._get_certificates(),
                    self._get_etcd_encryption(),
                    self._get_apiserver_cert(),
                    self._get_kubelet_certs(),
                    return_exceptions=True,
                )
            )

            # Handle exceptions
            if isinstance(secrets, Exception):
                logger.warning(f"secrets enumeration failed: {secrets}")
                errors.append(f"secrets: {secrets}")
                secrets = []
            if isinstance(certs, Exception):
                logger.warning(f"certs enumeration failed: {certs}")
                errors.append(f"certs: {certs}")
                certs = []
            if isinstance(etcd_encryption, Exception):
                logger.warning(f"etcd_encryption enumeration failed: {etcd_encryption}")
                errors.append(f"etcd_encryption: {etcd_encryption}")
                etcd_encryption = {}
            if isinstance(apiserver_cert, Exception):
                logger.warning(f"apiserver_cert enumeration failed: {apiserver_cert}")
                errors.append(f"apiserver_cert: {apiserver_cert}")
                apiserver_cert = {}
            if isinstance(kubelets, Exception):
                logger.warning(f"kubelets enumeration failed: {kubelets}")
                errors.append(f"kubelets: {kubelets}")
                kubelets = []

            # Analyze secrets for crypto algorithms
            tls_secrets = [s for s in secrets if s.get("has_cert") and s.get("has_key")]

            # Parse cert details from secret certs
            from app.scanners.cert_parser import parse_certificate

            cert_details = []
            for secret in tls_secrets:
                if "cert_pem" in secret:
                    try:
                        parsed = parse_certificate(secret["cert_pem"])
                        parsed["namespace"] = secret["namespace"]
                        parsed["secret_name"] = secret["name"]
                        cert_details.append(parsed)
                    except Exception as e:
                        logger.warning(
                            f"Failed to parse cert from secret {secret['namespace']}/{secret['name']}: {e}"
                        )

            # Create asset record
            cluster_name = self.context or "default"
            asset_name = f"k8s:{cluster_name}"
            stmt = select(Asset).where(
                Asset.name == asset_name, Asset.deleted_at.is_(None)
            )
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            metadata = {
                "provider": "kubernetes",
                "context": self.context,
                "tls_secrets_count": len(tls_secrets),
                "total_secrets": len(secrets),
                "certificates": certs,
                "etcd_encryption": etcd_encryption,
                "apiserver_cert": apiserver_cert,
                "kubelets": kubelets,
                "cert_details": cert_details,
                "cluster_name": cluster_name,
            }

            if existing:
                existing.asset_type = "kubernetes"
                existing.asset_metadata = metadata
                return {
                    "status": "success",
                    "updated": 1,
                    "imported": 0,
                    "errors": errors,
                }
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="kubernetes",
                    environment="onprem",
                    discovery_source="kubernetes",
                    asset_metadata=metadata,
                )
                session.add(asset)
                return {
                    "status": "success",
                    "imported": 1,
                    "updated": 0,
                    "errors": errors,
                }

        except Exception as exc:
            errors.append(f"Kubernetes sync failed: {exc}")
            logger.exception("Kubernetes sync failed")
            return {"status": "error", "imported": 0, "updated": 0, "errors": errors}
