import asyncio
import logging
import re
import subprocess
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.models.models import Asset

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    ("RSA private key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----", re.IGNORECASE)),
    ("EC private key", re.compile(r"-----BEGIN EC PRIVATE KEY-----", re.IGNORECASE)),
    ("DSA private key", re.compile(r"-----BEGIN DSA PRIVATE KEY-----", re.IGNORECASE)),
    (
        "OpenSSH private key",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE),
    ),
    ("X.509 certificate", re.compile(r"-----BEGIN CERTIFICATE-----", re.IGNORECASE)),
    ("TLS certificate", re.compile(r"-----BEGIN TLS CERTIFICATE-----", re.IGNORECASE)),
    ("PKCS#8 private key", re.compile(r"-----BEGIN PRIVATE KEY-----", re.IGNORECASE)),
]


class GitSecretsConnector(BaseConnector):
    """Scan git repositories for exposed cryptographic keys and credentials."""

    def __init__(self, repo_path: str, scan_history: bool = True):
        super().__init__(f"Git Secrets Scanner ({repo_path})")
        self.repo_path = repo_path
        self.scan_history = scan_history

    def _run_git(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git"] + list(args),
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.debug(f"Git command failed: {e}")
            return ""
        except Exception as e:
            logger.debug(f"Git error: {e}")
            return ""

    def _scan_content_for_secrets(self, content: str) -> Dict[str, int]:
        findings: Dict[str, int] = {}
        for name, pattern in SECRET_PATTERNS:
            matches = pattern.findall(content)
            count = len(matches)
            if count > 0:
                findings[name] = count
        return findings

    async def _get_commit_count(self) -> int:
        output = await asyncio.to_thread(self._run_git, "rev-list", "--count", "HEAD")
        try:
            return int(output.strip())
        except Exception:
            return 0

    async def _scan_recent_diffs(self) -> Dict[str, int]:
        secrets_found: Dict[str, int] = {}
        try:
            output = await asyncio.to_thread(
                self._run_git,
                "diff",
                "HEAD~10..HEAD",
                "--",
                "--",
                "*.pem",
                "*.crt",
                "*.key",
                "*.p12",
                "*.pfx",
                "*.cer",
                "*.p7b",
                "*.p7c",
            )
            found = self._scan_content_for_secrets(output)
            for k, v in found.items():
                secrets_found[k] = secrets_found.get(k, 0) + v
        except Exception as e:
            logger.warning(f"Git diff scan failed: {e}")
        return secrets_found

    async def _scan_tracked_files(self) -> Dict[str, int]:
        secrets_found: Dict[str, int] = {}
        try:
            files = await asyncio.to_thread(self._run_git, "ls-files")
            for fpath in files.splitlines():
                if not fpath:
                    continue
                try:
                    content = await asyncio.to_thread(
                        self._run_git, "show", f"HEAD:{fpath}"
                    )
                    found = self._scan_content_for_secrets(content)
                    for k, v in found.items():
                        secrets_found[k] = secrets_found.get(k, 0) + v
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Git tracked files scan failed: {e}")
        return secrets_found

    async def _get_repo_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            remotes = await asyncio.to_thread(self._run_git, "remote", "-v")
            info["remotes"] = remotes.strip().splitlines() if remotes else []
        except Exception:
            info["remotes"] = []
        try:
            branches = await asyncio.to_thread(self._run_git, "branch", "-a")
            info["branches"] = [
                b.strip().lstrip("*").strip()
                for b in branches.strip().splitlines()
                if b.strip()
            ]
        except Exception:
            info["branches"] = []
        return info

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        secrets_found: Dict[str, int] = {}

        if self.scan_history:
            diff_findings = await self._scan_recent_diffs()
            for k, v in diff_findings.items():
                secrets_found[k] = secrets_found.get(k, 0) + v

        tracked_findings = await self._scan_tracked_files()
        for k, v in tracked_findings.items():
            secrets_found[k] = secrets_found.get(k, 0) + v

        commit_count = await self._get_commit_count()
        repo_info = await self._get_repo_info()

        asset_name = f"git:{self.repo_path}"
        stmt = select(Asset).where(Asset.name == asset_name, Asset.deleted_at.is_(None))
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        metadata = {
            "repo_path": self.repo_path,
            "commit_count": commit_count,
            "scan_history": self.scan_history,
            "remotes": repo_info.get("remotes", []),
            "branches": repo_info.get("branches", []),
            "secrets_found": secrets_found,
            "total_secrets": sum(secrets_found.values()),
        }

        if existing:
            existing.asset_type = "source_code"
            existing.asset_metadata = metadata
            await session.flush()
            return {
                "status": "success",
                "imported": 0,
                "updated": 1,
                "errors": [],
                "total_processed": 1,
            }

        asset = Asset(
            name=asset_name,
            asset_type="source_code",
            environment="onprem",
            discovery_source="git_secrets",
            asset_metadata=metadata,
        )
        session.add(asset)
        await session.flush()
        return {
            "status": "success",
            "imported": 1,
            "updated": 0,
            "errors": [],
            "total_processed": 1,
        }
