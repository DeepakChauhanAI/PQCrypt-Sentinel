import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.connectors.git_secrets_connector import GitSecretsConnector


class TestGitSecretsConnectorInit:
    def test_init_defaults(self):
        connector = GitSecretsConnector("/tmp/repo")
        assert connector.repo_path == "/tmp/repo"
        assert connector.scan_history is True
        assert "Git Secrets Scanner" in connector.name

    def test_init_no_history(self):
        connector = GitSecretsConnector("/tmp/repo", scan_history=False)
        assert connector.scan_history is False


class TestRunGit:
    def test_run_git_success(self):
        connector = GitSecretsConnector("/tmp/repo")
        mock_result = MagicMock()
        mock_result.stdout = "file1.pem\nfile2.key\n"
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            output = connector._run_git("ls-files")
            assert output == "file1.pem\nfile2.key\n"
            mock_run.assert_called_once_with(
                ["git", "ls-files"],
                cwd="/tmp/repo",
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )

    def test_run_git_called_process_error(self):
        connector = GitSecretsConnector("/tmp/repo")
        import subprocess

        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "git", stderr="fatal"),
        ):
            output = connector._run_git("log")
            assert output == ""

    def test_run_git_generic_exception(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("subprocess.run", side_effect=OSError("git not found")):
            output = connector._run_git("status")
            assert output == ""


class TestScanContentForSecrets:
    def test_rsa_private_key_detected(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        findings = connector._scan_content_for_secrets(content)
        assert "RSA private key" in findings
        assert findings["RSA private key"] == 1

    def test_ec_private_key_detected(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = (
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----"
        )
        findings = connector._scan_content_for_secrets(content)
        assert "EC private key" in findings

    def test_certificate_detected(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        findings = connector._scan_content_for_secrets(content)
        assert "X.509 certificate" in findings

    def test_multiple_secrets(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\nkey1\n-----END RSA PRIVATE KEY-----\n"
            "-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\ncert2\n-----END CERTIFICATE-----"
        )
        findings = connector._scan_content_for_secrets(content)
        assert findings["RSA private key"] == 1
        assert findings["X.509 certificate"] == 2

    def test_no_secrets(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "just some regular text with no secrets"
        findings = connector._scan_content_for_secrets(content)
        assert len(findings) == 0

    def test_dsa_private_key(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN DSA PRIVATE KEY-----\ndata\n-----END DSA PRIVATE KEY-----"
        findings = connector._scan_content_for_secrets(content)
        assert "DSA private key" in findings

    def test_openssh_private_key(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----"
        findings = connector._scan_content_for_secrets(content)
        assert "OpenSSH private key" in findings

    def test_tls_certificate(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN TLS CERTIFICATE-----\ndata\n-----END TLS CERTIFICATE-----"
        findings = connector._scan_content_for_secrets(content)
        assert "TLS certificate" in findings

    def test_pkcs8_private_key(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----"
        findings = connector._scan_content_for_secrets(content)
        assert "PKCS#8 private key" in findings

    def test_case_insensitive_match(self):
        connector = GitSecretsConnector("/tmp/repo")
        content = "-----begin certificate-----\ndata\n-----end certificate-----"
        findings = connector._scan_content_for_secrets(content)
        assert "X.509 certificate" in findings


class TestGetCommitCount:
    @pytest.mark.asyncio
    async def test_success(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = "42\n"
            count = await connector._get_commit_count()
            assert count == 42

    @pytest.mark.asyncio
    async def test_invalid_output(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = "not-a-number\n"
            count = await connector._get_commit_count()
            assert count == 0

    @pytest.mark.asyncio
    async def test_empty_output(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = ""
            count = await connector._get_commit_count()
            assert count == 0


class TestScanRecentDiffs:
    @pytest.mark.asyncio
    async def test_success_with_secrets(self):
        connector = GitSecretsConnector("/tmp/repo")
        diff_output = (
            "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"
        )
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = diff_output
            findings = await connector._scan_recent_diffs()
            assert "RSA private key" in findings
            assert findings["RSA private key"] == 1

    @pytest.mark.asyncio
    async def test_no_secrets_in_diff(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = "just some code changes"
            findings = await connector._scan_recent_diffs()
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_exception_handled(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch(
            "asyncio.to_thread",
            new_callable=AsyncMock,
            side_effect=Exception("git error"),
        ):
            findings = await connector._scan_recent_diffs()
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_accumulates_counts(self):
        connector = GitSecretsConnector("/tmp/repo")
        diff_output = (
            "-----BEGIN RSA PRIVATE KEY-----\nkey1\n-----END RSA PRIVATE KEY-----\n"
            "-----BEGIN RSA PRIVATE KEY-----\nkey2\n-----END RSA PRIVATE KEY-----\n"
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
        )
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = diff_output
            findings = await connector._scan_recent_diffs()
            assert findings["RSA private key"] == 2
            assert findings["X.509 certificate"] == 1


class TestScanTrackedFiles:
    @pytest.mark.asyncio
    async def test_success_with_secrets(self):
        connector = GitSecretsConnector("/tmp/repo")
        call_count = 0

        async def mock_to_thread(func, *args):
            nonlocal call_count
            call_count += 1
            if args[0] == "ls-files":
                return "server.pem\nreadme.txt"
            if args[1] == "HEAD:server.pem":
                return "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"
            if args[1] == "HEAD:readme.txt":
                return "just text"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            findings = await connector._scan_tracked_files()
            assert "X.509 certificate" in findings

    @pytest.mark.asyncio
    async def test_empty_file_list(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = ""
            findings = await connector._scan_tracked_files()
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_ls_files_exception(self):
        connector = GitSecretsConnector("/tmp/repo")
        with patch(
            "asyncio.to_thread",
            new_callable=AsyncMock,
            side_effect=Exception("git error"),
        ):
            findings = await connector._scan_tracked_files()
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_individual_file_read_exception_skipped(self):
        connector = GitSecretsConnector("/tmp/repo")
        call_count = 0

        async def mock_to_thread(func, *args):
            nonlocal call_count
            call_count += 1
            if args[0] == "ls-files":
                return "bad_file.pem\ngood_file.pem"
            if len(args) > 1 and "bad_file" in str(args[1]):
                raise Exception("cannot read file")
            if len(args) > 1 and "good_file" in str(args[1]):
                return "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            findings = await connector._scan_tracked_files()
            assert "X.509 certificate" in findings

    @pytest.mark.asyncio
    async def test_skips_empty_lines(self):
        connector = GitSecretsConnector("/tmp/repo")

        async def mock_to_thread(func, *args):
            if args[0] == "ls-files":
                return "file1.pem\n\n\nfile2.pem"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            findings = await connector._scan_tracked_files()
            assert isinstance(findings, dict)


class TestGetRepoInfo:
    @pytest.mark.asyncio
    async def test_success(self):
        connector = GitSecretsConnector("/tmp/repo")
        call_count = 0

        async def mock_to_thread(func, *args):
            nonlocal call_count
            call_count += 1
            if args[0] == "remote":
                return "origin\thttps://github.com/example/repo.git (fetch)\norigin\thttps://github.com/example/repo.git (push)"
            if args[0] == "branch":
                return "* main\n  remotes/origin/main"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            info = await connector._get_repo_info()
            assert len(info["remotes"]) == 2
            assert len(info["branches"]) == 2

    @pytest.mark.asyncio
    async def test_empty_remotes(self):
        connector = GitSecretsConnector("/tmp/repo")

        async def mock_to_thread(func, *args):
            if args[0] == "remote":
                return ""
            if args[0] == "branch":
                return "* main"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            info = await connector._get_repo_info()
            assert info["remotes"] == []

    @pytest.mark.asyncio
    async def test_remotes_exception(self):
        connector = GitSecretsConnector("/tmp/repo")
        call_count = 0

        async def mock_to_thread(func, *args):
            nonlocal call_count
            call_count += 1
            if args[0] == "remote":
                raise Exception("remote error")
            if args[0] == "branch":
                return "* main"
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            info = await connector._get_repo_info()
            assert info["remotes"] == []
            assert len(info["branches"]) == 1

    @pytest.mark.asyncio
    async def test_branches_exception(self):
        connector = GitSecretsConnector("/tmp/repo")
        call_count = 0

        async def mock_to_thread(func, *args):
            nonlocal call_count
            call_count += 1
            if args[0] == "remote":
                return "origin\thttps://github.com/example/repo.git (fetch)"
            if args[0] == "branch":
                raise Exception("branch error")
            return ""

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            info = await connector._get_repo_info()
            assert len(info["remotes"]) == 1
            assert info["branches"] == []


class TestSync:
    @pytest.mark.asyncio
    async def test_sync_creates_new_asset(self):
        connector = GitSecretsConnector("/tmp/repo", scan_history=True)
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        with patch.object(
            connector,
            "_scan_recent_diffs",
            new_callable=AsyncMock,
            return_value={"RSA private key": 1},
        ), patch.object(
            connector,
            "_scan_tracked_files",
            new_callable=AsyncMock,
            return_value={"X.509 certificate": 2},
        ), patch.object(
            connector, "_get_commit_count", new_callable=AsyncMock, return_value=100
        ), patch.object(
            connector,
            "_get_repo_info",
            new_callable=AsyncMock,
            return_value={"remotes": ["origin"], "branches": ["main"]},
        ):
            result = await connector.sync(session)

        assert result["status"] == "success"
        assert result["imported"] == 1
        assert result["updated"] == 0
        assert result["total_processed"] == 1
        session.add.assert_called_once()
        asset = session.add.call_args[0][0]
        assert asset.name == "git:/tmp/repo"
        assert asset.asset_type == "source_code"
        assert asset.discovery_source == "git_secrets"
        assert asset.asset_metadata["total_secrets"] == 3

    @pytest.mark.asyncio
    async def test_sync_updates_existing_asset(self):
        connector = GitSecretsConnector("/tmp/repo", scan_history=True)
        session = AsyncMock()
        existing_asset = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_asset
        session.execute.return_value = mock_result

        with patch.object(
            connector, "_scan_recent_diffs", new_callable=AsyncMock, return_value={}
        ), patch.object(
            connector,
            "_scan_tracked_files",
            new_callable=AsyncMock,
            return_value={"EC private key": 1},
        ), patch.object(
            connector, "_get_commit_count", new_callable=AsyncMock, return_value=50
        ), patch.object(
            connector,
            "_get_repo_info",
            new_callable=AsyncMock,
            return_value={"remotes": [], "branches": []},
        ):
            result = await connector.sync(session)

        assert result["status"] == "success"
        assert result["imported"] == 0
        assert result["updated"] == 1
        assert existing_asset.asset_type == "source_code"

    @pytest.mark.asyncio
    async def test_sync_without_history(self):
        connector = GitSecretsConnector("/tmp/repo", scan_history=False)
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        with patch.object(
            connector, "_scan_recent_diffs", new_callable=AsyncMock
        ) as mock_diffs, patch.object(
            connector, "_scan_tracked_files", new_callable=AsyncMock, return_value={}
        ), patch.object(
            connector, "_get_commit_count", new_callable=AsyncMock, return_value=10
        ), patch.object(
            connector,
            "_get_repo_info",
            new_callable=AsyncMock,
            return_value={"remotes": [], "branches": []},
        ):
            result = await connector.sync(session)
            mock_diffs.assert_not_called()

        assert result["status"] == "success"
