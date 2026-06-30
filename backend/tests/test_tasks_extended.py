import pytest
import asyncio
import os
import socket
from unittest.mock import patch, MagicMock, AsyncMock
from app.tasks import _run_async, _set_worker_loop, _worker_loop


class TestRunAsync:
    def test_normal_execution(self):
        async def coro():
            return 42
        result = _run_async(coro())
        assert result == 42

    def test_closed_loop_creates_new_one(self):
        old_loop = asyncio.new_event_loop()
        old_loop.close()

        with patch("app.tasks._worker_loop", old_loop):
            async def coro():
                return "ok"
            result = _run_async(coro())
        assert result == "ok"

    def test_runtime_error_not_loop_closed_raises(self):
        async def bad_coro():
            raise RuntimeError("some other error")
        with pytest.raises(RuntimeError, match="some other error"):
            _run_async(bad_coro())

    def test_runtime_error_event_loop_closed_recovered(self):
        """When run_until_complete raises 'Event loop is closed', a new loop
        is created and the coroutine is retried (lines 31-36)."""
        new_loop = asyncio.new_event_loop()

        mock_loop = MagicMock()
        mock_loop.is_closed.return_value = False
        mock_loop.run_until_complete.side_effect = RuntimeError("Event loop is closed")

        with patch("app.tasks._worker_loop", mock_loop), \
             patch("app.tasks._set_worker_loop"), \
             patch("asyncio.new_event_loop", return_value=new_loop):

            async def coro():
                return "recovered"

            result = _run_async(coro())

        assert result == "recovered"
        mock_loop.run_until_complete.assert_called_once()
        new_loop.close()


class TestSetWorkerLoop:
    def test_sets_loop(self):
        loop = asyncio.new_event_loop()
        try:
            _set_worker_loop(loop)
            import app.tasks
            assert app.tasks._worker_loop is loop
        finally:
            loop.close()


class TestExecuteReport:
    def test_report_not_found(self):
        """execute_report returns None when the report row is missing (line 81)."""
        mock_session_cm = AsyncMock()
        mock_session = AsyncMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.db.AsyncSessionLocal", return_value=mock_session_cm), \
             patch("app.services.report_service.generate_report", new_callable=AsyncMock) as mock_gen:
            from app.tasks import execute_report
            result = execute_report.__wrapped__("fake-report-id", scan_ids=[])
            assert result is None
            mock_gen.assert_not_called()

    def test_report_happy_path(self):
        """execute_report calls generate_report when report is found."""
        mock_session_cm = AsyncMock()
        mock_session = AsyncMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        fake_report = MagicMock()
        fake_report.id = "report-uuid"
        fake_report.report_type = "executive"
        fake_report.format = "pdf"
        fake_report.scope_filters = {"severity": "high"}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fake_report
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.db.AsyncSessionLocal", return_value=mock_session_cm), \
             patch("app.services.report_service.generate_report", new_callable=AsyncMock) as mock_gen:
            from app.tasks import execute_report
            execute_report.__wrapped__("report-uuid", scan_ids=["s1"])

            mock_gen.assert_called_once()
            call_kwargs = mock_gen.call_args
            assert call_kwargs.kwargs["report_id"] == "report-uuid"
            assert call_kwargs.kwargs["report_type"] == "executive"
            assert call_kwargs.kwargs["fmt"] == "pdf"
            assert call_kwargs.kwargs["scan_ids"] == ["s1"]


class TestExecuteScheduledScan:
    def test_env_targets_used(self):
        """When PQC_PERIODIC_SCAN_TARGETS is set, those targets are used."""
        mock_session_cm = AsyncMock()
        mock_session = AsyncMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        added_scans = []

        def _add(obj):
            added_scans.append(obj)

        mock_session.add = MagicMock(side_effect=_add)

        with patch("app.db.AsyncSessionLocal", return_value=mock_session_cm), \
             patch.dict(os.environ, {"PQC_PERIODIC_SCAN_TARGETS": "10.0.0.1,10.0.0.2"}), \
             patch("app.tasks.classify_target") as mock_classify, \
             patch("app.tasks.execute_scan") as mock_task:
            mock_classify.return_value = MagicMock(kind="host", label="test")
            mock_task.delay = MagicMock()

            from app.tasks import execute_scheduled_scan
            execute_scheduled_scan.__wrapped__()

        assert len(added_scans) == 2
        assert added_scans[0].target == "10.0.0.1"
        assert added_scans[1].target == "10.0.0.2"
        assert mock_task.delay.call_count == 2

    def test_fallback_to_localhost(self):
        """When no env targets and no DB assets, falls back to localhost (line 125)."""
        mock_session_cm = AsyncMock()
        mock_session = AsyncMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        added_scans = []

        def _add(obj):
            added_scans.append(obj)

        mock_session.add = MagicMock(side_effect=_add)

        empty_result = MagicMock()
        empty_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=empty_result)

        with patch("app.db.AsyncSessionLocal", return_value=mock_session_cm), \
             patch.dict(os.environ, {"PQC_PERIODIC_SCAN_TARGETS": ""}, clear=False), \
             patch("app.tasks.classify_target") as mock_classify, \
             patch("app.tasks.execute_scan") as mock_task:
            mock_classify.return_value = MagicMock(kind="host", label="localhost")
            mock_task.delay = MagicMock()

            from app.tasks import execute_scheduled_scan
            execute_scheduled_scan.__wrapped__()

        assert len(added_scans) == 1
        assert added_scans[0].target == "localhost"
        mock_task.delay.assert_called_once()
