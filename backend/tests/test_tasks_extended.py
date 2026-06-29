import pytest
import asyncio
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


class TestSetWorkerLoop:
    def test_sets_loop(self):
        loop = asyncio.new_event_loop()
        try:
            _set_worker_loop(loop)
            import app.tasks
            assert app.tasks._worker_loop is loop
        finally:
            loop.close()
