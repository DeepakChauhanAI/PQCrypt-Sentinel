"""
Async retry helper for the PQC scanner.

Provides a small decorator that wraps an `async def` coroutine with
exponential backoff + jitter, used by scanner / connector call sites that
hit transient network errors (timeouts, connection resets, SSRF policy
delays, etc.).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import random
from typing import Awaitable, Callable, Iterable, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def async_retry(
    *,
    attempts: int = 3,
    initial_delay: float = 0.5,
    max_delay: float = 8.0,
    backoff: float = 2.0,
    jitter: float = 0.1,
    retry_on: Iterable[Type[BaseException]] = (
        asyncio.TimeoutError,
        ConnectionError,
        OSError,
    ),
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator that retries the wrapped coroutine on the given exception types.

    Backoff is exponential with multiplicative jitter. Honours asyncio.CancelledError
    (no retry, immediate re-raise).
    """
    retry_tuple = tuple(retry_on)

    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs) -> T:
            last_exc: BaseException | None = None
            delay = initial_delay
            for attempt in range(1, attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except asyncio.CancelledError:
                    raise
                except retry_tuple as exc:
                    last_exc = exc
                    if attempt == attempts:
                        logger.warning(
                            f"{fn.__name__} failed after {attempt} attempts: {exc}"
                        )
                        break
                    sleep_for = delay + random.uniform(0, delay * jitter)
                    sleep_for = min(sleep_for, max_delay)
                    logger.info(
                        f"{fn.__name__} attempt {attempt} failed ({exc!r}); "
                        f"retrying in {sleep_for:.2f}s"
                    )
                    await asyncio.sleep(sleep_for)
                    delay = min(delay * backoff, max_delay)
            assert last_exc is not None
            raise last_exc

        return wrapper

    return decorator
