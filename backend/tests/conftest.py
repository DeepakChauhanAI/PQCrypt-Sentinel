"""
Shared pytest fixtures for the PQC backend test suite.

These fixtures are designed to:
  * avoid duplicating mock setup across the test files
  * provide deterministic IDs / timestamps so tests can compare objects
  * never hit a real database or external service
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure the backend root is on sys.path so `import app.*` works
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://invalid:1")
os.environ.setdefault("PQC_ALLOW_LOOPBACK", "1")
os.environ.setdefault("PQC_ALLOW_PRIVATE_RANGES", "1")

# Import the FastAPI app once at module load so fixtures can reuse the same
# instance. The app's lifespan handler is exercised only when entering the
# TestClient context manager inside a test.
from app.main import app as _fastapi_app  # noqa: E402
from app.models import models as _models  # noqa: E402

# The lifespan handler calls `Base.metadata.create_all` against a *sync*
# engine. Tests use SQLite (which doesn't support the `JSONB` column type
# used by a few models), so we patch the call to a no-op. Tests that need
# real DDL mock out the model layer directly.
_models.Base.metadata.create_all = lambda *_a, **_kw: None


@pytest.fixture
def fastapi_app():
    """Return the configured FastAPI app instance."""
    return _fastapi_app


@pytest.fixture
def client():
    """A TestClient with the FastAPI lifespan entered/exited automatically."""
    with TestClient(_fastapi_app) as c:
        yield c


@pytest.fixture
def mock_user():
    """A canonical mock user for auth-protected endpoints."""
    return SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        email="tester@example.com",
        role="admin",
        is_active=True,
    )


@pytest.fixture
def mock_db():
    """An AsyncMock-compatible DB session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.scalar = AsyncMock()
    db.scalars = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    db.add = MagicMock()
    db.delete = AsyncMock()
    return db


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


@pytest.fixture
def fixed_scan_id():
    return "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def fixed_asset_id():
    return "00000000-0000-0000-0000-000000000002"


@pytest.fixture
def fixed_finding_id():
    return "00000000-0000-0000-0000-000000000003"


@pytest.fixture
def auth_override(mock_user):
    """
    Install a get_current_user override on the FastAPI app and remove it
    after the test. Use as a context manager if you need finer control.
    """
    from app.api.auth import get_current_user

    _fastapi_app.dependency_overrides[get_current_user] = lambda: mock_user
    yield mock_user
    _fastapi_app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def sample_cert_data():
    """Minimal cert_data dict used by finding_service tests."""
    return {
        "thumbprint": "a" * 64,
        "subject": "CN=example.com",
        "issuer": "CN=Test CA",
        "serial_number": "01",
        "sig_algorithm": "sha256WithRSAEncryption",
        "pub_key_algorithm": "rsa",
        "pub_key_size": 2048,
        "not_before": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "not_after": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "is_self_signed": False,
        "is_ca": False,
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "san_dns": ["example.com"],
        "san_ip": [],
        "pqc_capable": False,
        "pqc_details": {
            "oid": "1.2.840.113549.1.1.11",
            "algorithm_name": "sha256WithRSAEncryption",
            "is_hybrid": False,
            "pqc_status": "vulnerable",
            "hybrid_partner": None,
            "pqc_standard": None,
        },
    }
