import logging
import os
import re
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

logger = logging.getLogger(__name__)

# Regex patterns for sensitive data that should be redacted in logs
SENSITIVE_PATTERNS = [
    (
        re.compile(
            r'(aws_secret_access_key|aws_secret_key|secret_access_key)["\s:=]+([^"\s,}]+)',
            re.I,
        ),
        r'\1="***"',
    ),
    (
        re.compile(
            r'(aws_access_key_id|aws_access_key|access_key_id)["\s:=]+([^"\s,}]+)', re.I
        ),
        r'\1="***"',
    ),
    (
        re.compile(r'(client_secret|client_secret_key)["\s:=]+([^"\s,}]+)', re.I),
        r'\1="***"',
    ),
    (re.compile(r'(client_id)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(tenant_id)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(secret_key|secret)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(password|passwd|pwd)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(token|bearer)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(api_key|apikey)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(private_key|privatekey)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
    (re.compile(r'(credentials_json)["\s:=]+([^"\s,}]+)', re.I), r'\1="***"'),
]


def redact_sensitive(text: str) -> str:
    """Redact sensitive values from a string for safe logging."""
    if not text:
        return text
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# Dynamically find the .env file in the project root or backend dir
_backend_dir = Path(__file__).resolve().parent.parent
_project_root = _backend_dir.parent
_env_files: list[str | Path] = [
    str(_project_root / ".env"),
    str(_backend_dir / ".env"),
    ".env",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_env_files, extra="ignore")

    # SSRF / DNS-rebinding safe target resolution settings
    PQC_ALLOW_PRIVATE_RANGES: bool = False
    PQC_ALLOW_LOOPBACK: bool = False
    PQC_ALLOW_LINK_LOCAL: bool = False
    PQC_ALLOW_MULTICAST: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt"
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    SECRET_KEY: str = "dev-secret-key-change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ORIGINS: str = "http://localhost:3000"
    OFFLINE_MODE: bool = False
    SCAN_THROTTLE_RATE: str = "10/m"
    SCAN_TIMEOUT_SECONDS: int = 30
    SCAN_DEDUP_WINDOW_HOURS: int = (
        24  # Hours to wait before allowing re-scan of same target+port
    )
    SCAN_MAX_DURATION_SECONDS: int = (
        3600  # 1 hour maximum execution duration for a scan
    )
    # Quantum timeline year (Y in Mosca's X+Y>Z). Mosca's published estimate
    # is 2034; override per-deployment via env.
    QUANTUM_TIMELINE_YEAR: int = 2034
    SCAN_SCHEDULE_CRON: str = "0 2 * * *"  # Default 2 AM daily
    # Dashboard cache TTL (seconds)
    DASHBOARD_CACHE_TTL_SECONDS: int = 60
    # Database connection pool
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    # Rate-limiting (token-bucket)
    RATE_LIMIT_RPS: int = 10
    RATE_LIMIT_BURST: int = 20
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_ADDRESS: str = ""

    # Vault Integration Settings
    VAULT_URL: str = ""
    VAULT_TOKEN: str = ""
    VAULT_NAMESPACE: str = ""
    VAULT_PQC_PATH: str = "secret/pqc"

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        insecure = "change-me" in value or len(value) < 32
        if insecure:
            import sys

            in_test = "pytest" in sys.modules or "test" in sys.argv
            env_name = os.environ.get(
                "APP_ENV",
                os.environ.get(
                    "ENVIRONMENT", "development" if in_test else "production"
                ),
            ).lower()
            is_production = env_name not in (
                "development",
                "dev",
                "test",
                "testing",
                "local",
            )
            if is_production:
                raise ValueError(
                    "SECRET_KEY must be set to a secure random string (at least 32 characters) in production environments."
                )
            logger.warning(
                "SECRET_KEY is using the default development value. "
                "Set the SECRET_KEY environment variable before running in production."
            )
        return value

    def to_dict_redacted(self) -> dict:
        """Return settings as dict with sensitive values redacted for logging."""
        data = self.model_dump()
        # Redact sensitive fields
        sensitive_fields = {
            "DATABASE_URL",
            "REDIS_URL",
            "CELERY_BROKER_URL",
            "CELERY_RESULT_BACKEND",
            "SECRET_KEY",
            "SMTP_PASSWORD",
            "SMTP_USER",
            "VAULT_TOKEN",
            "VAULT_PASSWORD",
            "SLACK_WEBHOOK_URL",
            "SMTP_HOST",
            "SMTP_FROM_ADDRESS",
        }
        for field in sensitive_fields:
            if field in data and data[field]:
                data[field] = "***"
        return data

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()
        ]


settings = Settings()
