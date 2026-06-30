import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock

from app.config import redact_sensitive, Settings


class TestRedactSensitive:
    def test_empty_string(self):
        assert redact_sensitive("") == ""

    def test_none_input(self):
        assert redact_sensitive(None) is None

    def test_no_sensitive_data(self):
        text = "This is a normal log message"
        assert redact_sensitive(text) == text

    def test_password_redacted(self):
        text = 'password="supersecret123"'
        result = redact_sensitive(text)
        assert "supersecret123" not in result
        assert 'password="***"' in result

    def test_token_redacted(self):
        text = 'token="bearer_abc123"'
        result = redact_sensitive(text)
        assert "bearer_abc123" not in result
        assert 'token="***"' in result

    def test_api_key_redacted(self):
        text = 'api_key="my-api-key-value"'
        result = redact_sensitive(text)
        assert "my-api-key-value" not in result
        assert 'api_key="***"' in result

    def test_private_key_redacted(self):
        text = 'private_key="-----BEGIN RSA PRIVATE KEY-----"'
        result = redact_sensitive(text)
        assert "-----BEGIN RSA PRIVATE KEY-----" not in result
        assert 'private_key="***"' in result

    def test_secret_redacted(self):
        text = 'secret="top-secret-value"'
        result = redact_sensitive(text)
        assert "top-secret-value" not in result
        assert 'secret="***"' in result

    def test_aws_secret_access_key_redacted(self):
        text = 'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        result = redact_sensitive(text)
        assert "wJalrXUtnFEMI" not in result
        assert 'aws_secret_access_key="***"' in result

    def test_multiple_sensitive_fields(self):
        text = 'password="abc" token="def" api_key="ghi"'
        result = redact_sensitive(text)
        assert '"abc"' not in result
        assert '"def"' not in result
        assert '"ghi"' not in result


class TestValidateSecretKey:
    def test_production_with_default_key_raises(self):
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=False):
            with pytest.raises(ValueError, match="SECRET_KEY must be set"):
                Settings(SECRET_KEY="dev-secret-key-change-me")

    def test_production_with_short_key_raises(self):
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=False):
            with pytest.raises(ValueError, match="SECRET_KEY must be set"):
                Settings(SECRET_KEY="short")

    def test_development_with_default_key_ok(self):
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=False):
            s = Settings(SECRET_KEY="dev-secret-key-change-me")
            assert s.SECRET_KEY == "dev-secret-key-change-me"

    def test_test_env_with_default_key_ok(self):
        with patch.dict(os.environ, {"APP_ENV": "test"}, clear=False):
            s = Settings(SECRET_KEY="dev-secret-key-change-me")
            assert s.SECRET_KEY == "dev-secret-key-change-me"


class TestToDictRedacted:
    def test_sensitive_fields_replaced(self):
        s = Settings(
            SECRET_KEY="my-super-secret-key-that-is-long-enough",
            DATABASE_URL="postgresql://user:pass@host/db",
            SMTP_PASSWORD="emailpass",
        )
        data = s.to_dict_redacted()
        assert data["SECRET_KEY"] == "***"
        assert data["DATABASE_URL"] == "***"
        assert data["SMTP_PASSWORD"] == "***"

    def test_non_sensitive_fields_preserved(self):
        s = Settings()
        data = s.to_dict_redacted()
        assert data["ACCESS_TOKEN_EXPIRE_MINUTES"] == 60
        assert data["REFRESH_TOKEN_EXPIRE_DAYS"] == 7
        assert data["SCAN_TIMEOUT_SECONDS"] == 30

    def test_empty_sensitive_fields_not_replaced(self):
        s = Settings(SLACK_WEBHOOK_URL="", SMTP_PASSWORD="")
        data = s.to_dict_redacted()
        assert data["SLACK_WEBHOOK_URL"] == ""
        assert data["SMTP_PASSWORD"] == ""


class TestCorsOriginsList:
    def test_single_origin(self):
        s = Settings(CORS_ORIGINS="http://localhost:3000")
        assert s.cors_origins_list == ["http://localhost:3000"]

    def test_multiple_origins(self):
        s = Settings(CORS_ORIGINS="http://a.com, http://b.com, http://c.com")
        assert s.cors_origins_list == ["http://a.com", "http://b.com", "http://c.com"]

    def test_origins_with_spaces(self):
        s = Settings(CORS_ORIGINS="  http://a.com , http://b.com  ")
        assert s.cors_origins_list == ["http://a.com", "http://b.com"]

    def test_empty_origins(self):
        s = Settings(CORS_ORIGINS="")
        assert s.cors_origins_list == []
