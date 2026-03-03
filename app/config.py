"""Application configuration via environment variables. Sensitive values use SecretStr."""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Platform
    soc_platform_url: str = "http://localhost:8000"
    secret_key: SecretStr = SecretStr("change-me-in-production")
    debug: bool = False
    log_level: str = "INFO"

    # Observability
    jaeger_host: str = "localhost"
    jaeger_port: int = 6831
    environment: str = "development"
    service_version: str = "1.0.0"

    # Database (sensitive)
    database_url: SecretStr = SecretStr("sqlite:///./soc_platform.db")

    # AI Providers
    ai_provider: Literal["openai", "anthropic", "azure"] = "openai"
    openai_api_key: SecretStr = SecretStr("")
    anthropic_api_key: SecretStr = SecretStr("")
    azure_openai_api_key: SecretStr = SecretStr("")
    azure_openai_endpoint: str = ""

    # Azure / Microsoft Sentinel
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: SecretStr = SecretStr("")
    loganalytics_workspace_id: str = ""

    # AWS
    aws_access_key_id: str = ""
    aws_secret_access_key: SecretStr = SecretStr("")
    aws_region: str = "us-east-1"

    # Threat Intel
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")

    # Notifications
    slack_webhook_url: SecretStr = SecretStr("")
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    alert_email_to: str = ""

    # Security / CORS
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    max_request_body_bytes: int = 10 * 1024 * 1024  # 10MB
    max_url_length: int = 2048
    max_header_value_bytes: int = 8192

    # Auth / JWT
    data_dir: str = "data"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    max_sessions_per_user: int = 3
    absolute_session_timeout_hours: int = 8
    lockout_attempts: int = 5
    lockout_minutes: int = 15
    bcrypt_rounds: int = 12
    api_key_grace_hours: int = 24

    @model_validator(mode="after")
    def validate_secrets_and_hardening(self) -> "Settings":
        from app.security.secrets import validate_secrets
        from app.security.config_hardening import (
            validate_debug,
            validate_secret_key,
            validate_database_url,
            is_production,
        )
        prod = is_production()
        sk = self.secret_key.get_secret_value()
        du = self.database_url.get_secret_value()
        validate_secrets(secret_key=sk, database_url=du, is_production=prod)
        validate_debug(self.debug)
        if prod:
            validate_secret_key(sk)
            validate_database_url(du)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
