"""Application configuration via environment variables. Sensitive values use SecretStr."""

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
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
    # Set RATE_LIMIT_ENABLED=false in tests / local dev when hammering the API.
    rate_limit_enabled: bool = True

    # Observability
    jaeger_host: str = "localhost"
    jaeger_port: int = 6831
    environment: str = "development"
    service_version: str = "1.0.0"

    # Database (sensitive)
    database_url: SecretStr = SecretStr("sqlite:///./soc_platform.db")

    # AI Providers
    ai_provider: Literal["openai", "anthropic", "azure", "gemini", "bedrock", "groq", "mistral", "ollama"] = "openai"
    openai_api_key: SecretStr = SecretStr("")
    openai_model: str = "gpt-4o"
    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-sonnet-4-6"
    azure_openai_api_key: SecretStr = SecretStr("")
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = ""
    # Google Gemini
    gemini_api_key: SecretStr = SecretStr("")
    gemini_model: str = "gemini-2.0-flash"
    # AWS Bedrock (reuses AWS IAM credentials)
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    # Groq
    groq_api_key: SecretStr = SecretStr("")
    groq_model: str = "llama-3.3-70b-versatile"
    # Mistral AI
    mistral_api_key: SecretStr = SecretStr("")
    mistral_model: str = "mistral-large-latest"
    # Ollama (local / self-hosted)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Azure / Microsoft Sentinel
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: SecretStr = SecretStr("")
    loganalytics_workspace_id: str = ""

    # AWS (GuardDuty + CloudTrail)
    aws_access_key_id: str = ""
    aws_secret_access_key: SecretStr = SecretStr("")
    aws_region: str = "us-east-1"
    cloudtrail_trail_name: str = ""

    # Azure shared (Sentinel, Defender for Cloud, Azure AD, M365 fallback)
    azure_subscription_id: str = ""

    # CrowdStrike Falcon
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: SecretStr = SecretStr("")
    crowdstrike_base_url: str = "https://api.crowdstrike.com"

    # SentinelOne
    s1_console_url: str = ""
    s1_api_token: SecretStr = SecretStr("")
    s1_site_id: str = ""

    # Carbon Black Cloud
    cbc_org_key: str = ""
    cbc_api_key: SecretStr = SecretStr("")
    cbc_api_id: str = ""
    cbc_base_url: str = ""

    # Palo Alto Cortex XDR
    cortex_api_key: SecretStr = SecretStr("")
    cortex_api_key_id: str = ""
    cortex_base_url: str = ""

    # Splunk
    splunk_host: str = ""
    splunk_port: int = 8089
    splunk_token: SecretStr = SecretStr("")
    splunk_query: str = "search index=notable earliest=-5m | head 1000"

    # IBM QRadar
    qradar_host: str = ""
    qradar_token: SecretStr = SecretStr("")

    # Elastic Security
    elastic_host: str = ""
    elastic_api_key: SecretStr = SecretStr("")

    # Okta
    okta_domain: str = ""
    okta_api_token: SecretStr = SecretStr("")

    # Palo Alto NGFW (PAN-OS XML API)
    panos_host: str = ""
    panos_api_key: SecretStr = SecretStr("")
    panos_vsys: str = "vsys1"

    # Fortinet FortiGate
    fortigate_host: str = ""
    fortigate_api_key: SecretStr = SecretStr("")
    fortigate_vdom: str = "root"

    # Microsoft 365 Defender
    m365_tenant_id: str = ""
    m365_client_id: str = ""
    m365_client_secret: SecretStr = SecretStr("")

    # Google Workspace
    gworkspace_service_account_key: SecretStr = SecretStr("")
    gworkspace_admin_email: str = ""

    # GCP Security Command Center
    gcp_org_id: str = ""
    gcp_service_account_key: SecretStr = SecretStr("")

    # Tenable.io
    tenable_access_key: SecretStr = SecretStr("")
    tenable_secret_key: SecretStr = SecretStr("")

    # Qualys VMDR
    qualys_api_url: str = ""
    qualys_username: str = ""
    qualys_password: SecretStr = SecretStr("")

    # Threat Intel / Enrichment
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    shodan_api_key: SecretStr = SecretStr("")

    # Notifications
    slack_webhook_url: SecretStr = SecretStr("")
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    alert_email_to: str = ""

    # Scheduled reports worker
    scheduled_reports_poll_seconds: int = 60
    scheduled_reports_retry_minutes: int = 15

    # Durable background job queue
    job_queue_poll_seconds: int = 5
    job_queue_batch_size: int = 100
    job_queue_max_attempts: int = 5
    job_queue_retry_backoff_seconds: int = 15

    # Source health and ingestion SLOs
    source_health_window_hours: int = 24
    source_health_stale_after_minutes: int = 45
    source_health_error_budget_failure_rate: float = 0.05
    source_health_alert_cooldown_minutes: int = 60
    source_health_monitor_poll_seconds: int = 60

    # LDAP / directory sync
    ldap_server_url: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: SecretStr = SecretStr("")
    ldap_search_base: str = ""
    ldap_search_filter: str = "(objectClass=person)"

    # Security / CORS
    allowed_origins: str = "http://localhost:3000,http://localhost:5173,http://localhost:8000"
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
