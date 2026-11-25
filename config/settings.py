from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # Application
    app_env: str = "development"
    app_secret_key: str = "dev-secret"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    # LLM
    gemini_api_key: str = ""
    llm_model: str = "gemini-2.5-flash"
    llm_max_tokens: int = 8192
    llm_temperature: float = 0.1

    # Database
    database_url: str = "postgresql://shadowhound:password@localhost:5432/shadowhound"
    weaviate_url: str = "http://localhost:8080"
    weaviate_api_key: Optional[str] = None

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Auth
    jwt_secret_key: str = "dev-jwt-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Vault
    vault_url: str = "http://localhost:8200"
    vault_token: str = "root"
    vault_mount_path: str = "shadowhound"

    # CrowdStrike
    crowdstrike_client_id: Optional[str] = None
    crowdstrike_client_secret: Optional[str] = None
    crowdstrike_base_url: str = "https://api.crowdstrike.com"

    # SentinelOne
    sentinelone_api_token: Optional[str] = None
    sentinelone_base_url: Optional[str] = None

    # Microsoft Defender
    defender_tenant_id: Optional[str] = None
    defender_client_id: Optional[str] = None
    defender_client_secret: Optional[str] = None

    # Splunk
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_token: Optional[str] = None
    splunk_index: str = "main"

    # Microsoft Sentinel
    sentinel_workspace_id: Optional[str] = None
    sentinel_workspace_key: Optional[str] = None

    # Threat Intel
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    opencti_url: Optional[str] = None
    opencti_token: Optional[str] = None

    # Telemetry
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "shadowhound-threat-hunter"

    # Hunt controls
    max_hunt_iterations: int = 5
    confidence_threshold: int = 70
    max_hunt_duration_minutes: int = 120

    class Config:
        env_file = (".env.example", ".env")
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
