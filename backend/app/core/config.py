from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")
    database_url: str = ""
    frontend_origins: list[str] = ["http://localhost:5174", "http://127.0.0.1:5174"]
    scan_timeout_seconds: float = Field(default=10, ge=1, le=30)
    crawler_max_depth: int = Field(default=3, ge=0, le=10)
    crawler_max_pages: int = Field(default=50, ge=1, le=500)
    crawler_max_requests: int = Field(default=250, ge=1, le=5000)
    crawler_max_static_requests: int = Field(default=500, ge=0, le=10000)
    crawler_timeout_seconds: float = Field(default=15, ge=1, le=60)
    crawler_wait_after_load_ms: int = Field(default=500, ge=0, le=5000)
    manual_api_max_requests: int = Field(default=20, ge=1, le=100)
    manual_api_request_delay_ms: int = Field(default=100, ge=0, le=5000)
    sensitive_body_max_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)
    authz_max_scenarios: int = Field(default=20, ge=1, le=100)
    authz_max_requests: int = Field(default=100, ge=1, le=1000)
    authz_request_timeout: float = Field(default=10, ge=1, le=30)
    authz_request_delay_ms: int = Field(default=150, ge=0, le=5000)
    authz_execution_stale_seconds: int = Field(default=900, ge=60, le=86400)
    active_max_requests: int = Field(default=50, ge=1, le=200)
    active_max_endpoints: int = Field(default=10, ge=1, le=50)
    active_max_parameters: int = Field(default=20, ge=1, le=100)
    active_max_parameters_per_module: int = Field(default=5, ge=1, le=20)
    active_request_timeout: float = Field(default=8, ge=1, le=30)
    active_request_delay_ms: int = Field(default=100, ge=0, le=5000)
    dast_secret_key: SecretStr | None = None
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
