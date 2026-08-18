from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_base_url: str = "http://localhost:8080"
    store_backend: str = "memory"
    google_cloud_project: str | None = None
    firestore_database: str = "(default)"
    cloud_run_region: str = "asia-southeast1"
    scanner_job_name: str = "zap-scanner"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = ""
    ai_enrich_per_request: int = 20
    max_active_scans: int = 3
    scan_token_secret: str = "development-only"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

