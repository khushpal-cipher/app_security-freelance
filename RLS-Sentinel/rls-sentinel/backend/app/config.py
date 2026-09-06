from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./rls_sentinel.db"
    rate_limit_rps: float = 5.0
    scan_request_rate_limit: str = "10/minute"
    http_timeout_seconds: float = 10.0
    allowed_host_suffixes: tuple[str, ...] = ("supabase.co", "supabase.in")
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
