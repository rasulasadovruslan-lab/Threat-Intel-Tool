"""Settings loaded from environment / .env. Secrets use SecretStr so they never print in logs."""
from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None  # optional: falls back to keyless InternetDB

    # VirusTotal's free key allows 4 requests per minute. The app waits instead of failing.
    # Premium key? Raise this (e.g. 300). Set VT_FETCH_COMMENTS=false to skip community comments.
    vt_requests_per_minute: int = 4
    vt_fetch_comments: bool = True

    request_timeout: float = 10.0
    cache_ttl: int = 3600                 # seconds a saved scan counts as fresh
    default_rate_limit: str = "120/minute"
    lookup_rate_limit: str = "15/minute"
    reports_dir: str = "reports"          # saved pages live here, inside the project


@lru_cache
def get_settings() -> Settings:
    return Settings()
