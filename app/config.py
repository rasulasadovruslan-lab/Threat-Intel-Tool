"""Settings loaded from environment / .env. Secrets use SecretStr so they never print in logs."""
from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_token: SecretStr  # protects YOUR endpoint (required)
    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None  # optional: falls back to keyless InternetDB

    request_timeout: float = 10.0
    cache_ttl: int = 600
    rate_limit: str = "20/minute"


@lru_cache
def get_settings() -> Settings:
    return Settings()
