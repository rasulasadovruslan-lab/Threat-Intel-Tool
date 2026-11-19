"""Settings loaded from environment / .env. Secrets use SecretStr so they never print in logs."""
from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None  # optional: falls back to keyless InternetDB

    # AI report: any OpenAI-compatible provider (Groq, Gemini, OpenRouter, DeepSeek...)
    ai_api_key: SecretStr | None = None
    ai_base_url: str = "https://api.groq.com/openai/v1"
    ai_model: str = "openai/gpt-oss-120b"

    request_timeout: float = 10.0
    ai_timeout: float = 60.0
    cache_ttl: int = 3600                 # seconds a saved scan counts as fresh
    default_rate_limit: str = "120/minute"
    lookup_rate_limit: str = "15/minute"
    ai_rate_limit: str = "5/minute"
    ai_cooldown: int = 120                # seconds before the same report can be (re)generated again
    ai_daily_limit: int = 20              # max AI reports per day, protects your free AI quota
    reports_dir: str = "reports"          # saved pages live here, inside the project


@lru_cache
def get_settings() -> Settings:
    return Settings()
