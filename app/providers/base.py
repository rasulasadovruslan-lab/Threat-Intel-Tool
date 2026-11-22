"""Shared provider interface. Add a new service = subclass Provider, implement lookup(), register it."""
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..classifier import IndicatorType
from ..config import Settings
from ..models import ProviderResult

log = logging.getLogger(__name__)


class Provider(ABC):
    name: str
    supports: frozenset[IndicatorType]
    key_attr: str | None = None  # Settings attribute holding this provider's key

    def __init__(self, client: httpx.AsyncClient, settings: Settings) -> None:
        self.client = client
        self._key = getattr(settings, self.key_attr) if self.key_attr else None

    @property
    def key(self) -> str:
        return self._key.get_secret_value() if self._key else ""

    def enabled(self) -> bool:
        return self.key_attr is None or bool(self.key)

    @abstractmethod
    async def lookup(self, kind: IndicatorType, value: str, deep: bool = True) -> dict[str, Any]: ...

    async def safe_lookup(self, kind: IndicatorType, value: str, deep: bool = True) -> ProviderResult:
        """Never raises, and never leaks URLs/keys in error text (Shodan puts its key in the query string)."""
        try:
            return ProviderResult(provider=self.name, ok=True, data=await self.lookup(kind, value, deep))
        except httpx.HTTPStatusError as e:
            msg = {401: "Invalid API key", 403: "Forbidden", 429: "Rate limited"}.get(
                e.response.status_code, f"HTTP {e.response.status_code}"
            )
        except httpx.TimeoutException:
            msg = "Timed out"
        except Exception as e:  # noqa: BLE001
            log.warning("%s failed: %s", self.name, type(e).__name__)
            msg = "Provider error"
        return ProviderResult(provider=self.name, ok=False, error=msg)
