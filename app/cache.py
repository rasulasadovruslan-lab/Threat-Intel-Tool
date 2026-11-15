"""Tiny in-memory TTL cache. Saves API quota on repeat lookups. Swap for Redis if you scale out."""
import time
from typing import Any


class TTLCache:
    def __init__(self, ttl: int, max_items: int = 1000) -> None:
        self.ttl, self.max_items = ttl, max_items
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self._store.get(key)
        if not item:
            return None
        expires, value = item
        if expires < time.monotonic():
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if len(self._store) >= self.max_items:
            self._store.pop(next(iter(self._store)))  # evict oldest
        self._store[key] = (time.monotonic() + self.ttl, value)
