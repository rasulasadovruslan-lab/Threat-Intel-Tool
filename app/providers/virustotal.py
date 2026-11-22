import asyncio
import base64
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx

from ..classifier import IndicatorType as T
from ..config import Settings
from .base import Provider

BASE = "https://www.virustotal.com/api/v3"


class _Window:
    """Sliding-window limiter: at most `calls` requests per `period` seconds (waits, never fails)."""

    def __init__(self, calls: int, period: float = 60.0) -> None:
        self.calls, self.period = max(1, calls), period
        self.stamps: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            while True:
                now = time.monotonic()
                while self.stamps and now - self.stamps[0] >= self.period:
                    self.stamps.popleft()
                if len(self.stamps) < self.calls:
                    self.stamps.append(now)
                    return
                await asyncio.sleep(self.period - (now - self.stamps[0]) + 0.05)


class VirusTotal(Provider):
    name = "virustotal"
    supports = frozenset(T)
    key_attr = "vt_api_key"

    def __init__(self, client: httpx.AsyncClient, settings: Settings) -> None:
        super().__init__(client, settings)
        self.window = _Window(settings.vt_requests_per_minute)
        self.fetch_comments = settings.vt_fetch_comments

    async def _get(self, path: str, **params: Any) -> httpx.Response:
        await self.window.wait()
        return await self.client.get(BASE + path, headers={"x-apikey": self.key}, params=params or None)

    async def _comments(self, path: str) -> list[dict[str, Any]]:
        """Community comments. A failure here must never break the main lookup."""
        try:
            r = await self._get(path + "/comments", limit=40)
            if r.status_code != 200:
                return []
            out = []
            for c in r.json().get("data", []):
                a = c.get("attributes", {})
                ts = a.get("date")
                out.append({
                    "date": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds") if ts else None,
                    "text": (a.get("text") or "")[:2000],
                    "votes": a.get("votes") or {},
                    "tags": a.get("tags") or [],
                })
            return out
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return []

    async def lookup(self, kind: T, value: str, deep: bool = True) -> dict[str, Any]:
        if kind is T.URL:
            path = "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else:
            path = {T.IP: "/ip_addresses/", T.DOMAIN: "/domains/", T.HASH: "/files/"}[kind] + value
        r = await self._get(path)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        a = r.json()["data"]["attributes"]
        return {
            "found": True,
            "stats": a.get("last_analysis_stats"),
            "reputation": a.get("reputation"),
            "tags": a.get("tags"),
            "names": a.get("names", [])[:5],
            "country": a.get("country"),
            "as_owner": a.get("as_owner"),
            "total_votes": a.get("total_votes"),          # community harmless/malicious votes
            "comments": await self._comments(path) if (deep and self.fetch_comments) else [],
        }
