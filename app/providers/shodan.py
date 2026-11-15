from typing import Any

import httpx

from ..classifier import IndicatorType as T
from .base import Provider


class Shodan(Provider):
    """Uses the full Shodan API when a key is set (and valid), otherwise the free keyless InternetDB."""

    name = "shodan"
    supports = frozenset({T.IP})
    key_attr = "shodan_api_key"

    def enabled(self) -> bool:
        return True  # InternetDB needs no key

    async def lookup(self, kind: T, value: str) -> dict[str, Any]:
        if self.key:
            r = await self.client.get(
                f"https://api.shodan.io/shodan/host/{value}", params={"key": self.key}
            )
            if r.status_code == 404:
                return {"found": False, "source": "shodan-api"}
            if r.status_code not in (401, 402, 403):  # else fall back to InternetDB
                r.raise_for_status()
                d = r.json()
                return {
                    "found": True, "source": "shodan-api",
                    "ports": d.get("ports"), "vulns": d.get("vulns"),
                    "org": d.get("org"), "os": d.get("os"), "hostnames": d.get("hostnames"),
                }
        r = await self.client.get(f"https://internetdb.shodan.io/{value}")
        if r.status_code == 404:
            return {"found": False, "source": "internetdb"}
        r.raise_for_status()
        d = r.json()
        return {"found": True, "source": "internetdb", **{
            k: d.get(k) for k in ("ports", "vulns", "hostnames", "tags", "cpes")}}
