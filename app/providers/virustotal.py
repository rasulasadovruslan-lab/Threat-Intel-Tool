import base64
from typing import Any

from ..classifier import IndicatorType as T
from .base import Provider

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Provider):
    name = "virustotal"
    supports = frozenset(T)
    key_attr = "vt_api_key"

    async def lookup(self, kind: T, value: str) -> dict[str, Any]:
        if kind is T.URL:
            path = "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else:
            path = {T.IP: "/ip_addresses/", T.DOMAIN: "/domains/", T.HASH: "/files/"}[kind] + value
        r = await self.client.get(BASE + path, headers={"x-apikey": self.key})
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
        }
