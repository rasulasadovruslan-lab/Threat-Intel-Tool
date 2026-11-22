from typing import Any

from ..classifier import IndicatorType as T
from .base import Provider


class AbuseIPDB(Provider):
    name = "abuseipdb"
    supports = frozenset({T.IP})
    key_attr = "abuseipdb_api_key"

    async def lookup(self, kind: T, value: str, deep: bool = True) -> dict[str, Any]:
        r = await self.client.get(
            "https://api.abuseipdb.com/api/v2/check",
            # `verbose` adds the list of individual community reports (comment, categories, date)
            # to the same call, so it costs no extra quota.
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.key, "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json()["data"]
        out = {k: d.get(k) for k in (
            "abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
            "isp", "usageType", "domain", "isTor", "lastReportedAt",
        )}
        out["reports"] = [
            {"date": x.get("reportedAt"), "comment": (x.get("comment") or "")[:2000],
             "categories": x.get("categories") or [], "country": x.get("reporterCountryName") or x.get("reporterCountryCode")}
            for x in (d.get("reports") or [])[:100]
        ]
        return out
