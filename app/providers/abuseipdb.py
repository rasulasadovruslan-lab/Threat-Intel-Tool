from typing import Any

from ..classifier import IndicatorType as T
from .base import Provider


class AbuseIPDB(Provider):
    name = "abuseipdb"
    supports = frozenset({T.IP})
    key_attr = "abuseipdb_api_key"

    async def lookup(self, kind: T, value: str) -> dict[str, Any]:
        r = await self.client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": self.key, "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {k: d.get(k) for k in (
            "abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
            "isp", "usageType", "domain", "isTor", "lastReportedAt",
        )}
