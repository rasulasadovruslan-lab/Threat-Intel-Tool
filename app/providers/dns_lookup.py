from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from ..classifier import IndicatorType as T
from .base import Provider

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DNSLookup(Provider):
    name = "dns"
    supports = frozenset({T.DOMAIN, T.IP})

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = 5.0

    async def _query(self, name: str, rtype: str) -> list[str]:
        try:
            answer = await self.resolver.resolve(name, rtype)
            return [r.to_text() for r in answer]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []

    async def lookup(self, kind: T, value: str, deep: bool = True) -> dict[str, Any]:
        if kind is T.IP:
            return {"PTR": await self._query(dns.reversename.from_address(value).to_text(), "PTR")}
        return {rt: await self._query(value, rt) for rt in RECORD_TYPES}
