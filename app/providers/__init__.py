"""Provider registry. To add a service: create the file, import it, append it below."""
import httpx

from ..config import Settings
from .abuseipdb import AbuseIPDB
from .base import Provider
from .dns_lookup import DNSLookup
from .shodan import Shodan
from .virustotal import VirusTotal


def build_providers(client: httpx.AsyncClient, settings: Settings) -> list[Provider]:
    all_providers = [VirusTotal, AbuseIPDB, Shodan, DNSLookup]
    return [p for p in (cls(client, settings) for cls in all_providers) if p.enabled()]
