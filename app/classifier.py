"""Detects what kind of indicator the user typed and normalises it. Rejects everything else."""
import ipaddress
import re
from enum import StrEnum
from urllib.parse import urlsplit


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def classify(raw: str) -> tuple[IndicatorType, str]:
    value = raw.strip().replace("[.]", ".").replace("hxxp", "http")  # un-defang
    if not value or len(value) > 2048:
        raise ValueError("Empty or too long")

    if HASH_RE.match(value):
        return IndicatorType.HASH, value.lower()

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if not ip.is_global:
            raise ValueError("Private or reserved IP addresses are not allowed")
        return IndicatorType.IP, str(ip)

    if value.lower().startswith(("http://", "https://")):
        if not urlsplit(value).hostname:
            raise ValueError("Invalid URL")
        return IndicatorType.URL, value

    domain = value.lower().rstrip(".")
    if DOMAIN_RE.match(domain):
        return IndicatorType.DOMAIN, domain

    raise ValueError("Not a valid IP, domain, URL or MD5/SHA1/SHA256 hash")
