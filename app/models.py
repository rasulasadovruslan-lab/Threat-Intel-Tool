import ipaddress
from typing import Any

from pydantic import BaseModel, Field, field_validator


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    refresh: bool = False         # force a new scan instead of reusing the saved one
    deep: bool = True             # also pull community comments (costs extra VirusTotal quota)


class CommunityNote(BaseModel):
    """One community-written report/comment, from any source."""
    author: str | None = None
    text: str = ""
    date: str | None = None       # ISO 8601
    categories: list[str] = []    # e.g. AbuseIPDB attack categories, hashtags from a VirusTotal comment
    extra: str | None = None      # e.g. reporter country or vote counts


class Tag(BaseModel):
    tag: str
    source: str


class ProviderResult(BaseModel):
    provider: str
    ok: bool                      # did the request itself succeed?
    data: dict[str, Any] | None = None
    error: str | None = None
    found: bool = False           # did the provider actually know this indicator?
    score: int | None = None      # normalised danger 0-100 (None = informational only)
    facts: list[str] = []         # human-readable highlights for the UI
    note: str | None = None
    tags: list[str] = []
    community: list[CommunityNote] = []


class Verdict(BaseModel):
    score: int | None
    level: str                    # low | medium | high | unknown
    sources: int
    queried: int
    summary: str


class LookupResponse(BaseModel):
    id: str                       # stable per indicator, doubles as the saved page's address
    indicator: str
    type: str
    cached: bool
    created: str
    updated: str
    verdict: Verdict
    results: list[ProviderResult]
    no_data: list[str] = []
    tags: list[Tag] = []
    deep: bool = False            # were community comments fetched for this saved scan?


# ---------- log file reports ----------

class LogEntry(BaseModel):
    ip: str = Field(max_length=64)
    count: int = Field(ge=1)                  # how many times it appears in the log
    first_line: int = Field(ge=1)
    report_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")
    score: int | None = Field(default=None, ge=0, le=100)
    level: str = Field(default="unknown", pattern=r"^(low|medium|high|unknown)$")
    tags: list[str] = Field(default=[], max_length=40)
    error: str | None = Field(default=None, max_length=200)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))   # raises on anything that is not an IP

    @field_validator("tags")
    @classmethod
    def _short_tags(cls, v: list[str]) -> list[str]:
        return [t[:60] for t in v]


class LogReportIn(BaseModel):
    filename: str = Field(max_length=200)
    total_lines: int = Field(ge=0)
    unique_ips: int = Field(ge=0)             # public IPs found
    skipped_private: int = Field(ge=0)        # private/reserved IPs ignored
    not_scanned: int = Field(ge=0)            # public IPs left out (cap reached or scan stopped)
    entries: list[LogEntry] = Field(max_length=500)


class LogReport(LogReportIn):
    id: str
    created: str
