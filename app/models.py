from typing import Any

from pydantic import BaseModel, Field


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    refresh: bool = False         # force a new scan instead of reusing the saved one


class ProviderResult(BaseModel):
    provider: str
    ok: bool                      # did the request itself succeed?
    data: dict[str, Any] | None = None
    error: str | None = None
    found: bool = False           # did the provider actually know this indicator?
    score: int | None = None      # normalised danger 0-100 (None = informational only)
    facts: list[str] = []         # human-readable highlights for the UI
    note: str | None = None


class Verdict(BaseModel):
    score: int | None
    level: str                    # low | medium | high | unknown
    sources: int
    queried: int
    summary: str


class AIReport(BaseModel):
    headline: str
    summary: str
    key_findings: list[str]
    risk_assessment: str
    recommendations: list[str]
    confidence: str
    model: str
    generated_at: str


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
    ai_report: AIReport | None = None
