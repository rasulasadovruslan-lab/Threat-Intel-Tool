from typing import Any

from pydantic import BaseModel, Field


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


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
    sources: int                  # scoring sources that had data
    queried: int                  # scoring sources we asked
    summary: str


class LookupResponse(BaseModel):
    indicator: str
    type: str
    cached: bool
    verdict: Verdict
    results: list[ProviderResult]
    no_data: list[str] = []
