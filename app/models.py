from typing import Any

from pydantic import BaseModel, Field


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


class ProviderResult(BaseModel):
    provider: str
    ok: bool
    data: dict[str, Any] | None = None
    error: str | None = None


class LookupResponse(BaseModel):
    indicator: str
    type: str
    cached: bool
    results: list[ProviderResult]
