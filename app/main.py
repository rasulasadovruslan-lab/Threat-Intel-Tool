import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from .cache import TTLCache
from .classifier import classify
from .config import get_settings
from .models import LookupRequest, LookupResponse
from .providers import build_providers
from .security import require_token

logging.basicConfig(level=logging.INFO)
settings = get_settings()
cache = TTLCache(settings.cache_ttl)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One shared client; no redirects so providers can't bounce us to arbitrary hosts.
    async with httpx.AsyncClient(
        timeout=settings.request_timeout, follow_redirects=False,
        headers={"User-Agent": "threat-intel-tool/1.0"},
    ) as client:
        app.state.providers = build_providers(client, settings)
        yield


# Interactive docs disabled: nothing extra exposed.
app = FastAPI(title="Threat Intel Lookup", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    )
    return response


@app.post("/api/lookup", response_model=LookupResponse, dependencies=[Depends(require_token)])
async def lookup(request: Request, body: LookupRequest) -> LookupResponse:
    try:
        kind, value = classify(body.indicator)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    key = f"{kind}:{value}"
    if (hit := cache.get(key)) is not None:
        return LookupResponse(indicator=value, type=kind, cached=True, results=hit)

    providers = [p for p in request.app.state.providers if kind in p.supports]
    results = await asyncio.gather(*(p.safe_lookup(kind, value) for p in providers))

    if any(r.ok for r in results):  # don't cache total failures
        cache.set(key, results)
    return LookupResponse(indicator=value, type=kind, cached=False, results=list(results))


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
