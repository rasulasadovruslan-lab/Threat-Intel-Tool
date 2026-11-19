import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from .ai import AIError, generate_report
from .classifier import IndicatorType as T
from .classifier import classify
from .config import get_settings
from .models import AIReport, LookupRequest, LookupResponse
from .providers import build_providers
from .storage import ReportStore
from .verdict import assess, build_verdict

logging.basicConfig(level=logging.INFO)
settings = get_settings()
store = ReportStore(settings.reports_dir)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.default_rate_limit])


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One shared client; no redirects so providers can't bounce us to arbitrary hosts.
    async with httpx.AsyncClient(
        timeout=settings.request_timeout, follow_redirects=False,
        headers={"User-Agent": "threat-intel-tool/1.0"},
    ) as client:
        app.state.client = client
        app.state.providers = build_providers(client, settings)
        yield


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
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get_or_404(rid: str) -> LookupResponse:
    rec = store.load(rid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return rec


async def resolve_public_ip(providers, domain: str) -> str | None:
    """Domain -> first public A record, so IP-only sources (AbuseIPDB, Shodan) can be checked too."""
    dns = next((p for p in providers if p.name == "dns"), None)
    if dns is None:
        return None
    for rec in await dns._query(domain, "A"):
        try:
            ip = ipaddress.ip_address(rec)
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return None


@app.post("/api/lookup", response_model=LookupResponse)
@limiter.limit(settings.lookup_rate_limit)
async def lookup(request: Request, body: LookupRequest) -> LookupResponse:
    try:
        kind, value = classify(body.indicator)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    rid = store.make_id(kind, value)
    existing = store.load(rid)
    if existing and not body.refresh:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(existing.updated)).total_seconds()
        if age < settings.cache_ttl:  # fresh saved scan: no API quota spent
            return existing.model_copy(update={"cached": True})

    all_providers = request.app.state.providers
    direct = [p for p in all_providers if kind in p.supports]
    results = list(await asyncio.gather(*(p.safe_lookup(kind, value) for p in direct)))

    if kind is T.DOMAIN and (ip := await resolve_public_ip(all_providers, value)):
        ip_only = [p for p in all_providers if T.IP in p.supports and T.DOMAIN not in p.supports]
        pivots = await asyncio.gather(*(p.safe_lookup(T.IP, ip) for p in ip_only))
        for r in pivots:
            r.note = f"Checked the domain's resolved IP ({ip})"
        results += pivots

    for r in results:
        assess(r)

    now = _now()
    response = LookupResponse(
        id=rid, indicator=value, type=kind, cached=False,
        created=existing.created if existing else now, updated=now,
        results=results, verdict=build_verdict(results),
        no_data=[r.provider for r in results if r.ok and not r.found and r.provider != "dns"],
        ai_report=existing.ai_report if existing else None,
    )
    if any(r.ok for r in results):  # never save total failures
        store.save(response)
    return response


@app.get("/api/reports")
async def list_reports() -> list[dict]:
    return store.list()


@app.get("/api/reports/{rid}", response_model=LookupResponse)
async def get_report(rid: str) -> LookupResponse:
    return _get_or_404(rid)


@app.delete("/api/reports/{rid}")
async def delete_report(rid: str) -> dict[str, bool]:
    _get_or_404(rid)
    return {"deleted": store.delete(rid)}


@app.post("/api/reports/{rid}/ai", response_model=AIReport)
@limiter.limit(settings.ai_rate_limit)
async def ai_report(request: Request, rid: str) -> AIReport:
    rec = _get_or_404(rid)
    try:
        report = await generate_report(request.app.state.client, settings, rec)
    except AIError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    rec.ai_report = report
    store.save(rec)  # the written report is saved into the page too
    return report


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
