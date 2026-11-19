import asyncio
import csv
import io
import ipaddress
import logging
from contextlib import asynccontextmanager
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
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
_ai_last: dict[str, float] = {}          # rid -> monotonic time of last AI call (blocks double-clicks)
_ai_day = {"date": "", "count": 0}      # resets every UTC day
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


@app.get("/api/status")
async def status(request: Request) -> dict:
    """Which sources are live. Never returns keys, only on/off."""
    names = {p.name for p in request.app.state.providers}
    return {
        "virustotal": "virustotal" in names,
        "abuseipdb": "abuseipdb" in names,
        "shodan": "full" if settings.shodan_api_key else "free",
        "dns": "dns" in names,
        "ai": bool(settings.ai_api_key),
        "ai_cooldown": settings.ai_cooldown,
    }


def _csv_safe(v) -> str:
    s = str(v if v is not None else "")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # block spreadsheet formula injection


@app.get("/api/reports/export.csv")
async def export_csv() -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator", "type", "score_percent", "level", "last_scanned_utc", "has_ai_report"])
    for it in store.list(limit=100000):
        w.writerow([_csv_safe(it["indicator"]), it["type"], it["score"] if it["score"] is not None else "",
                    it["level"], it["updated"], it["has_ai"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="threatscope-reports.csv"'})


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


def _ai_gate(rid: str, rec: LookupResponse) -> None:
    """Raises 429 with a readable message when a cooldown or the daily cap applies."""
    wait = 0.0
    if rec.ai_report:
        done = datetime.fromisoformat(rec.ai_report.generated_at)
        wait = settings.ai_cooldown - (datetime.now(timezone.utc) - done).total_seconds()
    if rid in _ai_last:
        wait = max(wait, settings.ai_cooldown - (time.monotonic() - _ai_last[rid]))
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Please wait {int(wait) + 1}s before generating this report again.")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if _ai_day["date"] != today:
        _ai_day.update(date=today, count=0)
    if _ai_day["count"] >= settings.ai_daily_limit:
        raise HTTPException(status_code=429, detail=f"Daily AI limit reached ({settings.ai_daily_limit} reports). Try again tomorrow.")


@app.post("/api/reports/{rid}/ai", response_model=AIReport)
@limiter.limit(settings.ai_rate_limit)
async def ai_report(request: Request, rid: str) -> AIReport:
    rec = _get_or_404(rid)
    _ai_gate(rid, rec)
    _ai_last[rid] = time.monotonic()  # claim the slot first so a second click can't slip through
    try:
        report = await generate_report(request.app.state.client, settings, rec)
    except AIError as e:
        _ai_last.pop(rid, None)  # failed attempts don't cost the user a cooldown or a daily slot
        raise HTTPException(status_code=502, detail=str(e)) from e
    _ai_day["count"] += 1
    rec.ai_report = report
    store.save(rec)  # the written report is saved into the page too
    return report


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
