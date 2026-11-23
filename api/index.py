"""Vercel entry point. Wraps the existing FastAPI app without changing it."""
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # the app serves ./static relative to the project root

# Vercel's filesystem is read-only except /tmp. A REPORTS_DIR set in Vercel env vars still wins.
os.environ.setdefault("REPORTS_DIR", "/tmp/reports")

from app.main import app as fastapi_app  # noqa: E402

_started = False
_lock = None


async def app(scope, receive, send):
    """Starts the app's lifespan (shared HTTP client + providers) even if the platform doesn't send one."""
    global _started, _lock
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if not _started:
        if _lock is None:
            _lock = asyncio.Lock()
        async with _lock:
            if not _started:
                await fastapi_app.router.lifespan_context(fastapi_app).__aenter__()
                _started = True
    await fastapi_app(scope, receive, send)
