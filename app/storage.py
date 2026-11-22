"""Saves every scan as a JSON file in ./reports so each result is a permanent, shareable page.
IDs are a hash of the indicator and validated with a strict regex, so no path traversal is possible."""
import hashlib
import os
import re
import secrets
from pathlib import Path

from .models import LogReport, LookupResponse
from .verdict import collect_tags

ID_RE = re.compile(r"^[a-f0-9]{16}$")


class ReportStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def make_id(kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16]

    def _path(self, rid: str) -> Path:
        if not ID_RE.fullmatch(rid):
            raise ValueError("bad id")
        return self.root / f"{rid}.json"

    def load(self, rid: str) -> LookupResponse | None:
        try:
            return LookupResponse.model_validate_json(self._path(rid).read_text("utf-8"))
        except (ValueError, OSError):
            return None

    def save(self, rec: LookupResponse) -> None:
        path = self._path(rec.id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(rec.model_dump_json(indent=2), "utf-8")
        os.replace(tmp, path)  # atomic: never leaves a half-written file

    def delete(self, rid: str) -> bool:
        try:
            self._path(rid).unlink()
            return True
        except (ValueError, OSError):
            return False

    def list(self, limit: int = 500) -> list[dict]:
        files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        out = []
        for f in files:
            rec = self.load(f.stem)
            if rec:
                tags = sorted({t.tag for t in (rec.tags or collect_tags(rec.results))})
                out.append({"id": rec.id, "indicator": rec.indicator, "type": rec.type,
                            "score": rec.verdict.score, "level": rec.verdict.level,
                            "updated": rec.updated, "tags": tags})
        return out


class LogStore:
    """Log-file scan reports live in reports/logs/ so they never mix with single-indicator scans."""

    def __init__(self, root: str) -> None:
        self.root = Path(root) / "logs"
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def new_id() -> str:
        return secrets.token_hex(8)

    def _path(self, lid: str) -> Path:
        if not ID_RE.fullmatch(lid):
            raise ValueError("bad id")
        return self.root / f"{lid}.json"

    def load(self, lid: str) -> LogReport | None:
        try:
            return LogReport.model_validate_json(self._path(lid).read_text("utf-8"))
        except (ValueError, OSError):
            return None

    def save(self, rep: LogReport) -> None:
        path = self._path(rep.id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(rep.model_dump_json(indent=2), "utf-8")
        os.replace(tmp, path)

    def delete(self, lid: str) -> bool:
        try:
            self._path(lid).unlink()
            return True
        except (ValueError, OSError):
            return False

    def list(self, limit: int = 50) -> list[dict]:
        files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        out = []
        for f in files:
            rep = self.load(f.stem)
            if rep:
                lv = [e.level for e in rep.entries]
                out.append({"id": rep.id, "filename": rep.filename, "created": rep.created,
                            "scanned": len(rep.entries), "unique_ips": rep.unique_ips,
                            "high": lv.count("high"), "medium": lv.count("medium")})
        return out
