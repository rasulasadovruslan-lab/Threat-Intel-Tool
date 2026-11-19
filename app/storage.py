"""Saves every scan as a JSON file in ./reports so each result is a permanent, shareable page.
IDs are a hash of the indicator and validated with a strict regex, so no path traversal is possible."""
import hashlib
import os
import re
from pathlib import Path

from .models import LookupResponse

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

    def list(self, limit: int = 60) -> list[dict]:
        files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        out = []
        for f in files:
            rec = self.load(f.stem)
            if rec:
                out.append({"id": rec.id, "indicator": rec.indicator, "type": rec.type,
                            "score": rec.verdict.score, "level": rec.verdict.level,
                            "updated": rec.updated, "has_ai": rec.ai_report is not None})
        return out
