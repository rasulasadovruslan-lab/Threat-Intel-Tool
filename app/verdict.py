"""Turns raw provider data into (a) readable facts + a 0-100 danger score per source,
and (b) one combined verdict. All scoring rules live here so they're easy to tweak."""
from collections import Counter

from .models import CommunityNote, ProviderResult, Tag, Verdict

WEIGHTS = {"virustotal": 0.50, "abuseipdb": 0.35, "shodan": 0.15}
RISKY_PORTS = {21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017}

# AbuseIPDB attack category ids -> names (from their API docs)
ABUSE_CATEGORIES = {
    1: "DNS compromise", 2: "DNS poisoning", 3: "Fraud orders", 4: "DDoS attack", 5: "FTP brute-force",
    6: "Ping of death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open proxy", 10: "Web spam", 11: "Email spam",
    12: "Blog spam", 13: "VPN IP", 14: "Port scan", 15: "Hacking", 16: "SQL injection", 17: "Spoofing",
    18: "Brute-force", 19: "Bad web bot", 20: "Exploited host", 21: "Web app attack", 22: "SSH", 23: "IoT targeted",
}


def _virustotal(r: ProviderResult, d: dict) -> None:
    if not d.get("found"):
        return
    s = d.get("stats") or {}
    mal, sus, total = s.get("malicious", 0), s.get("suspicious", 0), sum(s.values())
    r.found, r.score = True, min(100, mal * 10 + sus * 4)
    r.facts.append(f"{mal} of {total} security engines flag it as malicious")
    if sus:
        r.facts.append(f"{sus} more mark it suspicious")
    if d.get("reputation") is not None:
        r.facts.append(f"Community reputation: {d['reputation']}")
    if d.get("as_owner") or d.get("country"):
        r.facts.append(f"Owner: {d.get('as_owner') or '?'} ({d.get('country') or '?'})")
    votes = d.get("total_votes") or {}
    if votes.get("harmless") or votes.get("malicious"):
        r.facts.append(f"Community votes: {votes.get('harmless', 0)} harmless, {votes.get('malicious', 0)} malicious")
    if d.get("tags"):
        r.facts.append("Tags: " + ", ".join(d["tags"][:6]))
        r.tags = [str(t) for t in d["tags"]]
    for c in d.pop("comments", None) or []:   # moved out of the raw data into the community list
        v = c.get("votes") or {}
        r.community.append(CommunityNote(
            text=c.get("text") or "", date=c.get("date"), categories=[str(t) for t in c.get("tags") or []],
            extra=f"{v.get('positive', 0)} up / {v.get('negative', 0)} down" if (v.get("positive") or v.get("negative")) else None))
    if d.get("names"):
        r.facts.append("Known file names: " + ", ".join(d["names"][:3]))


def _abuseipdb(r: ProviderResult, d: dict) -> None:
    score, reports = d.get("abuseConfidenceScore") or 0, d.get("totalReports") or 0
    raw = d.pop("reports", None) or []        # moved out of the raw data into the community list
    if not score and not reports:
        return  # no abuse history = nothing to show
    seen: Counter[str] = Counter()
    for x in raw:
        cats = [ABUSE_CATEGORIES.get(c, f"category {c}") for c in x.get("categories") or []]
        seen.update(cats)
        r.community.append(CommunityNote(
            text=(x.get("comment") or "").strip(), date=x.get("date"), categories=cats,
            extra=f"Reported from {x['country']}" if x.get("country") else None))
    r.tags = [c for c, _ in seen.most_common(12)]
    if d.get("isTor"):
        r.tags.append("tor")
    if d.get("usageType"):
        r.tags.append(str(d["usageType"]))
    r.found, r.score = True, score
    r.facts.append(f"Abuse confidence: {score}%")
    r.facts.append(f"{reports} reports from {d.get('numDistinctUsers') or 0} users (last 90 days)")
    if d.get("isp"):
        r.facts.append(f"ISP: {d['isp']} ({d.get('countryCode') or '?'})")
    if d.get("usageType"):
        r.facts.append(f"Usage type: {d['usageType']}")
    if d.get("isTor"):
        r.facts.append("Tor exit node")
    if d.get("lastReportedAt"):
        r.facts.append(f"Last reported: {d['lastReportedAt'][:10]}")


def _shodan(r: ProviderResult, d: dict) -> None:
    if not d.get("found"):
        return
    ports, vulns = d.get("ports") or [], d.get("vulns") or []
    risky = sorted(set(ports) & RISKY_PORTS)
    r.found, r.score = True, min(100, len(vulns) * 12 + len(risky) * 8)
    r.facts.append(f"{len(ports)} open ports: {', '.join(map(str, ports[:15])) or 'none'}")
    if risky:
        r.facts.append(f"Risky exposed services on ports: {', '.join(map(str, risky))}")
    if vulns:
        r.facts.append(f"{len(vulns)} known vulnerabilities (e.g. {', '.join(vulns[:4])})")
    if d.get("org"):
        r.facts.append(f"Organisation: {d['org']}")
    if d.get("hostnames"):
        r.facts.append("Hostnames: " + ", ".join(d["hostnames"][:3]))
    if d.get("tags"):
        r.tags = [str(t) for t in d["tags"]]
        r.facts.append("Tags: " + ", ".join(r.tags[:6]))


def _dns(r: ProviderResult, d: dict) -> None:
    records = {k: v for k, v in d.items() if v}
    if not records:
        return
    r.found = True  # informational: no score
    for k, v in records.items():
        r.facts.append(f"{k}: " + " | ".join(v[:3]) + (" …" if len(v) > 3 else ""))


_ASSESSORS = {"virustotal": _virustotal, "abuseipdb": _abuseipdb, "shodan": _shodan, "dns": _dns}


def assess(r: ProviderResult) -> None:
    if r.ok and r.data is not None and r.provider in _ASSESSORS:
        _ASSESSORS[r.provider](r, r.data)


def _level(score: int) -> str:
    return "low" if score < 15 else "medium" if score < 50 else "high"


def build_verdict(results: list[ProviderResult]) -> Verdict:
    queried = sum(1 for r in results if r.provider in WEIGHTS)
    scored = [r for r in results if r.found and r.score is not None]
    if not scored:
        return Verdict(score=None, level="unknown", sources=0, queried=queried,
                       summary="None of the threat sources has any data on this indicator.")
    wsum = sum(WEIGHTS[r.provider] for r in scored)
    avg = sum(r.score * WEIGHTS[r.provider] for r in scored) / wsum
    top = max(r.score for r in scored)
    score = round(0.5 * avg + 0.5 * top)  # a single strong signal is never fully diluted
    level = _level(score)
    flagged = [r.provider for r in scored if r.score >= 50]
    summary = {
        "high": f"Flagged as dangerous by {', '.join(flagged)}." if flagged else "Combined signals indicate high risk.",
        "medium": "Some sources show suspicious activity. Treat with caution.",
        "low": "No significant malicious indicators were found.",
    }[level]
    if len(scored) == 1:
        summary += " (Based on a single source, so confidence is lower.)"
    return Verdict(score=score, level=level, sources=len(scored), queried=queried, summary=summary)


def collect_tags(results: list[ProviderResult]) -> list[Tag]:
    """Every tag from every source, lower-cased and de-duplicated. Also works for scans saved before tags existed."""
    out, seen = [], set()
    for r in results:
        raw = r.tags
        if not raw and r.provider in ("virustotal", "shodan") and r.data:
            raw = [t for t in (r.data.get("tags") or []) if isinstance(t, str)]
        for t in raw:
            t = t.strip().lower()
            if t and len(t) <= 60 and (t, r.provider) not in seen:
                seen.add((t, r.provider))
                out.append(Tag(tag=t, source=r.provider))
    return out
