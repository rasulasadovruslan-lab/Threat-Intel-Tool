// All output is built with textContent (never innerHTML), so API data can't inject HTML.
const $ = (id) => document.getElementById(id);
const out = $("out");
const NAMES = {virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan", dns: "DNS records"};
const TITLES = {low: "Low risk", medium: "Medium risk", high: "High risk", unknown: "No data found"};

function el(tag, cls, text, parent) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  if (parent) parent.append(e);
  return e;
}
const levelOf = (s) => (s === null ? "unknown" : s < 15 ? "low" : s < 50 ? "medium" : "high");

function verdictCard(j) {
  const v = j.verdict, c = el("div", `card verdict ${v.level}`, undefined, out);
  const big = el("div", "big", v.score === null ? "?" : String(v.score), c);
  el("small", "", "/ 100", big);
  const box = el("div", "", undefined, c);
  el("h2", "", TITLES[v.level], box);
  el("p", "", v.summary, box);
  el("p", "meta", `${j.type.toUpperCase()}: ${j.indicator} · ${v.sources} of ${v.queried} sources had data${j.cached ? " · cached" : ""}`, box);
  if (v.score !== null) el("i", "", "", el("div", "bar", undefined, box)).style.width = v.score + "%";
}

function sourceCard(r) {
  const c = el("div", `card ${levelOf(r.score)}`, undefined, out);
  const head = el("div", "head", undefined, c);
  el("strong", "", NAMES[r.provider] || r.provider, head);
  if (r.score !== null) el("span", "chip", `${r.score}/100`, head);
  if (r.note) el("div", "meta", r.note, c);
  const ul = el("ul", "", undefined, c);
  r.facts.forEach((f) => el("li", "", f, ul));
  const d = el("details", "", undefined, c);
  el("summary", "", "Raw data", d);
  el("pre", "", JSON.stringify(r.data, null, 2), d);
}

async function run(ev) {
  ev.preventDefault();
  const btn = $("go");
  btn.disabled = true; out.textContent = "";
  try {
    sessionStorage.setItem("tok", $("token").value);
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-API-Token": $("token").value},
      body: JSON.stringify({indicator: $("ind").value}),
    });
    const j = await res.json();
    if (!res.ok) {
      const msg = res.status === 401 ? "Wrong access token (use the APP_TOKEN from your .env)"
        : res.status === 429 ? "Slow down: rate limit reached"
        : typeof j.detail === "string" ? j.detail : "Invalid input";
      return el("div", "card err", msg, out);
    }
    verdictCard(j);
    j.results.filter((r) => r.ok && r.found).forEach(sourceCard);
    j.results.filter((r) => !r.ok).forEach((r) =>
      el("div", "card err", `${NAMES[r.provider] || r.provider}: ${r.error}`, out));
    if (j.no_data.length)
      el("p", "muted", "No data from: " + [...new Set(j.no_data)].map((n) => NAMES[n] || n).join(", "), out);
  } catch {
    el("div", "card err", "Could not reach the server. Is it running?", out);
  } finally {
    btn.disabled = false;
  }
}
$("token").value = sessionStorage.getItem("tok") || "";
$("form").addEventListener("submit", run);
