// Everything is built with textContent (never innerHTML), so API/AI text can't inject HTML.
const $ = (id) => document.getElementById(id);
const view = $("view");
const NAMES = {virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan", dns: "DNS records"};
const LEVEL = {low: "Low risk", medium: "Medium risk", high: "High risk", unknown: "No data"};
const levelOf = (s) => (s == null ? "unknown" : s < 15 ? "low" : s < 50 ? "medium" : "high");
const pct = (s) => (s == null ? "—" : s + "%");
const fmt = (iso) => new Date(iso).toLocaleString();

function el(tag, cls, text, parent) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  if (parent) parent.append(e);
  return e;
}
function list(items, parent) {
  const ul = el("ul", "", undefined, parent);
  items.forEach((t) => el("li", "", t, ul));
}

async function api(path, opts = {}) {
  let res;
  try { res = await fetch(path, opts); } catch { throw new Error("Cannot reach the server. Is it running?"); }
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(res.status === 429 ? "Slow down a little: rate limit reached."
      : typeof d === "string" ? d : `Request failed (${res.status})`);
  }
  return data;
}
const post = (path, body) => api(path, {
  method: "POST", headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined,
});

function showError(msg) { view.textContent = ""; el("div", "card err", msg, view); }

async function search(indicator, refresh = false) {
  indicator = indicator.trim();
  if (!indicator) return;
  $("go").disabled = true;
  view.textContent = "";
  el("div", "loading", "Scanning sources…", view);
  try {
    const rec = await post("/api/lookup", {indicator, refresh});
    render(rec);
    if (rec.results.some((r) => r.ok)) history.replaceState(null, "", "#/r/" + rec.id);
  } catch (e) { showError(e.message); } finally { $("go").disabled = false; }
}

async function home() {
  view.textContent = "";
  const hero = el("section", "hero", undefined, view);
  const h = el("h1", "", "Is it ", hero);
  el("em", "", "safe", h);
  h.append("? Find out in seconds.");
  el("p", "", "Search any IP, domain, URL or file hash. We check VirusTotal, AbuseIPDB and Shodan, then rate it.", hero);
  try {
    const items = await api("/api/reports");
    if (!items.length) return;
    el("div", "sec", "Saved reports", view);
    const grid = el("div", "grid", undefined, view);
    items.forEach((it) => {
      const a = el("a", `card mini ${levelOf(it.score)}`, undefined, grid);
      a.href = "#/r/" + it.id;
      el("span", "pct", pct(it.score), a);
      const b = el("div", "", undefined, a);
      el("strong", "", it.indicator, b);
      el("small", "muted", `${it.type.toUpperCase()} · ${new Date(it.updated).toLocaleDateString()}${it.has_ai ? " · AI report" : ""}`, b);
    });
  } catch { /* history is optional */ }
}

function sourceCard(r, parent) {
  const c = el("div", `card src ${levelOf(r.score)}`, undefined, parent);
  const head = el("div", "head", undefined, c);
  el("strong", "", NAMES[r.provider] || r.provider, head);
  if (r.score != null) el("span", "pct", pct(r.score), head);
  else el("span", "pct info-only", "Info", head);
  if (r.score != null) el("i", "", "", el("div", "track", undefined, c)).style.width = r.score + "%";
  if (r.note) el("div", "meta", r.note, c);
  list(r.facts, c);
  const d = el("details", "", undefined, c);
  el("summary", "", "Raw data", d);
  el("pre", "", JSON.stringify(r.data, null, 2), d);
}

function aiSection(rec) {
  const box = el("section", "card ai", undefined, view);
  function draw() {
    box.textContent = "";
    const head = el("div", "head", undefined, box);
    el("strong", "", "AI analyst report", head);
    const r = rec.ai_report;
    if (r) el("span", "chip", `${r.confidence} confidence`, head);
    const msg = el("p", "muted", r ? "" : "Get a written assessment of these results, saved with this page.", box);
    if (r) {
      el("h3", "", r.headline, box);
      el("p", "", r.summary, box);
      if (r.key_findings.length) { el("h4", "", "Key findings", box); list(r.key_findings, box); }
      if (r.risk_assessment) { el("h4", "", "Risk assessment", box); el("p", "", r.risk_assessment, box); }
      if (r.recommendations.length) { el("h4", "", "Recommendations", box); list(r.recommendations, box); }
      el("p", "meta", `${r.model} · ${fmt(r.generated_at)} · AI-generated, verify before acting`, box);
    }
    const btn = el("button", r ? "ghost" : "", r ? "Regenerate" : "Generate report", box);
    btn.style.marginTop = ".8rem";
    btn.onclick = async () => {
      btn.disabled = true; btn.textContent = "Analysing…";
      try { rec.ai_report = await post(`/api/reports/${rec.id}/ai`); draw(); }
      catch (e) { btn.disabled = false; btn.textContent = r ? "Regenerate" : "Generate report"; msg.textContent = e.message; msg.className = "err"; }
    };
  }
  draw();
}

function render(rec) {
  view.textContent = "";
  const v = rec.verdict;
  const top = el("section", `card summary ${v.level}`, undefined, view);
  const ring = el("div", "ring", undefined, top);
  ring.style.setProperty("--p", v.score ?? 0);
  el("span", "", pct(v.score), ring);
  const info = el("div", "info", undefined, top);
  const chips = el("div", "chips", undefined, info);
  el("span", "chip lvl", LEVEL[v.level], chips);
  el("span", "chip", rec.type.toUpperCase(), chips);
  if (rec.cached) el("span", "chip", "saved scan", chips);
  el("h2", "", rec.indicator, info);
  el("p", "", v.summary, info);
  el("p", "meta", `${v.sources} of ${v.queried} sources had data · scanned ${fmt(rec.updated)}`, info);
  const act = el("div", "actions", undefined, info);
  const saved = rec.results.some((r) => r.ok);
  el("button", "ghost", "Re-scan", act).onclick = () => search(rec.indicator, true);
  if (saved) {
    el("button", "ghost", "Copy link", act).onclick = (e) => {
      navigator.clipboard.writeText(location.href); e.target.textContent = "Copied";
    };
    el("button", "ghost", "Delete", act).onclick = async () => {
      if (!confirm("Delete this saved report?")) return;
      await api("/api/reports/" + rec.id, {method: "DELETE"}).catch(() => {});
      location.hash = "#/";
    };
    aiSection(rec);
  }
  const found = rec.results.filter((r) => r.ok && r.found);
  if (found.length) {
    el("div", "sec", "Source ratings", view);
    const grid = el("div", "grid", undefined, view);
    found.forEach((r) => sourceCard(r, grid));
  }
  rec.results.filter((r) => !r.ok).forEach((r) =>
    el("div", "card err", `${NAMES[r.provider] || r.provider}: ${r.error}`, view));
  if (rec.no_data.length)
    el("p", "muted", "No data from: " + [...new Set(rec.no_data)].map((n) => NAMES[n] || n).join(", "), view);
}

async function route() {
  const m = location.hash.match(/^#\/r\/([a-f0-9]{16})$/);
  if (!m) return home();
  try { render(await api("/api/reports/" + m[1])); } catch (e) { showError(e.message); }
}

$("form").addEventListener("submit", (e) => { e.preventDefault(); search($("ind").value); });
window.addEventListener("hashchange", route);
route();
