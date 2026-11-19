// Everything is built with textContent (never innerHTML), so API/AI text can't inject HTML.
const $ = (id) => document.getElementById(id);
const view = $("view");
const NAMES = {virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan", dns: "DNS records"};
const LEVEL = {low: "Low risk", medium: "Medium risk", high: "High risk", unknown: "No data"};
const levelOf = (s) => (s == null ? "unknown" : s < 15 ? "low" : s < 50 ? "medium" : "high");
const pct = (s) => (s == null ? "—" : s + "%");
const fmt = (iso) => new Date(iso).toLocaleString();
const defang = (v) => v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");

function detect(v) {
  v = v.trim().replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http");
  if (!v) return null;
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)) return "HASH";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(":") && /^[a-f0-9:]+$/i.test(v))) return "IP";
  if (/^https?:\/\//i.test(v)) return "URL";
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return "DOMAIN";
  return "?";
}
function toast(msg) {
  const t = el("div", "toast", msg, document.body);
  setTimeout(() => t.remove(), 1600);
}
async function copy(text, label = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(label); } catch { toast("Copy blocked by browser"); }
}

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

let homeFilter = {level: "all", q: ""};

async function home() {
  view.textContent = "";
  const hero = el("section", "hero", undefined, view);
  const h = el("h1", "", "Is it ", hero);
  el("em", "", "safe", h);
  h.append("? Find out in seconds.");
  el("p", "", "Search any IP, domain, URL or file hash. We check VirusTotal, AbuseIPDB and Shodan, then rate it.", hero);
  let items = [];
  try { items = await api("/api/reports"); } catch { /* history is optional */ }
  if (!items.length) return;

  const stats = el("div", "stats", undefined, view);
  const count = (l) => items.filter((i) => i.level === l).length;
  [["all", "All scans", items.length, ""], ["high", "High risk", count("high"), "high"],
   ["medium", "Medium", count("medium"), "medium"], ["low", "Low risk", count("low"), "low"],
   ["unknown", "No data", count("unknown"), "unknown"]].forEach(([k, label, n, cls]) => {
    const b = el("button", `stat ${cls}${homeFilter.level === k ? " on" : ""}`, undefined, stats);
    el("b", "", String(n), b); el("small", "", label, b);
    b.onclick = () => { homeFilter.level = k; home(); };
  });

  const bar = el("div", "toolbar", undefined, view);
  el("div", "sec", "Saved reports", bar);
  const q = el("input", "", undefined, bar);
  q.placeholder = "Filter…"; q.value = homeFilter.q;
  const exp = el("a", "btn-link", "Export CSV", bar);
  exp.href = "/api/reports/export.csv"; exp.download = "threatscope-reports.csv";
  const grid = el("div", "grid", undefined, view);
  const draw = () => {
    grid.textContent = "";
    const shown = items.filter((i) => (homeFilter.level === "all" || i.level === homeFilter.level)
      && i.indicator.toLowerCase().includes(homeFilter.q.toLowerCase()));
    if (!shown.length) el("p", "empty", "Nothing matches.", grid);
    shown.forEach((it) => {
      const a = el("a", `card mini ${levelOf(it.score)}`, undefined, grid);
      a.href = "#/r/" + it.id;
      el("span", "pct", pct(it.score), a);
      const b = el("div", "", undefined, a);
      el("strong", "", it.indicator, b);
      el("small", "muted", `${it.type.toUpperCase()} · ${new Date(it.updated).toLocaleDateString()}${it.has_ai ? " · AI report" : ""}`, b);
    });
  };
  q.oninput = () => { homeFilter.q = q.value; draw(); };
  draw();
}

function sourceCard(r, parent) {
  const c = el("div", `card src ${levelOf(r.score)}`, undefined, parent);
  const head = el("div", "head", undefined, c);
  el("strong", "", NAMES[r.provider] || r.provider, head);
  if (r.score != null) el("span", "pct", pct(r.score), head);
  else el("span", "pct info-only", "Info", head);
  if (r.score != null) el("i", "", "", el("div", "track", undefined, c)).style.width = r.score + "%";
  if (r.note) el("div", "meta", r.note, c);
  const d0 = r.data || {};
  if (r.provider === "virustotal" && d0.stats) {
    const st = d0.stats, tot = Object.values(st).reduce((x, y) => x + y, 0) || 1;
    const bar = el("div", "segbar", undefined, c);
    [["malicious", "seg-m"], ["suspicious", "seg-s"], ["harmless", "seg-h"], ["undetected", "seg-u"]].forEach(([k, cl]) => {
      if (st[k]) el("i", cl, "", bar).style.width = (st[k] / tot * 100) + "%";
    });
    const lg = el("div", "legend", undefined, c);
    [["malicious", "--high"], ["suspicious", "--medium"], ["harmless", "--low"], ["undetected", "--unknown"]].forEach(([k, col]) =>
      el("span", "", `${k} ${st[k] || 0}`, lg).style.setProperty("--d", `var(${col})`));
  }
  list(r.facts, c);
  if (r.provider === "shodan" && d0.ports && d0.ports.length) {
    el("div", "sub", "Open ports", c);
    const pl = el("div", "pills", undefined, c);
    const RISKY = [21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017];
    d0.ports.forEach((p) => el("span", "pill" + (RISKY.includes(p) ? " risk" : ""), String(p), pl));
  }
  if (r.provider === "shodan" && d0.vulns && d0.vulns.length) {
    el("div", "sub", "Known CVEs", c);
    const vl = el("div", "pills", undefined, c);
    d0.vulns.slice(0, 20).forEach((v) => {
      if (!/^CVE-\d{4}-\d+$/i.test(v)) return;
      const a = el("a", "pill cve", v, vl);
      a.href = "https://nvd.nist.gov/vuln/detail/" + v; a.target = "_blank"; a.rel = "noopener noreferrer";
    });
  }
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
  el("button", "ghost", "Copy indicator", act).onclick = () => copy(rec.indicator);
  el("button", "ghost", "Copy defanged", act).onclick = () => copy(defang(rec.indicator), "Defanged copy ready");
  if (saved) {
    el("button", "ghost", "Download JSON", act).onclick = () => {
      const a = el("a", "", "", document.body);
      a.href = URL.createObjectURL(new Blob([JSON.stringify(rec, null, 2)], {type: "application/json"}));
      a.download = `threatscope-${rec.id}.json`; a.click(); a.remove();
    };
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function bulk() {
  view.textContent = "";
  const card = el("section", "card", undefined, view);
  el("strong", "", "Bulk scan", card);
  el("p", "muted", "Paste up to 25 indicators (one per line, or separated by commas/spaces). Defanged ones like hxxp and [.] work too. Scans run one at a time to respect API rate limits.", card);
  const ta = el("textarea", "", undefined, card);
  ta.placeholder = "8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f";
  const run = el("button", "", "Scan all", card);
  const out = el("div", "", undefined, view);
  run.onclick = async () => {
    const list = [...new Set(ta.value.split(/[\s,]+/).filter(Boolean))].slice(0, 25);
    if (!list.length) return;
    run.disabled = true; out.textContent = "";
    const t = el("table", "card", undefined, out);
    const hd = el("tr", "", undefined, el("thead", "", undefined, t));
    ["Indicator", "Type", "Risk", "Result"].forEach((h) => el("th", "", h, hd));
    const body = el("tbody", "", undefined, t);
    for (const ind of list) {
      const tr = el("tr", "", undefined, body);
      el("td", "ind", ind, tr); const ty = el("td", "", "…", tr);
      const rk = el("td", "", "", tr); const rs = el("td", "", "scanning…", tr);
      try {
        const rec = await post("/api/lookup", {indicator: ind, refresh: false});
        ty.textContent = rec.type.toUpperCase();
        rk.textContent = pct(rec.verdict.score); rk.className = levelOf(rec.verdict.score) + " pct-cell";
        rk.style.color = `var(--${levelOf(rec.verdict.score)})`; rk.style.fontWeight = "700";
        rs.textContent = "";
        if (rec.results.some((r) => r.ok)) { const a = el("a", "", "open", rs); a.href = "#/r/" + rec.id; }
        else rs.textContent = "all sources failed";
        if (!rec.cached) await sleep(4200);
      } catch (e) { ty.textContent = "?"; rs.textContent = e.message; rs.className = "err"; await sleep(4200); }
    }
    run.disabled = false;
  };
}

async function showStatus() {
  const box = $("status");
  try {
    const s = await api("/api/status");
    box.textContent = "";
    [["VirusTotal", s.virustotal ? "" : "off"], ["AbuseIPDB", s.abuseipdb ? "" : "off"],
     ["Shodan " + (s.shodan === "full" ? "(API)" : "(free InternetDB)"), s.shodan === "full" ? "" : "mid"],
     ["AI report", s.ai ? "" : "off"]].forEach(([n, st]) => {
      const sp = el("span", "", n, box);
      sp.prepend(Object.assign(el("i", "dot" + (st ? " " + st : "")), {}));
    });
  } catch { /* status is optional */ }
}

async function route() {
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === (location.hash.startsWith("#/bulk") ? "#/bulk" : "#/")));
  if (location.hash === "#/bulk") return bulk();
  const m = location.hash.match(/^#\/r\/([a-f0-9]{16})$/);
  if (!m) return home();
  try { render(await api("/api/reports/" + m[1])); } catch (e) { showError(e.message); }
}

$("ind").addEventListener("input", () => {
  const k = detect($("ind").value), badge = $("kind");
  badge.hidden = !k; badge.textContent = k === "?" ? "UNKNOWN" : k || ""; badge.className = "kind" + (k === "?" ? " bad" : "");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) { e.preventDefault(); $("ind").focus(); }
});
$("form").addEventListener("submit", (e) => { e.preventDefault(); search($("ind").value); });
window.addEventListener("hashchange", route);
route();
showStatus();
