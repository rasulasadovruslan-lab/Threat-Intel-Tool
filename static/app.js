// Everything is built with textContent (never innerHTML), so API text, comments and log content can't inject HTML.
const $ = (id) => document.getElementById(id);
const view = $("view");
const NAMES = {virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan", dns: "DNS records"};
const LEVEL = {low: "Low risk", medium: "Medium risk", high: "High risk", unknown: "No data"};
const RISKY = [21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017];
const levelOf = (s) => (s == null ? "unknown" : s < 15 ? "low" : s < 50 ? "medium" : "high");
const pct = (s) => (s == null ? "—" : s + "%");
const fmt = (iso) => new Date(iso).toLocaleString();
const day = (iso) => (iso && !isNaN(Date.parse(iso)) ? new Date(iso).toLocaleDateString(undefined, {year: "numeric", month: "short", day: "numeric"}) : "");
const defang = (v) => v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let STATUS = {};
let activeTab = "overview", lastId = null;

// ---------- small helpers ----------
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
function toast(msg) {
  const t = el("div", "toast", msg, document.body);
  setTimeout(() => t.remove(), 2200);
}
async function copy(text, label = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(label); } catch { toast("Copy blocked by the browser"); }
}
function download(name, text, type) {
  const a = el("a", "", "", document.body);
  a.href = URL.createObjectURL(new Blob([text], {type}));
  a.download = name; a.click(); a.remove();
}
const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // stops spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};
const tagLink = (t, parent, count) => {
  const a = el("a", "tag", t, parent);
  a.href = "#/tag/" + encodeURIComponent(t);
  if (count != null) el("small", "", String(count), a);
  return a;
};

async function api(path, opts = {}) {
  let res;
  try { res = await fetch(path, opts); } catch { throw new Error("Cannot reach the server. Is it running?"); }
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) {
    const d = data && data.detail;
    const err = new Error(typeof d === "string" ? d
      : res.status === 429 ? "Slow down a little: rate limit reached."
      : res.status === 422 && Array.isArray(d) ? "That input was rejected as invalid." : `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}
const post = (path, body) => api(path, {
  method: "POST", headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined,
});
async function lookupQuick(ind) {          // used by bulk and log scans: no community comments, saves VirusTotal quota
  for (let t = 0; ; t++) {
    try { return await post("/api/lookup", {indicator: ind, refresh: false, deep: false}); }
    catch (e) { if (e.status === 429 && t < 4) { await sleep(15000); continue; } throw e; }
  }
}
function showError(msg) { view.textContent = ""; el("div", "card err", msg, view); }
function setHash(h) { history.replaceState(null, "", h); markNav(); }
function markNav() {
  const h = location.hash;
  const cur = h.startsWith("#/log") ? "#/log" : h.startsWith("#/bulk") ? "#/bulk" : "#/";
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === cur));
}

// ---------- search bar ----------
function detect(v) {
  v = v.trim();
  if (!v) return null;
  if (/^(tag:|#)/i.test(v)) return "TAG";
  v = v.replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http");
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)) return "HASH";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(":") && /^[a-f0-9:]+$/i.test(v))) return "IP";
  if (/^https?:\/\//i.test(v)) return "URL";
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return "DOMAIN";
  return "?";
}

async function search(raw, refresh = false) {
  raw = raw.trim();
  if (!raw) return;
  const m = raw.match(/^(?:tag:|#)\s*(.+)$/i);
  if (m) { location.hash = "#/tag/" + encodeURIComponent(m[1].trim().toLowerCase()); return; }
  view.textContent = "";
  const box = el("div", "loading", "Scanning sources…", view);
  setTimeout(() => { if (box.isConnected) box.textContent = "Still working. VirusTotal free keys allow only 4 requests a minute, so this can take a moment."; }, 7000);
  try {
    const rec = await post("/api/lookup", {indicator: raw, refresh, deep: true});
    if (rec.results.some((r) => r.ok)) setHash("#/r/" + rec.id);
    render(rec);
    loadTags();
  } catch (e) { showError(e.message); }
}

// ---------- report page ----------
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
  return c;
}

function glance(rec) {
  const by = Object.fromEntries(rec.results.map((r) => [r.provider, r.data || {}]));
  const vt = by.virustotal || {}, ab = by.abuseipdb || {}, sh = by.shodan || {};
  const rows = [
    ["Country", ab.countryCode || vt.country],
    ["Owner / ISP", ab.isp || vt.as_owner || sh.org],
    ["Usage type", ab.usageType],
    ["Domain", ab.domain],
    ["Hostnames", (sh.hostnames || []).slice(0, 4).join(", ")],
    ["Operating system", sh.os],
    ["Tor exit node", ab.isTor ? "Yes" : null],
    ["Last reported", ab.lastReportedAt ? day(ab.lastReportedAt) : null],
    ["Known file names", (vt.names || []).slice(0, 3).join(", ")],
  ];
  return rows.filter(([, v]) => v);
}

function overviewTab(rec, box) {
  // 1. verdict by source
  const c1 = el("div", "card", undefined, box);
  el("div", "sec", "Verdict by source", c1);
  el("p", "", rec.verdict.summary, c1);
  const rows = el("div", "rows", undefined, c1);
  rec.results.filter((r) => r.provider !== "dns").forEach((r) => {
    const lvl = r.ok && r.found && r.score != null ? levelOf(r.score) : "unknown";
    const row = el("div", `row ${lvl}`, undefined, rows);
    el("b", "", NAMES[r.provider] || r.provider, row);
    el("i", "", "", el("div", "bar", undefined, row)).style.width = (r.ok && r.score != null ? r.score : 0) + "%";
    el("span", "val", !r.ok ? "Failed" : r.found && r.score != null ? pct(r.score) : "No data", row);
    const why = !r.ok ? r.error : r.found ? (r.facts[0] || "") : "This source has no record of it.";
    if (why) el("div", `why${!r.ok ? " err" : ""}`, why, row);
  });
  // 2. at a glance
  const g = glance(rec);
  if (g.length) {
    const c2 = el("div", "card", undefined, box);
    el("div", "sec", "At a glance", c2);
    const dl = el("dl", "kv", undefined, c2);
    g.forEach(([k, v]) => { const d = el("div", "", undefined, dl); el("dt", "", k, d); el("dd", "", String(v), d); });
  }
  // 3. exposure
  const sh = (rec.results.find((r) => r.provider === "shodan") || {}).data || {};
  if ((sh.ports && sh.ports.length) || (sh.vulns && sh.vulns.length)) {
    const c3 = el("div", "card", undefined, box);
    el("div", "sec", "Exposure (Shodan)", c3);
    if (sh.ports && sh.ports.length) {
      el("div", "sub", "Open ports", c3);
      const pl = el("div", "pills", undefined, c3);
      sh.ports.forEach((p) => el("span", "pill" + (RISKY.includes(p) ? " risk" : ""), String(p), pl));
    }
    if (sh.vulns && sh.vulns.length) {
      el("div", "sub", `Known CVEs (${sh.vulns.length})`, c3);
      const vl = el("div", "pills", undefined, c3);
      sh.vulns.slice(0, 30).forEach((v) => {
        if (!/^CVE-\d{4}-\d+$/i.test(v)) return;
        const a = el("a", "pill cve", v, vl);
        a.href = "https://nvd.nist.gov/vuln/detail/" + v; a.target = "_blank"; a.rel = "noopener noreferrer";
      });
    }
  }
  // 4. tags
  const c4 = el("div", "card", undefined, box);
  el("div", "sec", "Tags", c4);
  const tags = rec.tags || [];
  if (!tags.length) el("p", "muted", "No source has tagged this indicator.", c4);
  else {
    el("p", "meta", "Click a tag to see every saved scan that has it.", c4);
    [...new Set(tags.map((t) => t.source))].forEach((src) => {
      el("div", "src-label", NAMES[src] || src, c4);
      const w = el("div", "tags", undefined, c4);
      tags.filter((t) => t.source === src).forEach((t) => tagLink(t.tag, w));
    });
  }
}

function communityTab(rec, box) {
  const notes = rec.results.flatMap((r) => (r.community || []).map((n) => ({...n, provider: r.provider})))
    .sort((a, b) => (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0));
  const vt = rec.results.find((r) => r.provider === "virustotal" && r.ok);
  if (vt && !rec.deep) {
    const b = el("div", "banner", undefined, box);
    el("span", "", "VirusTotal community comments weren't loaded for this quick scan.", b);
    el("button", "", "Load community reports", b).onclick = (ev) => { ev.target.disabled = true; search(rec.indicator, true); };
  }
  const votes = vt && vt.data && vt.data.total_votes;
  if (votes && (votes.harmless || votes.malicious)) {
    const c = el("div", "card", undefined, box);
    el("div", "sec", "VirusTotal community votes", c);
    el("p", "", `${votes.harmless || 0} users voted harmless, ${votes.malicious || 0} voted malicious.`, c);
  }
  const hasShodan = rec.results.some((r) => r.provider === "shodan");
  if (hasShodan) el("p", "meta", "Shodan has no community-written reports. Its tags are on the Overview tab.", box);
  if (!notes.length) { el("p", "empty", "No community reports or comments found for this indicator.", box); return; }

  const counts = {};
  notes.forEach((n) => (counts[n.provider] = (counts[n.provider] || 0) + 1));
  let filter = "all", shown = 10;
  const bar = el("div", "filters", undefined, box);
  const out = el("div", "", undefined, box);
  const draw = () => {
    bar.textContent = ""; out.textContent = "";
    [["all", `All (${notes.length})`], ...Object.entries(counts).map(([p, n]) => [p, `${NAMES[p] || p} (${n})`])].forEach(([k, label]) => {
      const b = el("button", k === filter ? "on" : "", label, bar);
      b.onclick = () => { filter = k; shown = 10; draw(); };
    });
    const pool = notes.filter((n) => filter === "all" || n.provider === filter);
    pool.slice(0, shown).forEach((n) => {
      const c = el("div", "card note", undefined, out);
      const head = el("div", "note-head", undefined, c);
      el("span", "badge", NAMES[n.provider] || n.provider, head);
      if (n.date) el("span", "", day(n.date), head);
      if (n.author) el("span", "", n.author, head);
      if (n.extra) el("span", "", n.extra, head);
      if (n.categories.length) {
        const w = el("div", "tags", undefined, c);
        n.categories.forEach((t) => (n.provider === "abuseipdb" ? el("span", "tag", t, w) : tagLink(t.toLowerCase(), w)));
      }
      if (n.text) el("p", "note-text", n.text, c);
      else el("p", "note-text none", "No comment written, categories only.", c);
    });
    if (pool.length > shown) {
      const more = el("button", "ghost", `Show ${Math.min(20, pool.length - shown)} more`, out);
      more.style.marginTop = "1rem";
      more.onclick = () => { shown += 20; draw(); };
    }
  };
  draw();
}

function render(rec) {
  if (rec.id !== lastId) { activeTab = "overview"; lastId = rec.id; }
  view.textContent = "";
  const v = rec.verdict, lvl = levelOf(v.score);
  const top = el("section", `card summary ${lvl}`, undefined, view);
  const ring = el("div", "ring", undefined, top);
  ring.style.setProperty("--p", v.score || 0);
  el("span", "", pct(v.score), ring);
  const info = el("div", "info", undefined, top);
  const chips = el("div", "chips", undefined, info);
  el("span", "chip lvl", LEVEL[lvl], chips);
  el("span", "chip", rec.type.toUpperCase(), chips);
  if (rec.cached) el("span", "chip", "saved scan", chips);
  el("h2", "ip", rec.indicator, info);
  el("p", "", v.summary, info);
  el("p", "meta", `${v.sources} of ${v.queried} sources had data · scanned ${fmt(rec.updated)}`, info);
  const act = el("div", "actions", undefined, info);
  const saved = rec.results.some((r) => r.ok);
  el("button", "ghost", "Re-scan", act).onclick = () => search(rec.indicator, true);
  el("button", "ghost", "Copy indicator", act).onclick = () => copy(rec.indicator);
  el("button", "ghost", "Copy defanged", act).onclick = () => copy(defang(rec.indicator), "Defanged copy ready");
  if (saved) {
    el("button", "ghost", "Download JSON", act).onclick = () => download(`threatscope-${rec.id}.json`, JSON.stringify(rec, null, 2), "application/json");
    el("button", "ghost", "Copy link", act).onclick = () => copy(location.href, "Link copied");
    el("button", "ghost danger", "Delete", act).onclick = async () => {
      if (!confirm("Delete this saved report?")) return;
      await api("/api/reports/" + rec.id, {method: "DELETE"}).catch(() => {});
      location.hash = "#/";
    };
  }

  const nComm = rec.results.reduce((n, r) => n + (r.community || []).length, 0);
  const defs = [["overview", "Overview", 0], ["community", "Community", nComm], ["sources", "Sources", 0], ["raw", "Raw data", 0]];
  const tabs = el("div", "tabs", undefined, view);
  const panel = el("div", "panel", undefined, view);
  const draw = () => {
    tabs.textContent = ""; panel.textContent = "";
    defs.forEach(([k, label, n]) => {
      const b = el("button", "tab" + (k === activeTab ? " on" : ""), label, tabs);
      if (n) el("small", "", String(n), b);
      b.onclick = () => { activeTab = k; draw(); };
    });
    if (activeTab === "overview") overviewTab(rec, panel);
    else if (activeTab === "community") communityTab(rec, panel);
    else if (activeTab === "sources") {
      const g = el("div", "grid", undefined, panel);
      g.style.marginTop = "1rem";
      rec.results.filter((r) => r.ok && r.found).forEach((r) => sourceCard(r, g));
      if (rec.no_data.length) el("p", "meta", "No data from: " + rec.no_data.map((p) => NAMES[p] || p).join(", "), panel);
    } else {
      rec.results.forEach((r) => {
        const d = el("details", "card", undefined, panel);
        el("summary", "", `${NAMES[r.provider] || r.provider}${r.ok ? "" : " (failed)"}`, d);
        el("pre", "", JSON.stringify(r.ok ? r.data : {error: r.error}, null, 2), d);
      });
    }
  };
  draw();
  rec.results.filter((r) => !r.ok).forEach((r) =>
    el("div", "card err", `${NAMES[r.provider] || r.provider}: ${r.error}`, view));
}

// ---------- home & tag pages ----------
let homeFilter = {level: "all", q: ""};

function miniCard(it, parent) {
  const a = el("a", `card mini ${levelOf(it.score)}`, undefined, parent);
  a.href = "#/r/" + it.id;
  el("span", "pct", pct(it.score), a);
  const b = el("div", "", undefined, a);
  el("strong", "ip", it.indicator, b);
  el("small", "muted", `${it.type.toUpperCase()} · ${day(it.updated)}`, b);
  if (it.tags && it.tags.length) {
    const w = el("div", "tags", undefined, b);
    it.tags.slice(0, 3).forEach((t) => el("span", "tag", t, w));
  }
}
function cloud(tags, parent, limit = 24) {
  const w = el("div", "cloud", undefined, parent);
  tags.slice(0, limit).forEach((t) => tagLink(t.tag, w, t.count));
}

async function home() {
  view.textContent = "";
  const hero = el("section", "hero", undefined, view);
  const h = el("h1", "", "Is it ", hero);
  el("em", "", "safe", h);
  h.append("? Find out in seconds.");
  el("p", "", "Search an IP, domain, URL, file hash or tag. Or attach a log file and we'll scan every IP in it.", hero);
  const [items, tags, logs] = await Promise.all([
    api("/api/reports").catch(() => []), api("/api/tags").catch(() => []), api("/api/logs").catch(() => [])]);
  if (!items.length && !logs.length) return;

  const stats = el("div", "stats", undefined, view);
  const count = (l) => items.filter((i) => i.level === l).length;
  [["all", "All scans", items.length, ""], ["high", "High risk", count("high"), "high"],
   ["medium", "Medium", count("medium"), "medium"], ["low", "Low risk", count("low"), "low"],
   ["unknown", "No data", count("unknown"), "unknown"]].forEach(([k, label, n, cls]) => {
    const b = el("button", `stat ${cls}${homeFilter.level === k ? " on" : ""}`, undefined, stats);
    el("b", "", String(n), b); el("small", "", label, b);
    b.onclick = () => { homeFilter.level = k; home(); };
  });

  if (tags.length) {
    const t = el("div", "block", undefined, view);
    el("div", "sec", "Browse by tag", t);
    cloud(tags, t);
  }

  const bar = el("div", "toolbar", undefined, view);
  el("div", "sec", "Saved scans", bar);
  const q = el("input", "field", undefined, bar);
  q.placeholder = "Filter…"; q.value = homeFilter.q;
  const exp = el("a", "btn-link", "Export CSV", bar);
  exp.href = "/api/reports/export.csv"; exp.download = "threatscope-reports.csv";
  const grid = el("div", "grid", undefined, view);
  const draw = () => {
    grid.textContent = "";
    const needle = homeFilter.q.toLowerCase();
    const shown = items.filter((i) => (homeFilter.level === "all" || i.level === homeFilter.level)
      && (i.indicator.toLowerCase().includes(needle) || i.tags.some((t) => t.includes(needle))));
    if (!shown.length) el("p", "empty", "Nothing matches.", grid);
    shown.slice(0, 60).forEach((it) => miniCard(it, grid));
  };
  q.oninput = () => { homeFilter.q = q.value; draw(); };
  draw();

  if (logs.length) {
    el("div", "sec block", "Log reports", view);
    const g = el("div", "grid", undefined, view);
    logs.slice(0, 6).forEach((l) => logCard(l, g));
  }
}

function logCard(l, parent) {
  const a = el("a", `card mini ${l.high ? "high" : l.medium ? "medium" : "low"}`, undefined, parent);
  a.href = "#/log/" + l.id;
  el("span", "pct", String(l.high), a);
  const b = el("div", "", undefined, a);
  el("strong", "", l.filename, b);
  el("small", "muted", `${l.high} high risk · ${l.scanned} IPs scanned · ${day(l.created)}`, b);
}

async function tagPage(tag) {
  view.textContent = "";
  const head = el("section", "card", undefined, view);
  el("div", "sec", "Tag", head);
  el("h2", "ip", tag, head).style.margin = ".3rem 0";
  el("p", "meta", "Saved scans where VirusTotal, Shodan or AbuseIPDB reported this tag. Partial matches count, so “brute” finds “brute-force”.", head);
  const [items, tags] = await Promise.all([
    api("/api/reports?tag=" + encodeURIComponent(tag)).catch(() => []), api("/api/tags").catch(() => [])]);
  el("div", "sec block", `${items.length} matching scan${items.length === 1 ? "" : "s"}`, view);
  const g = el("div", "grid", undefined, view);
  g.style.marginTop = ".7rem";
  if (!items.length) el("p", "empty", "No saved scan has this tag yet. Tags appear after you scan something that a source has tagged.", g);
  items.forEach((it) => miniCard(it, g));
  if (tags.length) {
    const t = el("div", "block", undefined, view);
    el("div", "sec", "Other tags", t);
    cloud(tags, t, 40);
  }
}

// ---------- bulk ----------
function bulk() {
  view.textContent = "";
  const card = el("section", "card", undefined, view);
  el("div", "sec", "Bulk scan", card);
  el("p", "meta", "Paste up to 25 indicators (one per line, or separated by commas or spaces). Defanged ones like hxxp and [.] work too. Quick scans skip community comments to save VirusTotal quota.", card);
  const ta = el("textarea", "", undefined, card);
  ta.placeholder = "8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f";
  const run = el("button", "", "Scan all", card);
  const out = el("div", "", undefined, view);
  run.onclick = async () => {
    const items = [...new Set(ta.value.split(/[\s,]+/).filter(Boolean))].slice(0, 25);
    if (!items.length) return;
    run.disabled = true; out.textContent = "";
    const wrap = el("div", "card table-wrap", undefined, out);
    const t = el("table", "", undefined, wrap);
    const hd = el("tr", "", undefined, el("thead", "", undefined, t));
    ["Indicator", "Type", "Risk", "Result"].forEach((x) => el("th", "", x, hd));
    const body = el("tbody", "", undefined, t);
    for (const ind of items) {
      const tr = el("tr", "", undefined, body);
      el("td", "ip", ind, tr); const ty = el("td", "", "…", tr);
      const rk = el("td", "score", "", tr); const rs = el("td", "", "scanning…", tr);
      try {
        const rec = await lookupQuick(ind);
        ty.textContent = rec.type.toUpperCase();
        rk.textContent = pct(rec.verdict.score);
        rk.style.color = `var(--${levelOf(rec.verdict.score)})`;
        rs.textContent = "";
        if (rec.results.some((r) => r.ok)) { el("a", "", "open", rs).href = "#/r/" + rec.id; }
        else rs.textContent = "all sources failed";
      } catch (e) { ty.textContent = "?"; rs.textContent = e.message; rs.className = "err"; }
    }
    run.disabled = false; loadTags();
  };
}

// ---------- log files ----------
const V4 = /(?<![\w.\-/])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w-]|\.\d)/g;
const V6 = /(?<![\w:.])[0-9a-f:]{3,45}(?![\w:])/gi;

function isV6(s) {
  if (!/^[0-9a-f:]+$/i.test(s) || s.includes(":::") || (s.match(/::/g) || []).length > 1) return false;
  const ok = (x) => x.length >= 1 && x.length <= 4;
  const parts = s.split("::");
  const g = (x) => (x ? x.split(":") : []);
  if (parts.length === 1) { const a = s.split(":"); return a.length === 8 && a.every(ok); }
  const all = [...g(parts[0]), ...g(parts[1])];
  return all.length <= 7 && all.every(ok);
}
function isPublic4(ip) {
  const [a, b, c] = ip.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && ((b === 168) || (b === 0 && c === 0) || (b === 0 && c === 2))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}
const isPublic6 = (ip) => { const f = parseInt(ip.split(":")[0] || "0", 16); return f >= 0x2000 && f <= 0x3fff; };  // global unicast only

function extractIPs(text) {
  const lines = text.split(/\r?\n/);
  const found = new Map(), priv = new Set();
  const add = (ip, line, pub) => {
    if (!pub) { priv.add(ip); return; }
    const e = found.get(ip);
    if (e) e.count++; else found.set(ip, {ip, count: 1, first_line: line});
  };
  lines.forEach((ln, i) => {
    if (ln.length > 20000) ln = ln.slice(0, 20000);
    for (const m of ln.matchAll(V4)) add(m[0], i + 1, isPublic4(m[0]));
    if ((ln.match(/:/g) || []).length >= 2) {
      for (const m of ln.matchAll(V6)) if (isV6(m[0])) { const ip = m[0].toLowerCase(); add(ip, i + 1, isPublic6(ip)); }
    }
  });
  return {lines: lines.length, entries: [...found.values()].sort((a, b) => b.count - a.count), privateCount: priv.size};
}

async function handleFile(file) {
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) { toast("That file is over 50 MB. Please split it first."); return; }
  view.textContent = "";
  el("div", "loading", `Reading ${file.name}…`, view);
  let text;
  try { text = await file.text(); } catch { showError("Could not read that file."); return; }
  if (text.slice(0, 4000).includes("\u0000")) { showError("That looks like a binary file. Attach a text log (.log, .txt, .csv, …)."); return; }
  setHash("#/log");
  logPreview(file, extractIPs(text));
}

function logPreview(file, parsed) {
  view.textContent = "";
  const c = el("section", "card", undefined, view);
  el("div", "sec", "Log file", c);
  el("h2", "ip", file.name, c).style.margin = ".3rem 0 .8rem";
  const kv = el("dl", "kv", undefined, c);
  [["Lines", parsed.lines.toLocaleString()], ["Public IPs found", parsed.entries.length.toLocaleString()],
   ["Private/reserved skipped", parsed.privateCount.toLocaleString()]].forEach(([k, v]) => {
    const d = el("div", "", undefined, kv); el("dt", "", k, d); el("dd", "", v, d);
  });
  if (!parsed.entries.length) {
    el("p", "empty", "No public IP addresses found in this file.", c);
    return;
  }
  const t = el("div", "table-wrap", undefined, c);
  t.style.marginTop = "1rem";
  const tb = el("table", "", undefined, t);
  const hd = el("tr", "", undefined, el("thead", "", undefined, tb));
  ["Most frequent IPs", "Seen"].forEach((x) => el("th", "", x, hd));
  parsed.entries.slice(0, 8).forEach((e) => {
    const tr = el("tr", "", undefined, el("tbody", "", undefined, tb));
    el("td", "ip", e.ip, tr); el("td", "", `${e.count}×`, tr);
  });

  const max = Math.min(parsed.entries.length, 500);
  const row = el("div", "toolbar", undefined, c);
  el("label", "", "Scan the top", row);
  const n = el("input", "field numfield", undefined, row);
  n.type = "number"; n.min = 1; n.max = max; n.value = Math.min(max, 100);
  el("span", "", `IPs, most frequent first (max ${max})`, row);
  const est = el("p", "meta", "", c);
  const upd = () => {
    const k = Math.max(1, Math.min(max, parseInt(n.value, 10) || 1));
    est.textContent = STATUS.virustotal
      ? `Roughly ${Math.ceil(k / 4)} minute(s). VirusTotal free keys allow 4 lookups a minute, and the app waits instead of failing. IPs scanned in the last hour are reused instantly.`
      : "IPs scanned in the last hour are reused instantly.";
  };
  n.oninput = upd; upd();
  const act = el("div", "actions", undefined, c);
  el("button", "", "Start scan", act).onclick = () => runLogScan(file, parsed, Math.max(1, Math.min(max, parseInt(n.value, 10) || 1)));
  el("button", "ghost", "Cancel", act).onclick = () => { location.hash = "#/log"; route(); };
}

async function runLogScan(file, parsed, n) {
  const chosen = parsed.entries.slice(0, n).map((e) => ({...e, tags: [], level: "unknown", score: null, done: false}));
  view.textContent = "";
  const c = el("section", "card", undefined, view);
  el("div", "sec", "Scanning", c);
  el("h2", "ip", file.name, c).style.margin = ".3rem 0";
  const label = el("p", "meta", "Starting…", c);
  el("i", "", "", el("div", "progress", undefined, c));
  const bar = c.querySelector(".progress i");
  let stop = false;
  const act = el("div", "actions", undefined, c);
  const stopBtn = el("button", "ghost", "Stop and save what's done", act);
  stopBtn.onclick = () => { stop = true; stopBtn.disabled = true; };
  const wrap = el("div", "card table-wrap", undefined, view);
  const tb = el("table", "", undefined, wrap);
  const hd = el("tr", "", undefined, el("thead", "", undefined, tb));
  ["IP", "Seen", "Risk", "Tags", "Status"].forEach((x) => el("th", "", x, hd));
  const body = el("tbody", "", undefined, tb);
  const cells = chosen.map((e) => {
    const tr = el("tr", "", undefined, body);
    el("td", "ip", e.ip, tr); el("td", "", `${e.count}×`, tr);
    return {risk: el("td", "score", "", tr), tags: el("td", "", "", tr), st: el("td", "muted", "waiting", tr)};
  });

  let finished = 0;
  for (let i = 0; i < chosen.length && !stop; i++) {
    const e = chosen[i], cl = cells[i];
    cl.st.textContent = "scanning…";
    label.textContent = `Scanning ${i + 1} of ${chosen.length}: ${e.ip}`;
    try {
      const rec = await lookupQuick(e.ip);
      e.report_id = rec.id; e.score = rec.verdict.score; e.level = rec.verdict.level;
      e.tags = [...new Set((rec.tags || []).map((t) => t.tag))].slice(0, 40);
      if (!rec.results.some((r) => r.ok)) e.error = "All sources failed";
    } catch (err) { e.error = String(err.message).slice(0, 200); }
    e.done = true; finished++;
    cl.risk.textContent = pct(e.score); cl.risk.style.color = `var(--${levelOf(e.score)})`;
    e.tags.slice(0, 3).forEach((t) => el("span", "tag", t, cl.tags));
    cl.st.textContent = e.error || "done"; cl.st.className = e.error ? "err" : "muted";
    bar.style.width = (finished / chosen.length * 100) + "%";
  }

  const done = chosen.filter((e) => e.done);
  if (!done.length) { label.textContent = "Stopped before anything was scanned."; return; }
  label.textContent = "Saving report…";
  try {
    const rep = await post("/api/logs", {
      filename: file.name.slice(0, 200), total_lines: parsed.lines, unique_ips: parsed.entries.length,
      skipped_private: parsed.privateCount, not_scanned: parsed.entries.length - done.length,
      entries: done.map((e) => ({ip: e.ip, count: e.count, first_line: e.first_line, report_id: e.report_id || null,
        score: e.score, level: e.level, tags: e.tags, error: e.error || null})),
    });
    loadTags();
    location.hash = "#/log/" + rep.id;
  } catch (err) { label.textContent = "Could not save the report: " + err.message; label.className = "meta err"; }
}

async function logsHome() {
  view.textContent = "";
  const c = el("section", "card", undefined, view);
  el("div", "sec", "Scan a log file", c);
  el("p", "", "Attach any text log: firewall, web server, SSH/auth, VPN, mail, exported Windows events. We pull out every public IP address, scan each one against VirusTotal, AbuseIPDB and Shodan, and save a report ranked by risk.", c);
  const z = el("div", "zone", undefined, c);
  el("p", "", "Drag a file anywhere onto this page, or", z);
  el("button", "", "Choose a log file", z).onclick = () => $("file").click();
  el("p", "meta", "The file is read in your browser. Only the IP addresses are sent for scanning, never the log text.", z);
  let logs = [];
  try { logs = await api("/api/logs"); } catch { /* optional */ }
  if (logs.length) {
    el("div", "sec block", "Previous log reports", view);
    const g = el("div", "grid", undefined, view);
    g.style.marginTop = ".7rem";
    logs.forEach((l) => logCard(l, g));
  }
}

let logFilter = "all";
async function logReport(id) {
  let rep;
  try { rep = await api("/api/logs/" + id); } catch (e) { showError(e.message); return; }
  view.textContent = "";
  const hd = el("section", "card", undefined, view);
  el("div", "sec", "Log report", hd);
  el("h2", "", rep.filename, hd).style.margin = ".3rem 0";
  el("p", "meta", `${fmt(rep.created)} · ${rep.total_lines.toLocaleString()} lines · ${rep.unique_ips} public IPs found · ${rep.entries.length} scanned · ${rep.skipped_private} private/reserved skipped`, hd);
  if (rep.not_scanned > 0) el("p", "meta", `${rep.not_scanned} less frequent IPs were not scanned (scan limit or stopped early). Attach the file again to scan more.`, hd);
  const act = el("div", "actions", undefined, hd);
  el("button", "ghost", "Download CSV", act).onclick = () => {
    const rows = [["ip", "seen", "first_line", "risk_percent", "level", "tags", "error"],
      ...rep.entries.map((e) => [e.ip, e.count, e.first_line, e.score ?? "", e.level, e.tags.join("; "), e.error || ""])];
    download(`threatscope-log-${rep.id}.csv`, rows.map((r) => r.map(csvCell).join(",")).join("\n"), "text/csv");
  };
  el("button", "ghost", "Copy link", act).onclick = () => copy(location.href, "Link copied");
  el("button", "ghost danger", "Delete", act).onclick = async () => {
    if (!confirm("Delete this log report? The individual IP scans stay saved.")) return;
    await api("/api/logs/" + id, {method: "DELETE"}).catch(() => {});
    location.hash = "#/log";
  };

  const stats = el("div", "stats", undefined, view);
  const cnt = (l) => rep.entries.filter((e) => e.level === l).length;
  [["all", "All IPs", rep.entries.length, ""], ["high", "High risk", cnt("high"), "high"], ["medium", "Medium", cnt("medium"), "medium"],
   ["low", "Low risk", cnt("low"), "low"], ["unknown", "No data", cnt("unknown"), "unknown"]].forEach(([k, label, n, cls]) => {
    const b = el("button", `stat ${cls}${logFilter === k ? " on" : ""}`, undefined, stats);
    el("b", "", String(n), b); el("small", "", label, b);
    b.onclick = () => { logFilter = k; logReport(id); };
  });

  const tagCount = {};
  rep.entries.forEach((e) => e.tags.forEach((t) => (tagCount[t] = (tagCount[t] || 0) + 1)));
  const top = Object.entries(tagCount).sort((a, b) => b[1] - a[1]).map(([tag, count]) => ({tag, count}));
  if (top.length) {
    const t = el("div", "block", undefined, view);
    el("div", "sec", "Tags in this log", t);
    cloud(top, t, 24);
  }

  const wrap = el("div", "card table-wrap", undefined, view);
  const tb = el("table", "", undefined, wrap);
  const th = el("tr", "", undefined, el("thead", "", undefined, tb));
  ["Risk", "IP", "Seen", "Tags", ""].forEach((x) => el("th", "", x, th));
  const body = el("tbody", "", undefined, tb);
  rep.entries.filter((e) => logFilter === "all" || e.level === logFilter)
    .sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || b.count - a.count)
    .forEach((e) => {
      const tr = el("tr", "", undefined, body);
      const r = el("td", "score", e.error ? "—" : pct(e.score), tr);
      r.style.color = `var(--${e.level})`;
      el("td", "ip", e.ip, tr);
      el("td", "", `${e.count}× (line ${e.first_line})`, tr);
      const tg = el("td", "", undefined, tr);
      const w = el("div", "tags", undefined, tg);
      e.tags.slice(0, 4).forEach((t) => tagLink(t, w));
      const last = el("td", "", "", tr);
      if (e.error) { last.textContent = e.error; last.className = "err"; }
      else if (e.report_id) { el("a", "", "open", last).href = "#/r/" + e.report_id; }
    });
  if (!body.children.length) el("p", "empty", "Nothing in this category.", wrap);
}

// ---------- status footer, tag suggestions ----------
async function showStatus() {
  const box = $("status");
  try {
    STATUS = await api("/api/status");
    box.textContent = "";
    [["VirusTotal", STATUS.virustotal ? "" : "off"], ["AbuseIPDB", STATUS.abuseipdb ? "" : "off"],
     ["Shodan " + (STATUS.shodan === "full" ? "(API)" : "(free InternetDB)"), STATUS.shodan === "full" ? "" : "mid"]].forEach(([nm, st]) => {
      const sp = el("span", "", nm, box);
      sp.prepend(el("i", "dot" + (st ? " " + st : "")));
    });
  } catch { /* optional */ }
}
async function loadTags() {
  try {
    const tags = await api("/api/tags");
    const dl = $("taglist");
    dl.textContent = "";
    tags.slice(0, 100).forEach((t) => { el("option", "", undefined, dl).value = "tag:" + t.tag; });
  } catch { /* optional */ }
}

// ---------- router & wiring ----------
async function route() {
  markNav();
  const h = location.hash;
  let m;
  try {
    if (h === "#/bulk") return bulk();
    if (h === "#/log") return await logsHome();
    if ((m = h.match(/^#\/log\/([a-f0-9]{16})$/))) return await logReport(m[1]);
    if ((m = h.match(/^#\/tag\/(.+)$/))) return await tagPage(decodeURIComponent(m[1]));
    if ((m = h.match(/^#\/r\/([a-f0-9]{16})$/))) return render(await api("/api/reports/" + m[1]));
  } catch (e) { return showError(e.message); }
  return home();
}

$("ind").addEventListener("input", () => {
  const k = detect($("ind").value), badge = $("kind");
  badge.hidden = !k; badge.textContent = k === "?" ? "UNKNOWN" : k || ""; badge.className = "kind" + (k === "?" ? " bad" : "");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) { e.preventDefault(); $("ind").focus(); }
});
$("form").addEventListener("submit", (e) => { e.preventDefault(); search($("ind").value); });
$("attach").addEventListener("click", () => $("file").click());
$("file").addEventListener("change", (e) => { const f = e.target.files[0]; e.target.value = ""; handleFile(f); });

let dragDepth = 0;
const dropBox = $("drop");
window.addEventListener("dragenter", (e) => { if (e.dataTransfer && [...e.dataTransfer.types].includes("Files")) { dragDepth++; dropBox.hidden = false; } });
window.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dropBox.hidden = true; });
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault(); dragDepth = 0; dropBox.hidden = true;
  const f = e.dataTransfer && e.dataTransfer.files[0];
  if (f) handleFile(f);
});

window.addEventListener("hashchange", route);
showStatus().then(route);
loadTags();
