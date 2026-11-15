// Token is kept in memory only. Output uses textContent (never innerHTML) to prevent XSS.
const $ = (id) => document.getElementById(id);
const out = $("out");

function card(title, body, isErr) {
  const d = document.createElement("div");
  d.className = "card";
  const h = document.createElement("strong");
  h.textContent = title;
  const p = document.createElement("pre");
  p.textContent = body;
  if (isErr) p.className = "err";
  d.append(h, p);
  out.append(d);
}

async function run() {
  out.textContent = "";
  const res = await fetch("/api/lookup", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-API-Token": $("token").value},
    body: JSON.stringify({indicator: $("ind").value}),
  });
  const json = await res.json();
  if (!res.ok) return card("Error", JSON.stringify(json.detail ?? json), true);
  card(`${json.type}: ${json.indicator}`, json.cached ? "(cached)" : "fresh lookup");
  for (const r of json.results)
    card(r.provider, r.ok ? JSON.stringify(r.data, null, 2) : r.error, !r.ok);
}
$("go").addEventListener("click", run);
$("ind").addEventListener("keydown", (e) => e.key === "Enter" && run());
