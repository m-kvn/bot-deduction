const rows = document.getElementById("rows");
const TOKEN_KEY = "bot-signal-admin-token";
let tokenDeclined = false;

async function adminFetch(url, init = {}) {
  const send = (token) =>
    fetch(url, {
      ...init,
      headers: { ...(init.headers ?? {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    });
  const used = sessionStorage.getItem(TOKEN_KEY);
  let response = await send(used);
  if (response.status !== 401 || tokenDeclined) return response;
  let token = sessionStorage.getItem(TOKEN_KEY);
  if (!token || token === used) {
    token = window.prompt("Admin token for this dashboard");
    if (!token) {
      tokenDeclined = true;
      return response;
    }
    sessionStorage.setItem(TOKEN_KEY, token);
  }
  response = await send(token);
  if (response.status === 401) sessionStorage.removeItem(TOKEN_KEY);
  return response;
}
const statTotal = document.getElementById("stat-total");
const statHumans = document.getElementById("stat-humans");
const statAgents = document.getElementById("stat-agents");

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function layerText(layers) {
  const part = (name, layer) => `${name} ${layer ? layer.score.toFixed(2) : "n/a"}`;
  return [
    part("instant", layers.instant),
    part("behav", layers.behavioral),
    part("server", layers.server),
  ].join(" · ");
}

function signalText(item) {
  const notes = new Set(item.notes ?? []);
  const decisive = item.signals.filter(
    (signal) => !(signal.layer === "server" && notes.has(signal.id)),
  );
  const parts = [];
  if (decisive.length) {
    parts.push(decisive.slice(0, 3).map((signal) => `${signal.layer}:${signal.id}`).join(", "));
  }
  if (notes.size) parts.push(`advisory: ${[...notes].join(", ")}`);
  if (item.demoted?.length) parts.push(`demoted: ${item.demoted.join(", ")}`);
  if (item.agent) parts.push(`signed agent: ${item.agent.status}${item.agent.name ? ` (${item.agent.name})` : ""}`);
  return parts.length ? parts.join(" · ") : "clean";
}

function renderRow(item) {
  const tr = document.createElement("tr");
  tr.appendChild(cell(new Date(item.receivedAt).toLocaleTimeString()));

  const verdict = cell(
    `${
      item.verdict === "agent"
        ? `AGENT${item.automationKind && item.automationKind !== "unknown" ? ` (${item.automationKind})` : ""}`
        : "HUMAN"
    }${item.outcome ? ` · ${item.outcome}` : ""}`,
    item.verdict === "agent" ? "bad" : "ok",
  );
  tr.appendChild(verdict);

  tr.appendChild(cell(item.score.toFixed(2)));
  tr.appendChild(cell(`${item.form.name || "—"} · ${item.form.email || "—"}`));
  tr.appendChild(cell(`${item.ip} · ${item.userAgent.slice(0, 40) || "no UA"}`, "muted small"));
  tr.appendChild(cell(layerText(item.layers), "muted small"));
  tr.appendChild(cell(signalText(item), "muted small"));
  tr.appendChild(reviewCell(item));
  return tr;
}

function reviewCell(item) {
  if (item.label) {
    return cell(`labelled ${item.label}`, item.label === item.verdict ? "muted small" : "bad small");
  }
  const td = document.createElement("td");
  for (const label of ["human", "agent"]) {
    const button = document.createElement("button");
    button.className = "ghost";
    button.textContent = label === "human" ? "Human" : "Agent";
    button.addEventListener("click", async () => {
      button.disabled = true;
      await adminFetch(`/api/submissions/${item.id}/review`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label }),
      });
      refresh();
    });
    td.appendChild(button);
  }
  return td;
}

const precisionRows = document.getElementById("precision-rows");
const precisionSummary = document.getElementById("precision-summary");

async function refreshPrecision() {
  const response = await adminFetch("/api/signal-stats");
  if (!response.ok) return;
  const data = await response.json();
  precisionSummary.textContent = data.labeled
    ? `· ${data.labeled} labelled, ${data.falsePositives} false positive${data.falsePositives === 1 ? "" : "s"}, ${data.falseNegatives} missed`
    : "";
  precisionRows.replaceChildren();
  if (!data.signals.length) {
    const tr = document.createElement("tr");
    const td = cell("Label a few submissions to see which signals hold up.", "muted");
    td.colSpan = 4;
    tr.appendChild(td);
    precisionRows.appendChild(tr);
    return;
  }
  for (const entry of data.signals) {
    const tr = document.createElement("tr");
    tr.appendChild(cell(`${entry.signal}${entry.demoted ? " (demoted)" : ""}`, "small"));
    tr.appendChild(cell(String(entry.human), entry.human ? "bad" : "muted"));
    tr.appendChild(cell(String(entry.agent), "muted"));
    tr.appendChild(cell(`${Math.round(entry.precision * 100)}%`, entry.precision < 0.8 ? "bad" : "ok"));
    precisionRows.appendChild(tr);
  }
}

const protectionRows = document.getElementById("protection-rows");
const protectionMode = document.getElementById("protection-mode");

function renderProtectionRow(event) {
  const tr = document.createElement("tr");
  tr.appendChild(cell(new Date(event.at).toLocaleTimeString()));
  tr.appendChild(cell(event.rule, event.blocked ? "bad" : ""));
  tr.appendChild(cell(`${event.method} ${event.path}`, "small"));
  tr.appendChild(cell(`${event.ip} · ${event.userAgent.slice(0, 40) || "no UA"}`, "muted small"));
  const outcome = event.blocked ? "blocked" : event.state === "DRY_RUN" ? "observed (dry run)" : "observed";
  tr.appendChild(cell(`${outcome} — ${event.reason}`, "muted small"));
  return tr;
}

async function refreshProtection() {
  const response = await adminFetch("/api/protection");
  if (!response.ok) return;
  const data = await response.json();
  protectionMode.textContent = `· ${data.mode} mode over ${data.transport}`;
  protectionRows.replaceChildren();
  if (!data.events.length) {
    const tr = document.createElement("tr");
    const td = cell("Nothing tripped yet.", "muted");
    td.colSpan = 5;
    tr.appendChild(td);
    protectionRows.appendChild(tr);
    return;
  }
  for (const event of data.events) protectionRows.appendChild(renderProtectionRow(event));
}

async function refresh() {
  refreshProtection();
  refreshPrecision();
  const response = await adminFetch("/api/submissions");
  if (!response.ok) return;
  const data = await response.json();

  statTotal.textContent = data.total;
  statHumans.textContent = data.humans;
  statAgents.textContent = data.agents;

  rows.replaceChildren();
  if (!data.submissions.length) {
    const tr = document.createElement("tr");
    const td = cell("No submissions yet — fill the form.", "muted");
    td.colSpan = 8;
    tr.appendChild(td);
    rows.appendChild(tr);
    return;
  }

  for (const item of data.submissions) rows.appendChild(renderRow(item));
}

document.getElementById("reset").addEventListener("click", async () => {
  await adminFetch("/api/reset", { method: "POST" });
  refresh();
});

refresh();
setInterval(refresh, 2000);
