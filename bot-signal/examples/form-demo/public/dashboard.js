const rows = document.getElementById("rows");
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
  return parts.length ? parts.join(" · ") : "clean";
}

function renderRow(item) {
  const tr = document.createElement("tr");
  tr.appendChild(cell(new Date(item.receivedAt).toLocaleTimeString()));

  const verdict = cell(
    item.verdict === "agent"
      ? `AGENT${item.automationKind && item.automationKind !== "unknown" ? ` (${item.automationKind})` : ""}`
      : "HUMAN",
    item.verdict === "agent" ? "bad" : "ok",
  );
  tr.appendChild(verdict);

  tr.appendChild(cell(item.score.toFixed(2)));
  tr.appendChild(cell(`${item.form.name || "—"} · ${item.form.email || "—"}`));
  tr.appendChild(cell(`${item.ip} · ${item.userAgent.slice(0, 40) || "no UA"}`, "muted small"));
  tr.appendChild(cell(layerText(item.layers), "muted small"));
  tr.appendChild(cell(signalText(item), "muted small"));
  return tr;
}

async function refresh() {
  const response = await fetch("/api/submissions");
  const data = await response.json();

  statTotal.textContent = data.total;
  statHumans.textContent = data.humans;
  statAgents.textContent = data.agents;

  rows.replaceChildren();
  if (!data.submissions.length) {
    const tr = document.createElement("tr");
    const td = cell("No submissions yet — fill the form.", "muted");
    td.colSpan = 7;
    tr.appendChild(td);
    rows.appendChild(tr);
    return;
  }

  for (const item of data.submissions) rows.appendChild(renderRow(item));
}

document.getElementById("reset").addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  refresh();
});

refresh();
setInterval(refresh, 2000);
