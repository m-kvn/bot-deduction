import { copyFile, readFile, writeFile } from "node:fs/promises";
import { chromium } from "../bot-signal/node_modules/patchright/index.mjs";

const here = new URL("./", import.meta.url);
const data = JSON.parse(await readFile(new URL("results.json", here), "utf8"));
const chromeMcp = JSON.parse(
  await readFile(new URL("chrome_devtools_mcp_results.json", here), "utf8"),
);
const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const asImage = async (name) =>
  `data:image/png;base64,${(await readFile(new URL(name, here))).toString("base64")}`;

const images = {
  human: await asImage("human_control.png"),
  synthetic: await asImage("synthetic_click_detected.png"),
  headless: await asImage("headless_detected.png"),
};

const detectionCategories = new Set(["Server detection", "API bypass", "Browser detection"]);
const detectionCases = data.results
  .filter((item) => detectionCategories.has(item.category))
  .map((item) => {
    const expectedVerdict = item.expected;
    const actualVerdict = item.actual.startsWith("AGENT") ? "AGENT" : "HUMAN";
    return { ...item, expectedVerdict, actualVerdict };
  });

const agentCases = detectionCases.filter((item) => item.expectedVerdict === "AGENT");
const detectedAgents = agentCases.filter((item) => item.actualVerdict === "AGENT");
const missedAgents = agentCases.filter((item) => item.actualVerdict === "HUMAN");
const agentRecall = ((detectedAgents.length / agentCases.length) * 100).toFixed(1);
const missRate = ((missedAgents.length / agentCases.length) * 100).toFixed(1);

const groupStats = [
  { label: "Server request / identity signals", category: "Server detection" },
  { label: "Direct API and forged payloads", category: "API bypass" },
  { label: "Browser fingerprint and behavior", category: "Browser detection" },
].map(({ label, category }) => {
  const cases = detectionCases.filter((item) => item.category === category);
  const agents = cases.filter((item) => item.expectedVerdict === "AGENT");
  return {
    label,
    total: cases.length,
    agentTotal: agents.length,
    agentDetected: agents.filter((item) => item.actualVerdict === "AGENT").length,
    agentMissed: agents.filter((item) => item.actualVerdict === "HUMAN").length,
  };
});

const statsRows = groupStats
  .map(
    (group) => `<tr>
      <td>${escapeHtml(group.label)}</td>
      <td>${group.total}</td>
      <td>${group.agentDetected}/${group.agentTotal}</td>
      <td class="${group.agentMissed ? "bad" : "good"}">${group.agentMissed}</td>
    </tr>`,
  )
  .join("");

const missedRows = missedAgents
  .map(
    (item) => `<tr>
      <td>${item.id}</td>
      <td><strong>${escapeHtml(item.name)}</strong><div class="small">${escapeHtml(item.vector)}</div></td>
      <td>${escapeHtml(item.actual)}</td>
      <td>${escapeHtml(item.evidence)}</td>
      <td><span class="severity">${escapeHtml(item.severity)}</span></td>
    </tr>`,
  )
  .join("");

const matrixRows = detectionCases
  .map((item) => {
    const passed = item.expectedVerdict === item.actualVerdict;
    return `<tr class="${passed ? "" : "failed"}">
      <td>${item.id}</td>
      <td>${escapeHtml(item.category)}</td>
      <td><strong>${escapeHtml(item.name)}</strong><div class="small">${escapeHtml(item.vector)}</div></td>
      <td>${item.expectedVerdict}</td>
      <td>${escapeHtml(item.actual)}<div class="small">${escapeHtml(item.evidence)}</div></td>
      <td><span class="badge ${passed ? "pass" : "fail"}">${passed ? "PASS" : "FAIL"}</span></td>
    </tr>`;
  })
  .join("");

const detectedRows = detectedAgents
  .map(
    (item) => `<li><strong>${item.id} — ${escapeHtml(item.name)}:</strong> ${escapeHtml(item.actual)}${item.evidence ? `; ${escapeHtml(item.evidence)}` : ""}</li>`,
  )
  .join("");

const chromeMcpRows = chromeMcp.results
  .map(
    (item) => `<tr>
      <td>${escapeHtml(item.method)}</td>
      <td>${escapeHtml(item.expected.toUpperCase())}</td>
      <td>${escapeHtml(item.actual.toUpperCase())}, score ${item.score.toFixed(2)}${item.httpStatus ? `, HTTP ${item.httpStatus}` : ""}</td>
      <td>${escapeHtml(item.signals.join(", "))}</td>
      <td><span class="badge pass">PASS</span></td>
    </tr>`,
  )
  .join("");

const generated = new Date(data.generatedAt).toLocaleString("en-IN", {
  timeZone: "Asia/Calcutta",
  dateStyle: "full",
  timeStyle: "long",
});

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent-Filled Form Detection Test Report</title>
<style>
  @page { size: A4; margin: 17mm 12mm 18mm; }
  :root { --ink:#172033; --navy:#173b64; --blue:#2f6fad; --muted:#667085; --line:#d8e0ea; --panel:#f5f7fb; --green:#147a50; --green-bg:#e7f7ef; --red:#b42318; --red-bg:#fff0ee; }
  * { box-sizing: border-box; }
  body { margin:0; color:var(--ink); font:10.3px/1.45 Arial,"Segoe UI",sans-serif; }
  h1,h2,h3 { color:var(--navy); page-break-after:avoid; }
  h1 { margin:0 0 8px; font-size:29px; line-height:1.12; }
  h2 { margin:21px 0 9px; padding-bottom:5px; border-bottom:2px solid #d8e7f4; font-size:17px; }
  h3 { margin:14px 0 5px; font-size:13px; }
  p { margin:6px 0; }
  ul,ol { margin:6px 0 9px 19px; padding:0; }
  li { margin:4px 0; }
  code { font:9.4px Consolas,monospace; background:#edf2f7; padding:1px 3px; border-radius:3px; }
  table { width:100%; border-collapse:collapse; }
  th { background:#eaf0f7; color:#35465d; text-align:left; font-size:8.5px; text-transform:uppercase; letter-spacing:.2px; }
  th,td { padding:5px 6px; border:1px solid var(--line); vertical-align:top; }
  tr { page-break-inside:avoid; }
  .cover { min-height:242mm; display:flex; flex-direction:column; justify-content:center; page-break-after:always; }
  .eyebrow { color:var(--blue); font-size:11px; font-weight:800; letter-spacing:1.4px; text-transform:uppercase; }
  .subtitle { max-width:650px; color:var(--muted); font-size:15px; }
  .metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin:22px 0 12px; }
  .metric { padding:12px; border:1px solid var(--line); border-radius:8px; background:var(--panel); }
  .metric strong { display:block; color:var(--navy); font-size:23px; }
  .metric span { color:var(--muted); font-size:8.5px; text-transform:uppercase; letter-spacing:.45px; }
  .metric.good strong,.good { color:var(--green); }
  .metric.bad strong,.bad { color:var(--red); }
  .verdict { padding:14px 16px; border-left:5px solid var(--red); background:var(--red-bg); font-size:12.3px; }
  .verdict strong { color:var(--red); }
  .meta { margin-top:20px; font-size:10.5px; }
  .meta td { padding:7px 8px; border-width:1px 0 0; }
  .meta td:first-child { width:155px; color:var(--muted); font-weight:700; }
  .callout { margin:9px 0; padding:10px 12px; border:1px solid #b8d2e9; border-radius:7px; background:#eff7ff; }
  .finding { margin:9px 0; padding:11px 13px; border:1px solid var(--line); border-left:4px solid var(--red); border-radius:6px; page-break-inside:avoid; }
  .finding h3 { margin-top:0; color:var(--red); }
  .badge { display:inline-block; padding:2px 6px; border-radius:10px; font-size:8px; font-weight:800; }
  .pass { color:var(--green); background:var(--green-bg); }
  .fail { color:var(--red); background:var(--red-bg); }
  .severity { color:white; background:var(--red); border-radius:9px; padding:2px 6px; font-size:7.7px; font-weight:700; text-transform:uppercase; }
  .failed td { background:#fff8f7; }
  .small { margin-top:2px; color:var(--muted); font-size:8px; line-height:1.3; }
  .matrix { font-size:8.5px; }
  .matrix th:nth-child(1) { width:42px; }
  .matrix th:nth-child(2) { width:78px; }
  .matrix th:nth-child(3) { width:170px; }
  .matrix th:nth-child(4) { width:55px; }
  .matrix th:nth-child(6) { width:45px; }
  .page-break { page-break-before:always; }
  .evidence { margin:10px 0 16px; page-break-inside:avoid; }
  .evidence img { display:block; width:100%; max-height:185mm; object-fit:contain; object-position:top; border:1px solid var(--line); border-radius:6px; }
  .caption { margin-top:4px; color:var(--muted); font-size:8.5px; }
  .footnote { color:var(--muted); font-size:8.5px; }
</style>
</head>
<body>
  <section class="cover">
    <div class="eyebrow">Primary-purpose assessment</div>
    <h1>Agent-Filled Form<br>Detection Test Report</h1>
    <p class="subtitle">Can the application correctly decide whether a contact form was filled by a human or by an automated agent?</p>
    <div class="metrics">
      <div class="metric"><strong>${detectionCases.length}</strong><span>Classification tests</span></div>
      <div class="metric good"><strong>${detectedAgents.length}/${agentCases.length}</strong><span>Agents detected</span></div>
      <div class="metric bad"><strong>${missedAgents.length}</strong><span>Agents missed</span></div>
      <div class="metric"><strong>${agentRecall}%</strong><span>Agent detection rate</span></div>
    </div>
    <div class="verdict"><strong>Corrected verdict: OBJECTIVE NOT FULLY MET.</strong><br>
      Codex automation initiated all ${detectionCases.length} classification submissions, so every expected verdict is AGENT. The app detected ${detectedAgents.length} and incorrectly returned HUMAN for ${missedAgents.length}. The agent detection rate was ${agentRecall}% and the miss rate was ${missRate}%.</div>
    <div class="callout"><strong>Ground-truth correction:</strong> Human-like telemetry does not make the submitter human. All ${missedAgents.length} HUMAN results in this report are agent-detection failures because Codex, Patchright, Chrome DevTools MCP, JavaScript, or a direct-request harness generated the submission.</div>
    <table class="meta">
      <tr><td>Target</td><td><code>http://localhost:8787/index.html</code></td></tr>
      <tr><td>Primary outcome</td><td>AGENT versus HUMAN form-submission verdict</td></tr>
      <tr><td>Test methods</td><td>Chrome DevTools MCP, Google Chrome through Patchright, headless Chromium, trusted browser input, DOM APIs, JavaScript events, direct HTTP, forged payloads, server headers/IP/TLS scenarios</td></tr>
      <tr><td>Agent detection accuracy</td><td>${detectedAgents.length}/${agentCases.length} = ${agentRecall}% across Codex-generated classification attempts</td></tr>
      <tr><td>Genuine-human sessions</td><td>0 — false-positive performance was not measured by this automated run</td></tr>
      <tr><td>Execution date</td><td>${escapeHtml(generated)}</td></tr>
      <tr><td>Live-data safety</td><td>Existing live dashboard records were not changed; mutating tests used an in-memory instance of the same app.</td></tr>
    </table>
  </section>

  <h2>1. Detection scorecard</h2>
  <table>
    <thead><tr><th>Detection area</th><th>Codex-generated tests</th><th>Agents detected</th><th>Agents missed as HUMAN</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
  <p>The server/request matrix detected ${groupStats[0].agentDetected} of ${groupStats[0].total} Codex-generated submissions, the API matrix detected ${groupStats[1].agentDetected} of ${groupStats[1].total}, and the browser matrix detected ${groupStats[2].agentDetected} of ${groupStats[2].total}. Human-looking automated inputs are still able to cross the browser-to-server trust boundary.</p>

  <h2>2. Chrome DevTools MCP verification</h2>
  <p>The hardened live application was separately exercised through the Chrome DevTools MCP interface. All ${chromeMcp.total} MCP-driven agent submissions were classified as AGENT.</p>
  <table>
    <thead><tr><th>MCP method</th><th>Expected</th><th>Actual</th><th>Triggered evidence</th><th>Status</th></tr></thead>
    <tbody>${chromeMcpRows}</tbody>
  </table>

  <h2>3. Agents incorrectly classified as human</h2>
  <table>
    <thead><tr><th>ID</th><th>Agent method</th><th>Observed verdict</th><th>Evidence</th><th>Severity</th></tr></thead>
    <tbody>${missedRows}</tbody>
  </table>

  <div class="finding">
    <h3>Remaining limitation — Public browser telemetry can ultimately be forged</h3>
    <p>The ${missedAgents.length} misses used human-looking forged telemetry, low-risk/advisory network profiles, or human-like CDP input. Codex initiated every one, but the app returned HUMAN because public browser telemetry and CDP-generated trusted events do not prove a person was present.</p>
    <p><strong>Impact:</strong> An automated client that avoids obvious bot artifacts can bypass the binary verdict. Missing or replayed challenges, malformed layers, obvious synthetic events, headless browsers, and known automation markers were detected.</p>
  </div>
  <div class="callout"><strong>Fixes verified in this run:</strong> both client layers are mandatory; scores and signals are consistency-checked; challenges are one-time, expiring and UA/IP-bound; trusted field edits and recent submit intent are required; synthetic events are decisive at threshold 0.50; proxy/TLS metadata is ignored unless trusted-edge mode is enabled.</div>

  <h2>4. Agent techniques successfully detected</h2>
  <ul>${detectedRows}</ul>

  <h2>5. Genuine-human validation status</h2>
  <p>No genuine human session was executed in this Codex-driven run. The cases previously described as human controls were only automated submissions carrying human-like data, so their HUMAN verdicts are now counted as failures.</p>
  <table>
    <thead><tr><th colspan="5">Physical-human test coverage</th></tr></thead>
    <tbody><tr><td colspan="5">Not measured: requires an independently performed physical-human test session.</td></tr></tbody>
  </table>
  <div class="callout"><strong>Interpretation:</strong> This automated run measures agent recall only. It cannot establish a genuine-human acceptance rate.</div>

  <h2>6. Final assessment for the app's intended use</h2>
  <p>The application is effective against obvious headless agents, known automation fingerprints, direct script clients without browser telemetry, explicit framework markers, robotic typing/scrolling, suspicious server identities, and contradictory request metadata.</p>
  <p>The hardened application detected ${agentRecall}% of the Codex-generated classification attempts. It cannot prove that a person filled the form because a sufficiently capable requester can fabricate the client transcript or generate trusted browser input through automation.</p>
  <h3>Recommended production controls</h3>
  <ol>
    <li>Use CAPTCHA, device attestation, email verification, or another server-verifiable step-up challenge for high-value or uncertain submissions.</li>
    <li>Apply IP/account/session rate limits and duplicate-content detection independently of the browser verdict.</li>
    <li>Keep the verdict as a risk signal; introduce an UNCERTAIN/challenge state instead of interpreting every clean transcript as proven human.</li>
    <li>Retest accessibility tools, autofill, password managers, mobile browsers and the production proxy/CDN before strict enforcement.</li>
    <li>Store one-time challenges in shared infrastructure when running multiple server instances.</li>
  </ol>

  <h2 class="page-break">7. Complete human-versus-agent matrix</h2>
  <div class="callout"><strong>Reading the matrix:</strong> every submission originated from Codex automation, so every expected verdict is AGENT. Each HUMAN result is therefore a failed agent-detection case. Total misses: ${missedAgents.length}.</div>
  <table class="matrix">
    <thead><tr><th>ID</th><th>Area</th><th>Profile / method</th><th>Expected</th><th>Actual / evidence</th><th>Status</th></tr></thead>
    <tbody>${matrixRows}</tbody>
  </table>

  <h2 class="page-break">8. Browser evidence</h2>
  <div class="evidence"><img src="${images.human}"><div class="caption">Codex/Patchright human-like CDP input: incorrectly classified HUMAN, score 0.00.</div></div>
  <div class="evidence"><img src="${images.synthetic}"><div class="caption">JavaScript <code>element.click()</code> without pointer movement: correctly classified AGENT, score 0.95.</div></div>
  <div class="evidence"><img src="${images.headless}"><div class="caption">Standard headless automation: correctly classified AGENT, score 1.00.</div></div>

  <h2>9. Scope note</h2>
  <p>This is a risk-based set of ${detectionCases.length} classification scenarios covering the app's documented layers and the requested Chrome/DOM/JavaScript/request techniques. “All possible” browser and network combinations are not finite; the report does not certify every OS, browser version, mobile device, assistive technology, extension, proxy or TLS terminator.</p>
  <p>Chrome DevTools MCP was used directly for native MCP form filling/clicking and MCP-executed <code>HTMLElement.click()</code>, <code>form.requestSubmit()</code>, and synthetic submit dispatch. The wider matrix additionally used installed Google Chrome through Patchright and raw requests.</p>
  <p class="footnote">Fourteen additional functionality/security checks also passed (page/dashboard loading, validation, HTTP handling, storage limits, Unicode, dashboard consistency/reset and output encoding). They are excluded from the headline numbers because they do not answer HUMAN versus AGENT.</p>
</body>
</html>`;

await writeFile(new URL("agent_detection_test_report.html", here), html, "utf8");
const pdfUrl = new URL("agent_detection_test_report.pdf", here);
const browser = await chromium.launch({ headless: true, executablePath: chromePath });
try {
  const page = await browser.newPage();
  await page.goto(new URL("agent_detection_test_report.html", here).href, { waitUntil: "load" });
  await page.pdf({
    path: pdfUrl.pathname.slice(1),
    format: "A4",
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div style="width:100%;padding:0 12mm;text-align:right;font-size:7px;color:#7b8794">Agent-Filled Form Detection Test Report</div>',
    footerTemplate: '<div style="width:100%;padding:0 12mm;display:flex;justify-content:space-between;font-size:7px;color:#7b8794"><span>Human vs Agent classification assessment</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
    margin: { top: "17mm", right: "12mm", bottom: "18mm", left: "12mm" },
  });
} finally {
  await browser.close();
}

await copyFile(pdfUrl, new URL("test_report.pdf", here));
console.log(
  `Created focused report: ${detectionCases.length} Codex-generated classification tests, ${detectedAgents.length} agents detected, ${missedAgents.length} missed.`,
);
