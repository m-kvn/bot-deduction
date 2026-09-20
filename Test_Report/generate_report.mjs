import { fileURLToPath } from "node:url";
import { readFile, writeFile } from "node:fs/promises";
import { chromium } from "../bot-signal/node_modules/patchright/index.mjs";

const here = new URL("./", import.meta.url);
const report = JSON.parse(await readFile(fileURLToPath(new URL("results.json", here)), "utf8"));
const chromePath = process.env.CHROME_PATH ?? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const imageData = async (name) => {
  const bytes = await readFile(fileURLToPath(new URL(name, here)));
  return `data:image/png;base64,${bytes.toString("base64")}`;
};

const screenshots = {
  human: await imageData("human_control.png"),
  synthetic: await imageData("synthetic_click_detected.png"),
  headless: await imageData("headless_detected.png"),
  dashboard: await imageData("dashboard.png"),
};

const categories = [...new Set(report.results.map((item) => item.category))].map((category) => {
  const items = report.results.filter((item) => item.category === category);
  return {
    category,
    total: items.length,
    passed: items.filter((item) => item.passed).length,
    failed: items.filter((item) => !item.passed).length,
  };
});

const failures = report.results.filter((item) => !item.passed);
const critical = failures.filter((item) => item.severity === "Critical").length;
const high = failures.filter((item) => item.severity === "High").length;
const passRate = ((report.passed / report.total) * 100).toFixed(1);

const categoryRows = categories
  .map(
    (item) => `<tr>
      <td>${escapeHtml(item.category)}</td>
      <td class="num">${item.total}</td>
      <td class="num pass-text">${item.passed}</td>
      <td class="num ${item.failed ? "fail-text" : ""}">${item.failed}</td>
    </tr>`,
  )
  .join("");

const resultRows = report.results
  .map(
    (item) => `<tr class="result-row ${item.passed ? "passed" : "failed"}">
      <td class="id">${item.id}</td>
      <td>${escapeHtml(item.category)}</td>
      <td><strong>${escapeHtml(item.name)}</strong><div class="small">${escapeHtml(item.vector)}</div></td>
      <td>${escapeHtml(item.expected)}</td>
      <td>${escapeHtml(item.actual)}${item.evidence ? `<div class="small">${escapeHtml(item.evidence)}</div>` : ""}</td>
      <td><span class="badge ${item.passed ? "badge-pass" : "badge-fail"}">${item.passed ? "PASS" : "FAIL"}</span>${!item.passed ? `<div class="severity">${escapeHtml(item.severity)}</div>` : ""}</td>
    </tr>`,
  )
  .join("");

const failureRows = failures
  .map(
    (item) => `<tr>
      <td>${item.id}</td>
      <td>${escapeHtml(item.severity)}</td>
      <td>${escapeHtml(item.name)}</td>
      <td>${escapeHtml(item.actual)}</td>
    </tr>`,
  )
  .join("");

const generated = new Date(report.generatedAt);
const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Human vs Agent Deduction App — Test Report</title>
<style>
  @page { size: A4; margin: 17mm 12mm 18mm; }
  :root {
    --ink: #172033;
    --muted: #667085;
    --line: #d9e0ea;
    --panel: #f5f7fb;
    --navy: #173b64;
    --blue: #2f6fad;
    --green: #147a50;
    --green-bg: #e8f7ef;
    --red: #b42318;
    --red-bg: #fff0ee;
    --amber: #9a6700;
  }
  * { box-sizing: border-box; }
  body { margin: 0; color: var(--ink); font: 10.4px/1.45 Arial, "Segoe UI", sans-serif; }
  h1, h2, h3 { color: var(--navy); page-break-after: avoid; }
  h1 { margin: 0 0 7px; font-size: 28px; line-height: 1.14; }
  h2 { margin: 22px 0 9px; padding-bottom: 5px; border-bottom: 2px solid #d7e5f2; font-size: 17px; }
  h3 { margin: 15px 0 5px; font-size: 13px; }
  p { margin: 6px 0; }
  ul, ol { margin: 6px 0 8px 19px; padding: 0; }
  li { margin: 4px 0; }
  code { font: 9.6px Consolas, monospace; background: #eef2f7; padding: 1px 3px; border-radius: 3px; }
  .cover { min-height: 242mm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
  .eyebrow { color: var(--blue); font-size: 11px; font-weight: 700; letter-spacing: 1.4px; text-transform: uppercase; }
  .subtitle { max-width: 640px; color: var(--muted); font-size: 15px; }
  .meta { margin-top: 22px; width: 100%; border-collapse: collapse; font-size: 11px; }
  .meta td { padding: 7px 8px; border-top: 1px solid var(--line); }
  .meta td:first-child { width: 145px; color: var(--muted); font-weight: 700; }
  .summary-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 22px 0 10px; }
  .metric { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: var(--panel); }
  .metric .value { display: block; font-size: 24px; font-weight: 800; color: var(--navy); }
  .metric .label { display: block; color: var(--muted); font-size: 9px; letter-spacing: .5px; text-transform: uppercase; }
  .metric.fail .value { color: var(--red); }
  .metric.pass .value { color: var(--green); }
  .decision { margin-top: 10px; padding: 13px 15px; border-left: 5px solid var(--red); background: var(--red-bg); font-size: 12px; }
  .decision strong { color: var(--red); }
  .callout { margin: 9px 0; padding: 10px 12px; border: 1px solid #b9d2e8; border-radius: 7px; background: #eff7ff; }
  .finding { margin: 9px 0; padding: 11px 13px; border: 1px solid var(--line); border-left: 4px solid var(--red); border-radius: 6px; page-break-inside: avoid; }
  .finding h3 { margin-top: 0; color: var(--red); }
  .finding .tag { float: right; color: #fff; background: var(--red); border-radius: 10px; padding: 2px 7px; font-size: 8px; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #eaf0f7; color: #35465d; text-align: left; font-size: 8.7px; text-transform: uppercase; letter-spacing: .25px; }
  th, td { padding: 5px 6px; border: 1px solid var(--line); vertical-align: top; }
  tr { page-break-inside: avoid; }
  .num { text-align: right; }
  .pass-text { color: var(--green); font-weight: 700; }
  .fail-text { color: var(--red); font-weight: 700; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 8px; font-weight: 800; }
  .badge-pass { color: var(--green); background: var(--green-bg); }
  .badge-fail { color: var(--red); background: var(--red-bg); }
  .severity { margin-top: 3px; color: var(--red); font-size: 7.8px; font-weight: 700; text-transform: uppercase; }
  .small { margin-top: 2px; color: var(--muted); font-size: 8px; line-height: 1.3; }
  .id { white-space: nowrap; font-family: Consolas, monospace; }
  .result-row.failed td { background: #fff9f8; }
  .matrix { font-size: 8.5px; }
  .matrix th:nth-child(1) { width: 43px; }
  .matrix th:nth-child(2) { width: 74px; }
  .matrix th:nth-child(3) { width: 165px; }
  .matrix th:nth-child(4) { width: 82px; }
  .matrix th:nth-child(6) { width: 46px; }
  .screenshot { margin: 10px 0 16px; page-break-inside: avoid; }
  .screenshot img { display: block; width: 100%; max-height: 190mm; object-fit: contain; object-position: top; border: 1px solid var(--line); border-radius: 6px; }
  .caption { margin-top: 4px; color: var(--muted); font-size: 8.5px; }
  .page-break { page-break-before: always; }
  .footer-note { color: var(--muted); font-size: 8.5px; }
</style>
</head>
<body>
  <section class="cover">
    <div class="eyebrow">Independent end-to-end assessment</div>
    <h1>Human vs Agent Deduction App<br>Test Report</h1>
    <p class="subtitle">Functional and adversarial validation of browser fingerprinting, behavioral analysis, server request analysis, direct API abuse, and dashboard behavior.</p>

    <div class="summary-strip">
      <div class="metric"><span class="value">${report.total}</span><span class="label">Scenarios</span></div>
      <div class="metric pass"><span class="value">${report.passed}</span><span class="label">Passed</span></div>
      <div class="metric fail"><span class="value">${report.failed}</span><span class="label">Failed</span></div>
      <div class="metric"><span class="value">${passRate}%</span><span class="label">Pass rate</span></div>
    </div>

    <div class="decision"><strong>Overall result: NOT READY for reliable agent deduction in an adversarial environment.</strong><br>
      Ordinary headless automation and many explicit artifacts are detected, but a capable agent can be accepted as human by forging client result objects or using submission paths that produce no monitored behavioral event.</div>

    <table class="meta">
      <tr><td>Requested target</td><td><code>http://localhost:8787/index.html</code> — live smoke test passed</td></tr>
      <tr><td>Isolated execution</td><td><code>${escapeHtml(report.isolatedTarget)}</code> — same application, in-memory database</td></tr>
      <tr><td>Tested build</td><td><code>bot-signal 2.0.14</code> form demo</td></tr>
      <tr><td>Browser methods</td><td>Installed Google Chrome via Patchright, headless Chromium, physical-style input, DOM methods, <code>element.click()</code>, <code>dispatchEvent()</code>, and in-page <code>fetch()</code></td></tr>
      <tr><td>Request methods</td><td>Node HTTP requests plus bundled server cross-check for headers, IP, GeoIP, crawler verification, JA3/JA4 and TLS policy</td></tr>
      <tr><td>Run date</td><td>${escapeHtml(generated.toLocaleString("en-IN", { timeZone: "Asia/Calcutta", dateStyle: "full", timeStyle: "long" }))}</td></tr>
      <tr><td>Data safety</td><td>The four existing live dashboard records were left untouched. Mutating tests ran only against an isolated in-memory server.</td></tr>
    </table>
  </section>

  <h2>1. Executive summary</h2>
  <p>The application correctly handled page loading, form validation, malformed input, output encoding, dashboard counts, data truncation, Unicode data, and standard HTTP failures. The human-like control was accepted with score <strong>0.00</strong>; standard headless Patchright was rejected with score <strong>1.00</strong>. All 25 server-detection policy cases passed.</p>
  <p>However, 11 adversarial scenarios were accepted as human. Six are rated Critical and five High. No false positive occurred in the human-like control, travel/VPN, locale, or soft-server-signal cases covered by this run.</p>

  <table>
    <thead><tr><th>Area</th><th class="num">Total</th><th class="num">Passed</th><th class="num">Failed</th></tr></thead>
    <tbody>${categoryRows}</tbody>
  </table>

  <h3>Failed cases</h3>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Scenario</th><th>Observed result</th></tr></thead>
    <tbody>${failureRows}</tbody>
  </table>

  <h2>2. Priority findings</h2>

  <div class="finding">
    <span class="tag">Critical</span>
    <h3>F-01 — The server trusts attacker-controlled client verdict objects</h3>
    <p><strong>Affected:</strong> TC-033, TC-034, TC-035 and TC-063.</p>
    <p>A direct request or in-page script can supply fabricated <code>instant</code> and/or <code>behavioral</code> objects with score 0 and <code>isLegitClient: true</code>. The server accepts them without provenance, schema integrity, freshness, or a requirement that both layers exist. With realistic browser headers, the final result is HUMAN score 0.</p>
    <p><strong>Impact:</strong> This is a complete classification bypass for an attacker able to construct the request body.</p>
    <p><strong>Recommended action:</strong> Treat browser results only as untrusted telemetry. Require both layers, validate their complete schema, issue a short-lived server nonce bound to the session, and verify event-derived claims server-side where possible. A client-side signature embedded in public JavaScript is not a security boundary. Apply rate limiting and abuse controls independently of this score.</p>
  </div>

  <div class="finding">
    <span class="tag">Critical</span>
    <h3>F-02 — Submit-level programmatic paths generate no behavioral evidence</h3>
    <p><strong>Affected:</strong> TC-048 and TC-049; TC-050 demonstrates the same blind spot using a trusted Enter event after direct value assignment.</p>
    <p><code>form.requestSubmit()</code> and dispatching a synthetic <code>submit</code> event were accepted as HUMAN score 0. The detector monitors mouse, wheel, keyboard, click and touch events, but not the form's submit event or whether values arrived through trusted input/change events.</p>
    <p><strong>Recommended action:</strong> Track field focus, trusted <code>beforeinput</code>/<code>input</code>/<code>change</code> events, elapsed completion time, and a trusted recent submit precursor. Reject or challenge submissions with populated fields but no credible input history. Ensure keyboard submission remains usable by genuine users and assistive technology.</p>
  </div>

  <div class="finding">
    <span class="tag">High</span>
    <h3>F-03 — A synthetic event alone scores below the rejection threshold</h3>
    <p><strong>Affected:</strong> TC-046, TC-047, TC-052 and TC-055.</p>
    <p><code>isTrusted === false</code> correctly triggered <code>synthetic-events</code>, but its weight is 0.50 while the behavioral rejection threshold is 0.55. A prior trusted mouse move suppresses the supporting click-without-movement signal, producing HUMAN score 0.50. Some generated mouse/touch paths likewise avoided the cadence/path corroborator and remained at 0.50.</p>
    <p><strong>Recommended action:</strong> Make synthetic events decisive (weight at least the threshold) or introduce a hard rule for synthetic submit-related events. If false-positive concerns prevent that, require a challenge whenever synthetic evidence is present instead of accepting outright.</p>
  </div>

  <div class="callout"><strong>Important design boundary:</strong> Browser-side bot detection is probabilistic. Headful automation can emit trusted CDP events and remove common framework markers. Use this library as one risk signal within layered controls, not as sole authorization for a sensitive operation.</div>

  <h2>3. What worked</h2>
  <ul>
    <li><strong>25/25 server policy checks:</strong> scripting and crawler UAs, UA/client-hint/platform/mobile contradictions, GeoIP/timezone/locale policies, datacenter and abuse-listed IPs, iCloud Private Relay advisories, crawler verification, JA3/JA4, and optional TLS requirements.</li>
    <li><strong>Explicit automation artifacts:</strong> WebDriver, Playwright, Puppeteer, Selenium, DOM automation controller, tiny screen, patched navigator getter, and standard headless browser were rejected.</li>
    <li><strong>Behavioral catches:</strong> isolated synthetic click, isolated dispatched click, rapid synthetic typing, uniform synthetic scrolling, and teleporting pointer were rejected.</li>
    <li><strong>Human/false-positive controls:</strong> trusted human-like input, traveller/VPN cases, locale drift, private relay and a single weak datacenter/header signal behaved according to policy.</li>
    <li><strong>Application behavior:</strong> native required/email validation, HTTP 400/404/405 handling, field allow-listing and 500-character limit, Unicode persistence, dashboard consistency/reset, and stored-XSS output encoding passed.</li>
  </ul>

  <h2>4. Methodology and interpretation</h2>
  <p>A PASS means the observed result matched the security or functional expectation. For adversarial cases the expected result is AGENT; HUMAN is a false negative. For human-control and advisory-policy cases the expected result is HUMAN. Tests used the actual application code and real browser execution; server signal tests used the application's bundled isolated cross-check.</p>
  <p>The phrase “all possible scenarios” is not literally finite for browser fingerprints, operating systems, proxies, extensions, networks, and adversarial scripts. This report covers all practical interaction families requested plus the application's documented signal families. It does not certify every Chrome/Firefox/Safari version, mobile device, assistive technology, CDN/TLS terminator, or production network topology.</p>
  <p>Chrome MCP was not exposed in this execution environment. The equivalent browser coverage used the installed Google Chrome controlled through Patchright, plus direct DOM JavaScript and raw HTTP requests. This distinction does not weaken the tested DOM/event and network behaviors; exact Chrome-MCP implementation artifacts were not assessed.</p>

  <h2 class="page-break">5. Complete result matrix</h2>
  <table class="matrix">
    <thead><tr><th>ID</th><th>Area</th><th>Scenario / vector</th><th>Expected</th><th>Actual / evidence</th><th>Status</th></tr></thead>
    <tbody>${resultRows}</tbody>
  </table>

  <h2 class="page-break">6. Browser evidence</h2>
  <div class="screenshot"><img src="${screenshots.human}"><div class="caption">Human-like trusted control: accepted as Human, score 0.00.</div></div>
  <div class="screenshot"><img src="${screenshots.synthetic}"><div class="caption">Untrusted <code>HTMLElement.click()</code> without prior pointer movement: detected as Agent, score 0.74.</div></div>
  <div class="screenshot"><img src="${screenshots.headless}"><div class="caption">Standard headless Patchright/Chromium: detected as Agent, score 1.00.</div></div>
  <div class="screenshot"><img src="${screenshots.dashboard}"><div class="caption">Isolated dashboard during execution; API and UI counts/rows matched.</div></div>

  <h2>7. Remediation and retest checklist</h2>
  <ol>
    <li>Stop treating posted <code>client.instant</code> and <code>client.behavioral</code> verdicts as authoritative; validate presence and shape, and design a server-issued challenge/freshness mechanism.</li>
    <li>Record trusted field-edit history and submit provenance, including <code>beforeinput</code>, <code>input</code>, <code>change</code>, focus sequence, duration, and a recent trusted click or key precursor.</li>
    <li>Raise <code>synthetic-events</code> from 0.50 to at least the 0.55 threshold, or make it an explicit rejection/challenge rule.</li>
    <li>Add regression tests for all eleven failed IDs, especially clean forged payloads, one-layer payloads, <code>requestSubmit()</code>, synthetic <code>submit</code>, trusted-move-plus-synthetic-click, and in-page forged <code>fetch()</code>.</li>
    <li>Retest accessibility paths before enforcing trusted-event rules, then run the matrix in production-like Chrome, Firefox, Safari and mobile contexts behind the real proxy/CDN/TLS terminator.</li>
  </ol>
  <p class="footer-note">Report generated from machine-readable results.json. Existing live submissions were not reset or modified.</p>
</body>
</html>`;

await writeFile(fileURLToPath(new URL("test_report.html", here)), html, "utf8");

const browser = await chromium.launch({ headless: true, executablePath: chromePath });
try {
  const page = await browser.newPage();
  await page.goto(new URL("test_report.html", here).href, { waitUntil: "load" });
  await page.pdf({
    path: fileURLToPath(new URL("test_report.pdf", here)),
    format: "A4",
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div style="width:100%;font-size:7px;color:#7b8794;padding:0 12mm;text-align:right">Human vs Agent Deduction App — Test Report</div>',
    footerTemplate: '<div style="width:100%;font-size:7px;color:#7b8794;padding:0 12mm;display:flex;justify-content:space-between"><span>Confidential QA assessment</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
    margin: { top: "17mm", right: "12mm", bottom: "18mm", left: "12mm" },
  });
} finally {
  await browser.close();
}

console.log(`Created test_report.pdf (${report.total} cases, ${report.passed} passed, ${report.failed} failed)`);
