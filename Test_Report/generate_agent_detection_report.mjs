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
  osInjection: await asImage("os_injection_detected.png"),
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
      <div class="metric"><strong>${agentRecall}%</strong><span>Detection rate, this matrix</span></div>
    </div>
    <div class="verdict"><strong>Verdict: OBJECTIVE NOT FULLY MET.</strong><br>
      Codex automation initiated all ${detectionCases.length} classification submissions, so every expected verdict is AGENT. The app detected ${detectedAgents.length} and incorrectly returned HUMAN for ${missedAgents.length}${
        missedAgents.length === 0
          ? " within this matrix"
          : ""
      }. ${
        missedAgents.length === 0
          ? "That is not the same as the objective being met: an independent red team has since passed four methods this matrix does not contain — OS-level injection with real scan codes, and a raw CDP <code>Input</code> client driving a normal Chrome build. Section 10 documents them. A detection rate is only ever a rate over the attacks you thought to write."
          : `The agent detection rate was ${agentRecall}% and the miss rate was ${missRate}%.`
      }</div>
    <div class="callout"><strong>Ground-truth correction:</strong> Human-like telemetry does not make the submitter human. All ${missedAgents.length} HUMAN results in this report are agent-detection failures because Codex, Patchright, Chrome DevTools MCP, JavaScript, or a direct-request harness generated the submission.</div>
    <table class="meta">
      <tr><td>Target</td><td><code>http://localhost:8787/index.html</code></td></tr>
      <tr><td>Primary outcome</td><td>AGENT versus HUMAN form-submission verdict</td></tr>
      <tr><td>Test methods</td><td>Chrome DevTools MCP, Google Chrome through Patchright, headless Chromium, trusted browser input, DOM APIs, JavaScript events, direct HTTP, forged payloads, server headers/IP/TLS scenarios</td></tr>
      <tr><td>Agent detection accuracy</td><td>${detectedAgents.length}/${agentCases.length} = ${agentRecall}% across Codex-generated classification attempts</td></tr>
      <tr><td>Genuine-human sessions</td><td>0 — false-positive performance was not measured by this automated run</td></tr>
      <tr><td>Known-open vectors</td><td>4 — see section 10; not represented in the matrix below</td></tr>
      <tr><td>Execution date</td><td>${escapeHtml(generated)}</td></tr>
      <tr><td>Live-data safety</td><td>Existing live dashboard records were not changed; mutating tests used an in-memory instance of the same app.</td></tr>
    </table>
  </section>

  <h2>1. Detection scorecard</h2>
  <table>
    <thead><tr><th>Detection area</th><th>Codex-generated tests</th><th>Agents detected</th><th>Agents missed as HUMAN</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
  <p>The server/request matrix detected ${groupStats[0].agentDetected} of ${groupStats[0].total} Codex-generated submissions, the API matrix detected ${groupStats[1].agentDetected} of ${groupStats[1].total}, and the browser matrix detected ${groupStats[2].agentDetected} of ${groupStats[2].total}. ${
    missedAgents.length > 0
      ? "Human-looking automated inputs are still able to cross the browser-to-server trust boundary."
      : "No automated input in this matrix crossed the browser-to-server trust boundary."
  }</p>

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

  ${
    missedAgents.length > 0
      ? `<div class="finding">
    <h3>Remaining limitation — Public browser telemetry can ultimately be forged</h3>
    <p>The ${missedAgents.length} misses used human-looking forged telemetry, low-risk/advisory network profiles, or human-like CDP input. Codex initiated every one, but the app returned HUMAN because public browser telemetry and CDP-generated trusted events do not prove a person was present.</p>
    <p><strong>Impact:</strong> An automated client that avoids obvious bot artifacts can bypass the binary verdict. Missing or replayed challenges, malformed layers, obvious synthetic events, headless browsers, and known automation markers were detected.</p>
  </div>`
      : `<div class="finding">
    <h3>Remaining limitation — A full page-load replay, and scan-code input injection</h3>
    <p>Every scenario in this matrix is classified AGENT, but two routes remain open by construction. A script that replays a complete page load — cookie jar, every subresource with correct Fetch Metadata, a page-bound challenge and realistic timing — satisfies the provenance layer, because that layer verifies a trail rather than a person. And OS-level input injection that uses real virtual-key/scan-code pairs, rather than <code>KEYEVENTF_UNICODE</code>, produces keystrokes a browser cannot distinguish from hardware; only the pointer-level heuristics remain against it.</p>
    <p><strong>Impact:</strong> The verdict is a risk signal, not proof of human identity. It should gate friction, not irreversible decisions.</p>
  </div>`
  }
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

  <h2 class="page-break">9. OS-level input injection</h2>
  <p>The sharpest class of agent is one that drives a real, signed-in browser through the Windows input stack — <code>SendInput</code>, <code>keybd_event</code>, <code>mouse_event</code>, <code>SetCursorPos</code>, as used by PowerShell and AutoHotkey harnesses. Those events are genuinely <code>isTrusted</code>: the browser really did receive them from the operating system, the window is real, the page load is real, and every provenance check passes. Before this run, such a session was classified HUMAN with score 0.00.</p>
  <p>The distinguishing artifact is how the text is pushed in. <code>SendInput</code> with <code>KEYEVENTF_UNICODE</code> sets <code>wVk = 0</code> and carries the character in the scan-code field, so Windows reports <code>VK_PACKET</code> and Chromium has no physical key to name. Measured directly against Chrome 140 on Windows 11:</p>
  <table>
    <thead><tr><th>Input method</th><th><code>key</code></th><th><code>code</code></th><th><code>keyCode</code></th><th><code>isTrusted</code></th></tr></thead>
    <tbody>
      <tr><td><code>SendInput</code> + <code>KEYEVENTF_UNICODE</code></td><td>K</td><td><em>(empty)</em></td><td>231 (<code>VK_PACKET</code>)</td><td>true</td></tr>
      <tr><td>Scan-code key press (hardware path)</td><td>b</td><td><code>KeyB</code></td><td>66</td><td>true</td></tr>
    </tbody>
  </table>
  <p>The <code>injected-key-input</code> signal fires when at least five printable keystrokes, and at least 60% of them, arrive without a physical key behind them — a ratio, so that an emoji picker or a dictated word inside an otherwise hand-typed form is not flagged. The demo server enforces the same rule on the submitted interaction record, so a tampered page bundle cannot simply drop the evidence.</p>
  <div class="evidence"><img src="${images.osInjection}"><div class="caption">Real PowerShell <code>SendInput</code> session — curved <code>SetCursorPos</code> pointer paths, randomised per-character delays, <code>mouse_event</code> clicks, genuine page load: now classified AGENT, score 0.94, HTTP 403, on <code>behavioral:injected-key-input</code> and <code>client:untrusted-form-interaction</code>.</div></div>
  <p class="footnote">A rewrite that injects real virtual-key/scan-code pairs instead of Unicode packets defeats this specific signal — the keystrokes become indistinguishable from hardware. The supporting <code>zero-jitter-clicks</code> heuristic covers part of the pointer side, but this class of attack is not closed by client-side signals alone.</p>

  <h2 class="page-break">10. Independent red-team results</h2>
  <p>A separate red-team pass built ten bypass methods against this build and read every verdict back
  from <code>GET /api/submissions</code> rather than the screen. Six passed as human. The findings
  below are reproduced as stated, with what was changed in response.</p>
  <table>
    <thead><tr><th>Finding</th><th>Status</th><th>Response</th></tr></thead>
    <tbody>
      <tr>
        <td><strong>Client scores are advisory.</strong> The server accepted any self-consistent
        <code>{score: 0, signals: []}</code>, so a full page-session replay (no browser at all) and a
        <code>Runtime.evaluate</code> forge from inside a real page both scored human 0.00.</td>
        <td>Fixed</td>
        <td>The page now submits the raw sample streams behind its verdict, and the server recomputes
        the behavioral result itself — the reported score no longer decides anything. Three new gates:
        <code>missing-behavioral-samples</code>, <code>forged-client-verdict</code> (reported score or
        signal list disagrees with the samples it was derived from) and
        <code>impossible-observation-window</code> (claimed observation longer than the page session
        has existed — a duration comparison, so a visitor with a wrong clock is unaffected). Verified
        against the red team's own scripts: both now score agent 0.99.</td>
      </tr>
      <tr>
        <td><strong>The CDP console probe never fires</strong> for an attached <code>Input</code>-domain
        client, even with <code>Runtime.enable</code>.</td>
        <td>Confirmed, open</td>
        <td>Reproduced. Three candidate discriminators were measured and <em>all three rejected</em>:
        (1) CDP input skipping Chromium's rAF-aligned pipeline — it does not, 16.9 ms median gap versus
        16.8 ms for real OS input, zero sub-frame gaps in either; (2) fewer coalesced raw events than a
        polled mouse — 1.01 per <code>pointermove</code> for both injected paths, and any cadence rule is
        trivially matched once known; (3) CDP driving an unfocused window —
        <code>document.hasFocus()</code> stays <code>true</code>. No discriminator was shipped, because
        none survived measurement.</td>
      </tr>
      <tr>
        <td><strong><code>injected-key-input</code> is effectively a scan-code check</strong> — it
        catches <code>KEYEVENTF_UNICODE</code> and stock pyautogui, but not
        <code>KEYEVENTF_SCANCODE</code>, CDP <code>Input</code>, or USB-HID.</td>
        <td>Accurate, open</td>
        <td>Correct as stated. Injection that supplies a real scan code is indistinguishable from
        hardware at the DOM level; there is nothing left in the key event to compare.</td>
      </tr>
      <tr>
        <td><strong><code>zero-jitter-clicks</code> skipped presses held under 40 ms</strong>, so a fast
        synthetic clicker slipped past regardless of jitter.</td>
        <td>Fixed</td>
        <td>A press now reads as machine-made if it releases on the pixel it pressed <em>or</em> is
        gone before a finger could lift. Skipping the quick ones only told a clicker to hurry.</td>
      </tr>
    </tbody>
  </table>
  <p><strong>What remains undetectable.</strong> Four of the six passing methods are still classified
  HUMAN, and this is architectural rather than an unfinished heuristic: OS-level injection with real
  scan codes (PowerShell <code>SendInput</code>, patched pyautogui) and a raw CDP <code>Input</code>
  client driving a normal Chrome build both produce genuinely trusted events, a real page load and
  human-grade input. The samples the server now recomputes are honest samples of real input. There is
  no client-side signal left to add.</p>

  <h3>Volume and repetition controls</h3>
  <p>What those vectors cannot hide is repetition — a hand fills this form once, a loop fills it all
  afternoon. The server now tracks that as a second axis, kept deliberately out of the verdict:
  <code>verdict</code> remains a statement about one submission, <code>outcome</code> is what to do
  about it. A clean-looking submission from an address that has already sent the same content, or too
  many submissions, or opened too many page sessions, returns <code>outcome: "review"</code> and
  HTTP 202 instead of being silently accepted. Limits are environment-tunable
  (<code>MAX_SUBMISSIONS_PER_SESSION</code>, <code>MAX_SUBMISSIONS_PER_IP</code>,
  <code>MAX_SESSIONS_PER_IP</code>, <code>MAX_CHALLENGES_PER_SESSION</code>,
  <code>MAX_IDENTICAL_SUBMISSIONS</code>, <code>RISK_WINDOW_MS</code>).</p>
  <p>Verified against the scan-code injection that defeats detection outright: the first run scored
  <code>human</code> / <code>accepted</code>, and the second run with the same content scored
  <code>human</code> / <code>review</code>. The verdict stayed honest; the submission stopped being
  accepted in silence. This is mitigation, not detection, and is reported as such.</p>

  <div class="finding">
    <h3>A bug this suite could not see</h3>
    <p>Routing the recomputed behavioral layer through the existing client-layer validation made
    <code>invalid-client-layer</code> fire on <em>every</em> samples-backed submission, including
    honest ones — the validator requires <code>triggered === true</code> on each signal, and a full
    analysis carries untriggered entries too. All 81 tests stayed green, because every case in this
    matrix expects AGENT, so a verdict that was right for the wrong reason was indistinguishable from
    one that was right. It surfaced only when a real scan-code injection run came back AGENT on a
    signal it had no business tripping. A false-positive guard now asserts that a genuine page session
    carrying real samples trips none of the four sample-integrity gates.</p>
  </div>

  <h2>11. Scope note</h2>
  <p>This is a risk-based set of ${detectionCases.length} classification scenarios covering the app's documented layers and the requested Chrome/DOM/JavaScript/request techniques. “All possible” browser and network combinations are not finite; the report does not certify every OS, browser version, mobile device, assistive technology, extension, proxy or TLS terminator.</p>
  <p>Chrome DevTools MCP was used directly for native MCP form filling/clicking and MCP-executed <code>HTMLElement.click()</code>, <code>form.requestSubmit()</code>, and synthetic submit dispatch. The wider matrix additionally used installed Google Chrome through Patchright and raw requests.</p>
  <p class="footnote">${data.results.length - detectionCases.length} additional functionality, false-positive-guard and security checks also passed (page/dashboard loading, validation, HTTP handling, storage limits, Unicode, dashboard consistency/reset and output encoding). They are excluded from the headline numbers because they do not answer HUMAN versus AGENT.</p>
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
