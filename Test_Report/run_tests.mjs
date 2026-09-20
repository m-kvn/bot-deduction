import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium } from "../bot-signal/node_modules/patchright/index.mjs";

const reportDir = new URL("./", import.meta.url);
const repoDir = new URL("../bot-signal/", import.meta.url);
const serverPath = new URL("../bot-signal/examples/form-demo/server.mjs", import.meta.url);
const crosscheckPath = new URL("../bot-signal/examples/form-demo/crosscheck.mjs", import.meta.url);
const port = 8877;
const base = `http://127.0.0.1:${port}`;
const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const results = [];
const browserErrors = [];
let sequence = 0;

await mkdir(reportDir, { recursive: true });

function add({ category, name, vector, expected, actual, passed, evidence = "", severity = "" }) {
  sequence += 1;
  results.push({
    id: `TC-${String(sequence).padStart(3, "0")}`,
    category,
    name,
    vector,
    expected,
    actual,
    passed: Boolean(passed),
    evidence,
    severity: passed ? "" : severity || "High",
  });
}

function runProcess(executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, options);
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => (stdout += chunk));
    child.stderr?.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

async function waitForServer() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/api/submissions`);
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("Isolated test server did not start");
}

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const browserHeaders = {
  "content-type": "application/json",
  "user-agent": UA,
  "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Chromium";v="140", "Google Chrome";v="140", "Not=A?Brand";v="24"',
  "sec-ch-ua-platform": '"Windows"',
  "sec-ch-ua-mobile": "?0",
  "sec-fetch-site": "same-origin",
  "sec-fetch-mode": "cors",
  "sec-fetch-dest": "empty",
};

function cleanInstant(overrides = {}) {
  return {
    suspicionScore: 0,
    isLegitClient: true,
    confidence: "high",
    automation: {
      isAutomated: false,
      kind: "unknown",
      confidence: "low",
      evidence: [],
      alternatives: [],
    },
    signals: [],
    ...overrides,
  };
}

function cleanBehavioral(overrides = {}) {
  return {
    suspicionScore: 0,
    isLegitClient: true,
    confidence: "medium",
    sampleCounts: {
      mouseMoves: 80,
      scrolls: 3,
      keyPresses: 30,
      clicks: 2,
      touches: 0,
      syntheticEvents: 0,
    },
    observationMs: 15_000,
    signals: [],
    ...overrides,
  };
}

function cleanInteraction(overrides = {}) {
  return {
    observationMs: 15_000,
    trustedBeforeInputEvents: 30,
    trustedInputEvents: 30,
    trustedChangeEvents: 2,
    trustedFocusEvents: 4,
    editedFields: ["name", "email", "company", "message"],
    submitEventTrusted: true,
    submitIntentTrusted: true,
    submitIntentType: "pointer",
    submitIntentAgeMs: 50,
    untrustedFormEvents: 0,
    ...overrides,
  };
}

function cleanClient(overrides = {}) {
  return {
    instant: cleanInstant(),
    behavioral: cleanBehavioral(),
    userAgent: UA,
    timezone: "Asia/Calcutta",
    language: "en-US",
    languages: ["en-US", "en"],
    platform: "Win32",
    ...overrides,
  };
}

async function apiSubmit(payload, headers = browserHeaders) {
  const response = await fetch(`${base}/api/submit`, {
    method: "POST",
    headers,
    body: typeof payload === "string" ? payload : JSON.stringify(payload),
  });
  let data;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  return { status: response.status, data };
}

async function runCrosscheck() {
  const run = await runProcess(process.execPath, [crosscheckPath.pathname.slice(1)], {
    cwd: repoDir.pathname.slice(1),
    env: { ...process.env, PORT: "8900" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines = run.stdout.split(/\r?\n/);
  for (const line of lines) {
    const match = line.match(/^(.+)\s+(human|agent)\s+(human|agent)\s+([0-9.]+)\s+(PASS|FAIL)$/);
    if (!match) continue;
    const [, name, policyVerdict, verdict, score, state] = match;
    add({
      category: "Server detection",
      name: name.trim(),
      vector: "Codex direct-request harness with fabricated browser telemetry",
      expected: "AGENT",
      actual: `${verdict.toUpperCase()}, score ${score}`,
      passed: verdict === "agent",
      evidence: `Automated Codex origin; internal signal-policy expectation ${policyVerdict.toUpperCase()} ${state}`,
      severity: "High",
    });
  }
  return run;
}

async function expectVerdict({ category = "Browser detection", name, vector, expectedVerdict, response, evidence = "", severity = "High" }) {
  const actualVerdict = response?.data?.verdict ?? `HTTP ${response?.status ?? "no response"}`;
  const signals = response?.data?.signals?.map((signal) => `${signal.layer}:${signal.id}`).join(", ") || "none";
  add({
    category,
    name,
    vector,
    expected: expectedVerdict.toUpperCase(),
    actual: `${String(actualVerdict).toUpperCase()}${response?.data?.score != null ? `, score ${response.data.score}` : ""}`,
    passed: actualVerdict === expectedVerdict,
    evidence: evidence || `Signals: ${signals}`,
    severity,
  });
}

async function newPage(browser, options = {}) {
  const context = await browser.newContext({
    viewport: options.viewport ?? { width: 1200, height: 760 },
    screen: options.screen ?? { width: 1920, height: 1080 },
    userAgent: options.userAgent,
  });
  if (options.initScript) await context.addInitScript(options.initScript);
  const page = await context.newPage();
  page.on("pageerror", (error) => browserErrors.push(String(error)));
  await page.goto(`${base}/index.html`, { waitUntil: "load" });
  return { context, page };
}

async function assignValidValues(page, prefix) {
  await page.evaluate((value) => {
    document.querySelector('input[name="name"]').value = value;
    document.querySelector('input[name="email"]').value = `${value.toLowerCase().replace(/[^a-z0-9]+/g, ".")}@example.test`;
    document.querySelector('input[name="company"]').value = "Detection QA";
    document.querySelector('textarea[name="message"]').value = "Automated scenario test";
  }, prefix);
}

async function actionSubmission(page, action) {
  const responsePromise = page.waitForResponse(
    (response) => response.url().endsWith("/api/submit") && response.request().method() === "POST",
    { timeout: 12_000 },
  );
  await action();
  const response = await responsePromise;
  return { status: response.status(), data: await response.json() };
}

async function browserCase(browser, spec) {
  const { context, page } = await newPage(browser, spec.contextOptions);
  try {
    await assignValidValues(page, spec.name);
    if (spec.before) await spec.before(page);
    const response = await actionSubmission(page, () => spec.action(page));
    await expectVerdict({
      name: spec.name,
      vector: spec.vector,
      expectedVerdict: spec.expectedVerdict,
      response,
      evidence: `HTTP ${response.status}; signals: ${response.data.signals?.map((s) => `${s.layer}:${s.id}`).join(", ") || "none"}`,
      severity: spec.severity,
    });
    if (spec.screenshot) {
      await page.locator("#result h2").waitFor({ state: "visible" });
      await page.screenshot({ path: new URL(spec.screenshot, reportDir).pathname.slice(1), fullPage: true });
    }
    return response;
  } finally {
    await context.close();
  }
}

const crosscheck = await runCrosscheck();
if (crosscheck.code !== 0 || results.filter((item) => item.category === "Server detection").length !== 30) {
  add({
    category: "Server detection",
    name: "Server cross-check harness completes",
    vector: "crosscheck.mjs",
    expected: "30 parsed cases, exit 0",
    actual: `${results.filter((item) => item.category === "Server detection").length} parsed, exit ${crosscheck.code}`,
    passed: false,
    evidence: crosscheck.stderr || crosscheck.stdout,
    severity: "Critical",
  });
}

const server = spawn(process.execPath, [serverPath.pathname.slice(1)], {
  cwd: repoDir.pathname.slice(1),
  env: { ...process.env, PORT: String(port), DB_FILE: ":memory:" },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stdout.on("data", (chunk) => (serverLog += chunk));
server.stderr.on("data", (chunk) => (serverLog += chunk));

let headed;
let headless;
try {
  await waitForServer();

  const liveResponse = await fetch("http://localhost:8787/index.html");
  const liveHtml = await liveResponse.text();
  add({
    category: "Live smoke",
    name: "Requested localhost application is reachable",
    vector: "GET http://localhost:8787/index.html",
    expected: "HTTP 200 with contact form",
    actual: `HTTP ${liveResponse.status}`,
    passed: liveResponse.status === 200 && liveHtml.includes('id="contact-form"'),
    evidence: "Non-destructive smoke test against the exact user-supplied URL",
  });

  const index = await fetch(`${base}/index.html`);
  const indexHtml = await index.text();
  add({
    category: "Functional",
    name: "Contact page loads",
    vector: "GET /index.html",
    expected: "HTTP 200 with form and detection scripts",
    actual: `HTTP ${index.status}`,
    passed: index.status === 200 && indexHtml.includes('id="contact-form"') && indexHtml.includes("bot-signal.global.js"),
    evidence: `${indexHtml.length} response characters`,
  });

  const dashboard = await fetch(`${base}/dashboard.html`);
  const dashboardHtml = await dashboard.text();
  add({
    category: "Functional",
    name: "Dashboard page loads",
    vector: "GET /dashboard.html",
    expected: "HTTP 200 with submissions table",
    actual: `HTTP ${dashboard.status}`,
    passed: dashboard.status === 200 && dashboardHtml.includes('id="table"'),
    evidence: `${dashboardHtml.length} response characters`,
  });

  const notFound = await fetch(`${base}/does-not-exist`);
  add({
    category: "HTTP handling",
    name: "Unknown route returns 404",
    vector: "GET /does-not-exist",
    expected: "HTTP 404",
    actual: `HTTP ${notFound.status}`,
    passed: notFound.status === 404,
  });

  const wrongMethod = await fetch(`${base}/index.html`, { method: "PUT" });
  add({
    category: "HTTP handling",
    name: "Unsupported method rejected",
    vector: "PUT /index.html",
    expected: "HTTP 405",
    actual: `HTTP ${wrongMethod.status}`,
    passed: wrongMethod.status === 405,
  });

  const invalidJson = await apiSubmit("{not valid JSON", { "content-type": "application/json" });
  add({
    category: "HTTP handling",
    name: "Malformed JSON rejected",
    vector: "POST /api/submit",
    expected: "HTTP 400 and clear error",
    actual: `HTTP ${invalidJson.status}: ${invalidJson.data?.error}`,
    passed: invalidJson.status === 400 && invalidJson.data?.error === "invalid JSON body",
  });

  const noClient = await apiSubmit(
    { form: { name: "Direct request", email: "direct@example.test" } },
    { "content-type": "application/json", "user-agent": "python-requests/2.32.3" },
  );
  await expectVerdict({
    category: "API bypass",
    name: "Direct POST with no client signals",
    vector: "Raw HTTP / requests client",
    expectedVerdict: "agent",
    response: noClient,
  });

  const forged = await apiSubmit({
    form: { name: "Forged both", email: "forged@example.test" },
    client: cleanClient(),
  });
  await expectVerdict({
    category: "API bypass",
    name: "Forged clean instant + behavioral objects",
    vector: "Direct POST with attacker-controlled client scores",
    expectedVerdict: "agent",
    response: forged,
    severity: "Critical",
  });

  const forgedChallenge = await fetch(`${base}/api/challenge`, { headers: browserHeaders });
  const forgedChallengeToken = (await forgedChallenge.json()).token;
  const fullyForged = await apiSubmit({
    form: { name: "Fully forged", email: "fully-forged@example.test" },
    challengeToken: forgedChallengeToken,
    client: cleanClient({ interaction: cleanInteraction() }),
  });
  await expectVerdict({
    category: "API bypass",
    name: "Valid challenge plus fully forged browser telemetry",
    vector: "Direct client omits browser Origin/Referer while fabricating client evidence",
    expectedVerdict: "agent",
    response: fullyForged,
    severity: "Critical",
  });

  const forgedProvenanceHeaders = {
    ...browserHeaders,
    origin: base,
    referer: `${base}/index.html`,
  };
  const provenanceChallenge = await fetch(`${base}/api/challenge`, {
    headers: forgedProvenanceHeaders,
  });
  const provenanceChallengeToken = (await provenanceChallenge.json()).token;
  const fullyForgedWithProvenance = await apiSubmit(
    {
      form: { name: "Fully forged provenance", email: "forged-provenance@example.test" },
      challengeToken: provenanceChallengeToken,
      client: cleanClient({ interaction: cleanInteraction() }),
    },
    forgedProvenanceHeaders,
  );
  await expectVerdict({
    category: "API bypass",
    name: "Fully forged telemetry plus browser provenance headers",
    vector: "Direct client also spoofs same-origin Origin and Referer",
    expectedVerdict: "agent",
    response: fullyForgedWithProvenance,
    severity: "Critical",
  });

  const instantOnly = await apiSubmit({
    form: { name: "Instant only", email: "instant@example.test" },
    client: cleanClient({ behavioral: undefined }),
  });
  await expectVerdict({
    category: "API bypass",
    name: "Only a forged clean instant layer",
    vector: "Omit behavioral result",
    expectedVerdict: "agent",
    response: instantOnly,
    severity: "Critical",
  });

  const behavioralOnlyClient = cleanClient();
  delete behavioralOnlyClient.instant;
  const behavioralOnly = await apiSubmit({
    form: { name: "Behavior only", email: "behavior@example.test" },
    client: behavioralOnlyClient,
  });
  await expectVerdict({
    category: "API bypass",
    name: "Only a forged clean behavioral layer",
    vector: "Omit instant result",
    expectedVerdict: "agent",
    response: behavioralOnly,
    severity: "Critical",
  });

  const negativeInstant = await apiSubmit({
    form: { name: "Bad instant", email: "instant-bad@example.test" },
    client: cleanClient({
      instant: cleanInstant({
        suspicionScore: 0.9,
        isLegitClient: false,
        signals: [
          {
            id: "isHeadless",
            description: "Headless browser",
            triggered: true,
            weight: 0.9,
            confidence: "high",
            score: 0.9,
          },
        ],
      }),
    }),
  });
  await expectVerdict({
    category: "API bypass",
    name: "Forwarded negative instant result enforced",
    vector: "Direct POST",
    expectedVerdict: "agent",
    response: negativeInstant,
  });

  const negativeBehavior = await apiSubmit({
    form: { name: "Bad behavior", email: "behavior-bad@example.test" },
    client: cleanClient({
      behavioral: cleanBehavioral({
        suspicionScore: 0.8,
        isLegitClient: false,
        signals: [
          {
            id: "synthetic-events",
            description: "Synthetic events",
            triggered: true,
            weight: 0.5,
            confidence: "high",
            score: 0.5,
          },
        ],
      }),
    }),
  });
  await expectVerdict({
    category: "API bypass",
    name: "Forwarded negative behavioral result enforced",
    vector: "Direct POST",
    expectedVerdict: "agent",
    response: negativeBehavior,
  });

  const curlSpoof = await apiSubmit(
    {
      form: { name: "Curl spoof", email: "curl@example.test" },
      client: cleanClient({ userAgent: "curl/8.5.0" }),
    },
    { ...browserHeaders, "user-agent": "curl/8.5.0" },
  );
  await expectVerdict({
    category: "API bypass",
    name: "Known curl User-Agent with forged clean layers",
    vector: "curl-style direct request",
    expectedVerdict: "agent",
    response: curlSpoof,
  });

  const mismatchedUa = await apiSubmit({
    form: { name: "UA mismatch", email: "ua@example.test" },
    client: cleanClient({ userAgent: UA.replace("Chrome/140", "Chrome/120") }),
  });
  await expectVerdict({
    category: "API bypass",
    name: "HTTP User-Agent versus browser User-Agent mismatch",
    vector: "Contradictory headers and client object",
    expectedVerdict: "agent",
    response: mismatchedUa,
  });

  const longName = `LONG-${"x".repeat(700)}`;
  await apiSubmit({
    form: { name: longName, email: "long@example.test", extra: "must-not-persist" },
    client: cleanClient(),
  });
  const afterLong = await (await fetch(`${base}/api/submissions`)).json();
  const longRecord = afterLong.submissions.find((item) => item.form.email === "long@example.test");
  add({
    category: "Data handling",
    name: "Form fields are length-limited and allow-listed",
    vector: "700-character field plus unknown key",
    expected: "Name stored at 500 chars; extra key discarded",
    actual: `Name ${longRecord?.form?.name?.length ?? "missing"} chars; extra ${Object.hasOwn(longRecord?.form ?? {}, "extra") ? "stored" : "discarded"}`,
    passed: longRecord?.form?.name?.length === 500 && !Object.hasOwn(longRecord?.form ?? {}, "extra"),
    evidence: "GET /api/submissions record inspection",
  });

  headed = await chromium.launch({
    headless: false,
    executablePath: chromePath,
    args: ["--window-position=80,80", "--window-size=1280,900", "--disable-background-timer-throttling"],
  });

  {
    const { context, page } = await newPage(headed);
    try {
      let submits = 0;
      page.on("request", (request) => {
        if (request.url().endsWith("/api/submit")) submits += 1;
      });
      await page.locator('button[type="submit"]').click();
      await page.waitForTimeout(500);
      const nameInvalid = await page.locator('input[name="name"]').evaluate((node) => !node.validity.valid);
      add({
        category: "Form validation",
        name: "Required fields block empty submission",
        vector: "Native Chrome button click",
        expected: "No API request; name invalid",
        actual: `${submits} API requests; name invalid=${nameInvalid}`,
        passed: submits === 0 && nameInvalid,
      });
    } finally {
      await context.close();
    }
  }

  {
    const { context, page } = await newPage(headed);
    try {
      let submits = 0;
      page.on("request", (request) => {
        if (request.url().endsWith("/api/submit")) submits += 1;
      });
      await page.locator('input[name="name"]').fill("Email validation");
      await page.locator('input[name="email"]').fill("not-an-email");
      await page.locator('button[type="submit"]').click();
      await page.waitForTimeout(500);
      const emailInvalid = await page.locator('input[name="email"]').evaluate((node) => !node.validity.valid);
      add({
        category: "Form validation",
        name: "Invalid email blocks submission",
        vector: "Native Chrome constraint validation",
        expected: "No API request; email invalid",
        actual: `${submits} API requests; email invalid=${emailInvalid}`,
        passed: submits === 0 && emailInvalid,
      });
    } finally {
      await context.close();
    }
  }

  {
    const { context, page } = await newPage(headed);
    try {
      const name = "Human Like Control";
      await page.locator('input[name="name"]').click();
      for (let i = 0; i < name.length; i += 1) {
        await page.keyboard.type(name[i], { delay: [73, 118, 91, 147, 84][i % 5] });
      }
      await page.locator('input[name="email"]').click();
      const email = "human.control@example.test";
      for (let i = 0; i < email.length; i += 1) {
        await page.keyboard.type(email[i], { delay: [64, 103, 132, 88][i % 4] });
      }
      const button = await page.locator('button[type="submit"]').boundingBox();
      const points = [
        [220, 180], [270, 205], [330, 250], [390, 310], [470, 360], [560, 430],
        [650, 480], [button.x + button.width / 2 - 70, button.y - 35],
        [button.x + button.width / 2, button.y + button.height / 2],
      ];
      for (const [x, y] of points) {
        await page.mouse.move(x, y, { steps: 3 });
        await page.waitForTimeout(31 + (x % 37));
      }
      const response = await actionSubmission(page, () => page.mouse.click(button.x + button.width / 2, button.y + button.height / 2));
      await expectVerdict({
        name: "Human-like automated Patchright session",
        vector: "Codex/Patchright curved pointer path, varied typing cadence, CDP click",
        expectedVerdict: "agent",
        response,
        evidence: `HTTP ${response.status}; browser chips: ${await page.locator("#live").innerText()}`,
        severity: "High",
      });
      await page.locator("#result h2").waitFor({ state: "visible" });
      await page.screenshot({ path: new URL("human_control.png", reportDir).pathname.slice(1), fullPage: true });
    } finally {
      await context.close();
    }
  }

  await browserCase(headed, {
    name: "HTMLElement.click() without pointer movement",
    vector: "JavaScript button.click()",
    expectedVerdict: "agent",
    action: (page) => page.evaluate(() => document.querySelector('button[type="submit"]').click()),
    screenshot: "synthetic_click_detected.png",
  });

  await browserCase(headed, {
    name: "dispatchEvent(new MouseEvent('click'))",
    vector: "DOM dispatchEvent click",
    expectedVerdict: "agent",
    action: (page) =>
      page.evaluate(() =>
        document
          .querySelector('button[type="submit"]')
          .dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, clientX: 400, clientY: 400 })),
      ),
  });

  await browserCase(headed, {
    name: "HTMLElement.click() after trusted mouse movement",
    vector: "Trusted move immediately followed by synthetic click",
    expectedVerdict: "agent",
    before: async (page) => {
      await page.mouse.move(250, 250);
      await page.mouse.move(300, 300);
    },
    action: (page) => page.evaluate(() => document.querySelector('button[type="submit"]').click()),
    severity: "High",
  });

  await browserCase(headed, {
    name: "dispatchEvent click after trusted mouse movement",
    vector: "Trusted move masks click-without-movement heuristic",
    expectedVerdict: "agent",
    before: async (page) => {
      await page.mouse.move(260, 260);
      await page.mouse.move(310, 310);
    },
    action: (page) =>
      page.evaluate(() =>
        document
          .querySelector('button[type="submit"]')
          .dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, clientX: 310, clientY: 310 })),
      ),
    severity: "High",
  });

  await browserCase(headed, {
    name: "form.requestSubmit()",
    vector: "DOM requestSubmit without pointer/keyboard event",
    expectedVerdict: "agent",
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
    severity: "Critical",
  });

  await browserCase(headed, {
    name: "dispatchEvent(new Event('submit'))",
    vector: "Synthetic submit event not monitored by behavioral layer",
    expectedVerdict: "agent",
    action: (page) =>
      page.evaluate(() => document.querySelector("form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))),
    severity: "Critical",
  });

  await browserCase(headed, {
    name: "Enter-key form submission",
    vector: "Single trusted keyboard event after DOM value assignment",
    expectedVerdict: "agent",
    action: (page) => page.locator('input[name="email"]').press("Enter"),
    severity: "High",
  });

  await browserCase(headed, {
    name: "Synthetic rapid key sequence",
    vector: "Six untrusted keydown events then requestSubmit",
    expectedVerdict: "agent",
    before: (page) =>
      page.evaluate(() => {
        for (let index = 0; index < 6; index += 1) {
          window.dispatchEvent(new KeyboardEvent("keydown", { key: "a", bubbles: true }));
        }
      }),
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  await browserCase(headed, {
    name: "Synthetic linear mouse path",
    vector: "Fourteen uniform untrusted mousemove events",
    expectedVerdict: "agent",
    before: (page) =>
      page.evaluate(async () => {
        for (let index = 0; index < 16; index += 1) {
          window.dispatchEvent(
            new MouseEvent("mousemove", {
              bubbles: true,
              clientX: 100 + index * 10,
              clientY: 100 + index * 10,
              movementX: 10,
              movementY: 10,
            }),
          );
          await new Promise((resolve) => setTimeout(resolve, 12));
        }
      }),
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  await browserCase(headed, {
    name: "Synthetic uniform scrolling",
    vector: "Eight equal untrusted wheel events at equal cadence",
    expectedVerdict: "agent",
    before: (page) =>
      page.evaluate(async () => {
        for (let index = 0; index < 8; index += 1) {
          window.dispatchEvent(new WheelEvent("wheel", { bubbles: true, deltaY: 100 }));
          await new Promise((resolve) => setTimeout(resolve, 15));
        }
      }),
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  await browserCase(headed, {
    name: "Synthetic teleporting pointer",
    vector: "Untrusted >600px mouse jump",
    expectedVerdict: "agent",
    before: (page) =>
      page.evaluate(() => {
        window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 5, clientY: 5 }));
        window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 900, clientY: 700 }));
      }),
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  await browserCase(headed, {
    name: "Synthetic linear touch gesture",
    vector: "Untrusted touchstart/touchmove sequence",
    expectedVerdict: "agent",
    before: (page) =>
      page.evaluate(async () => {
        const send = (kind, x, y) => {
          const event = new Event(kind, { bubbles: true, cancelable: true });
          Object.defineProperty(event, "touches", { value: [{ clientX: x, clientY: y }] });
          Object.defineProperty(event, "changedTouches", { value: [{ clientX: x, clientY: y }] });
          window.dispatchEvent(event);
        };
        send("touchstart", 100, 100);
        for (let index = 1; index <= 15; index += 1) {
          send("touchmove", 100 + index * 8, 100 + index * 8);
          await new Promise((resolve) => setTimeout(resolve, 12));
        }
      }),
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  for (const marker of [
    {
      name: "navigator.webdriver marker",
      vector: "WebDriver fingerprint",
      script: () => Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: () => true }),
    },
    {
      name: "Playwright global marker",
      vector: "window.__playwright artifact",
      script: () => Object.defineProperty(window, "__playwright", { value: {} }),
    },
    {
      name: "Puppeteer global marker",
      vector: "window.__puppeteer_evaluation_script__ artifact",
      script: () => Object.defineProperty(window, "__puppeteer_evaluation_script__", { value: {} }),
    },
    {
      name: "Selenium global marker",
      vector: "window._selenium artifact",
      script: () => Object.defineProperty(window, "_selenium", { value: {} }),
    },
    {
      name: "DOM automation controller marker",
      vector: "window.domAutomationController artifact",
      script: () => Object.defineProperty(window, "domAutomationController", { value: {} }),
    },
  ]) {
    await browserCase(headed, {
      name: marker.name,
      vector: marker.vector,
      expectedVerdict: "agent",
      contextOptions: { initScript: marker.script },
      action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
    });
  }

  await browserCase(headed, {
    name: "Implausibly small screen",
    vector: "120×160 viewport and screen",
    expectedVerdict: "agent",
    contextOptions: { viewport: { width: 120, height: 160 }, screen: { width: 120, height: 160 } },
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  await browserCase(headed, {
    name: "Tampered navigator.languages getter",
    vector: "navigator.languages emptied with a patched native getter",
    expectedVerdict: "agent",
    contextOptions: {
      initScript: () => Object.defineProperty(Navigator.prototype, "languages", { configurable: true, get: () => [] }),
    },
    action: (page) => page.evaluate(() => document.querySelector("form").requestSubmit()),
  });

  {
    const { context, page } = await newPage(headed);
    try {
      const response = await page.evaluate(async (client) => {
        client.userAgent = navigator.userAgent;
        client.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        client.language = navigator.language;
        client.languages = Array.from(navigator.languages ?? []);
        client.platform = navigator.platform;
        const request = await fetch("/api/submit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            form: { name: "In-page forged fetch", email: "in-page@example.test" },
            client,
          }),
        });
        return { status: request.status, data: await request.json() };
      }, cleanClient());
      await expectVerdict({
        category: "API bypass",
        name: "In-page fetch with forged clean client scores",
        vector: "JavaScript fetch() using genuine browser headers",
        expectedVerdict: "agent",
        response,
        severity: "Critical",
      });
    } finally {
      await context.close();
    }
  }

  {
    const { context, page } = await newPage(headed);
    try {
      await assignValidValues(page, "Native submit bypass");
      let postedUrl = null;
      page.on("request", (request) => {
        if (request.method() === "POST") postedUrl = request.url();
      });
      const before = await (await fetch(`${base}/api/submissions`)).json();
      await page.evaluate(() => HTMLFormElement.prototype.submit.call(document.querySelector("form")));
      await page.waitForTimeout(1_000);
      const after = await (await fetch(`${base}/api/submissions`)).json();
      add({
        category: "Submission methods",
        name: "HTMLFormElement.prototype.submit()",
        vector: "Native submit bypasses app submit listener",
        expected: "Not accepted by /api/submit",
        actual: `${postedUrl ? `POST ${new URL(postedUrl).pathname}` : "No observed POST"}; records ${before.total} → ${after.total}`,
        passed: !postedUrl?.endsWith("/api/submit") && before.total === after.total,
        evidence: "Default form action does not create an API submission",
      });
    } finally {
      await context.close();
    }
  }

  headless = await chromium.launch({ headless: true });
  await browserCase(headless, {
    name: "Standard headless Patchright browser",
    vector: "Headless browser + automated fill/click",
    expectedVerdict: "agent",
    before: async (page) => {
      await page.locator('input[name="name"]').fill("Headless Patchright");
      await page.locator('input[name="email"]').fill("headless@example.test");
    },
    action: (page) => page.locator('button[type="submit"]').click(),
    screenshot: "headless_detected.png",
  });

  {
    const { context, page } = await newPage(headed);
    try {
      await page.goto(`${base}/dashboard.html`, { waitUntil: "load" });
      await page.waitForFunction(() => Number(document.querySelector("#stat-total")?.textContent) > 0);
      const api = await (await fetch(`${base}/api/submissions`)).json();
      const ui = await page.evaluate(() => ({
        total: Number(document.querySelector("#stat-total").textContent),
        humans: Number(document.querySelector("#stat-humans").textContent),
        agents: Number(document.querySelector("#stat-agents").textContent),
        rows: document.querySelectorAll("#rows tr").length,
      }));
      add({
        category: "Dashboard",
        name: "Dashboard counts and rows match API",
        vector: "Rendered dashboard versus GET /api/submissions",
        expected: `${api.total} total / ${api.humans} human / ${api.agents} agent`,
        actual: `${ui.total} total / ${ui.humans} human / ${ui.agents} agent; ${ui.rows} rows`,
        passed:
          ui.total === api.total &&
          ui.humans === api.humans &&
          ui.agents === api.agents &&
          ui.rows === api.submissions.length,
      });
      await page.screenshot({ path: new URL("dashboard.png", reportDir).pathname.slice(1), fullPage: true });
    } finally {
      await context.close();
    }
  }

  const xssPayload = '<img src=x onerror="window.__xssExecuted=true">';
  await apiSubmit({
    form: { name: xssPayload, email: "xss@example.test", message: "<script>window.__xssExecuted=true</script>" },
    client: cleanClient(),
  });
  {
    const { context, page } = await newPage(headed);
    try {
      await page.goto(`${base}/dashboard.html`, { waitUntil: "load" });
      await page.waitForFunction(() => document.querySelector("#rows")?.textContent.includes("xss@example.test"));
      const xss = await page.evaluate(() => ({
        executed: window.__xssExecuted === true,
        injectedImage: Boolean(document.querySelector('#rows img[src="x"]')),
        visibleText: document.querySelector("#rows").textContent.includes("<img src=x"),
      }));
      add({
        category: "Security / output encoding",
        name: "Stored form content is not executed on dashboard",
        vector: "Stored HTML event-handler and script payload",
        expected: "Payload rendered as text; no script/image execution",
        actual: `executed=${xss.executed}; injectedImage=${xss.injectedImage}; visibleText=${xss.visibleText}`,
        passed: !xss.executed && !xss.injectedImage && xss.visibleText,
        evidence: "Dashboard builds user-data cells with textContent",
      });
    } finally {
      await context.close();
    }
  }

  const unicodeName = "मानव 用户 👩🏽‍💻";
  await apiSubmit({
    form: { name: unicodeName, email: "unicode@example.test", company: "日本株式会社", message: "مرحبا" },
    client: cleanClient(),
  });
  const unicodeData = await (await fetch(`${base}/api/submissions`)).json();
  const unicodeRecord = unicodeData.submissions.find((item) => item.form.email === "unicode@example.test");
  add({
    category: "Data handling",
    name: "Unicode form data round-trips",
    vector: "Devanagari, CJK, emoji, Arabic",
    expected: "Exact UTF-8 values persisted",
    actual: unicodeRecord?.form?.name ?? "record missing",
    passed: unicodeRecord?.form?.name === unicodeName && unicodeRecord?.form?.company === "日本株式会社" && unicodeRecord?.form?.message === "مرحبا",
  });

  const reset = await fetch(`${base}/api/reset`, { method: "POST" });
  const resetBody = await reset.json();
  const empty = await (await fetch(`${base}/api/submissions`)).json();
  add({
    category: "Dashboard",
    name: "Clear/reset removes isolated submissions",
    vector: "POST /api/reset",
    expected: "HTTP 200, ok=true, zero records",
    actual: `HTTP ${reset.status}, ok=${resetBody.ok}, total=${empty.total}`,
    passed: reset.status === 200 && resetBody.ok === true && empty.total === 0,
    evidence: "Executed only against the in-memory test server",
  });
} catch (error) {
  add({
    category: "Harness",
    name: "Unexpected test-runner error",
    vector: "End-to-end execution",
    expected: "No harness error",
    actual: String(error?.stack || error),
    passed: false,
    evidence: serverLog,
    severity: "Critical",
  });
} finally {
  await headless?.close().catch(() => {});
  await headed?.close().catch(() => {});
  server.kill();
}

const summary = {
  generatedAt: new Date().toISOString(),
  target: "http://localhost:8787/index.html",
  isolatedTarget: base,
  browser: "Google Chrome via Patchright (headful) plus Patchright Chromium (headless)",
  scope: "Functional, DOM, synthetic events, browser fingerprint, direct API, server headers/IP/TLS, dashboard",
  total: results.length,
  passed: results.filter((item) => item.passed).length,
  failed: results.filter((item) => !item.passed).length,
  browserErrors,
  results,
  crosscheckOutput: crosscheck.stdout,
};

await writeFile(new URL("results.json", reportDir), JSON.stringify(summary, null, 2));
console.log(JSON.stringify({ total: summary.total, passed: summary.passed, failed: summary.failed }, null, 2));
for (const item of results.filter((result) => !result.passed)) {
  console.log(`FAIL ${item.id}: ${item.name} — expected ${item.expected}; actual ${item.actual}`);
}
