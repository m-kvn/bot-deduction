import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const here = fileURLToPath(new URL(".", import.meta.url));
const serverPath = join(here, "server.mjs");

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const SEC_CH_UA = '"Chromium";v="140", "Google Chrome";v="140", "Not=A?Brand";v="24"';
const DEMO_JA3 = "cd08e31494f9531f560d64c695473da9";
const DEMO_JA4 = "t13d1516h2_8daaf6152771_b186095e22b6";

// Plain `suspiciousTlsFingerprints` strings only ever raise `known-suspicious-tls`;
// `tls-user-agent-mismatch` needs family-labelled entries, so the demo server takes both.
const DEMO_TLS_ENTRIES = JSON.stringify([
  { id: "demo-curl-ja3", label: "curl (demo entry)", hash: DEMO_JA3, families: ["curl", "scripting"], confidence: "high" },
  { id: "demo-python-ja4", label: "python (demo entry)", fingerprintType: "ja4", hash: DEMO_JA4, families: ["python", "scripting"], confidence: "high" },
]);

function baseHeaders(extra = {}) {
  const headers = {
    "content-type": "application/json",
    "user-agent": UA,
    "accept-language": "en-US,en;q=0.9",
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    ...extra,
  };
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) delete headers[key];
  }
  return headers;
}

function cleanInstant(extra = {}) {
  return {
    suspicionScore: 0,
    isLegitClient: true,
    confidence: "high",
    automation: { isAutomated: false, kind: "unknown", confidence: "low", evidence: [], alternatives: [] },
    signals: [],
    ...extra,
  };
}

function cleanBehavioral(extra = {}) {
  return {
    suspicionScore: 0,
    isLegitClient: true,
    confidence: "medium",
    sampleCounts: { mouseMoves: 120, scrolls: 4, keyPresses: 40, clicks: 3, touches: 0, syntheticEvents: 0 },
    observationMs: 20_000,
    signals: [],
    ...extra,
  };
}

function cleanInteraction(extra = {}) {
  return {
    observationMs: 20_000,
    trustedBeforeInputEvents: 40,
    trustedInputEvents: 40,
    trustedChangeEvents: 2,
    trustedFocusEvents: 4,
    editedFields: ["name", "email", "company", "message"],
    submitEventTrusted: true,
    submitIntentTrusted: true,
    submitIntentType: "pointer",
    submitIntentAgeMs: 50,
    untrustedFormEvents: 0,
    ...extra,
  };
}

function baseClient(extra = {}) {
  return {
    userAgent: UA,
    timezone: "America/Los_Angeles",
    language: "en-US",
    languages: ["en-US", "en"],
    platform: "Win32",
    instant: cleanInstant(),
    behavioral: cleanBehavioral(),
    interaction: cleanInteraction(),
    ...extra,
  };
}

const CASES = [
  {
    name: "human baseline",
    expect: [],
    verdict: "human",
  },
  {
    name: "clean client layers without a page challenge",
    challenge: false,
    expect: ["client:invalid-challenge"],
    verdict: "agent",
  },
  {
    name: "one-time page challenge replayed",
    replayChallenge: true,
    expect: ["client:invalid-challenge"],
    verdict: "agent",
  },
  {
    name: "one browser detection layer omitted",
    client: baseClient({ behavioral: null }),
    expect: ["client:missing-client-layer"],
    verdict: "agent",
  },
  {
    name: "inconsistent browser result object",
    client: baseClient({
      instant: cleanInstant({ suspicionScore: 0.2 }),
    }),
    expect: ["client:invalid-client-layer"],
    verdict: "agent",
  },
  {
    name: "no trusted field interaction history",
    client: baseClient({ interaction: null }),
    expect: ["client:untrusted-form-interaction"],
    verdict: "agent",
  },
  {
    name: "scripting client, no page JS",
    headers: { "user-agent": "python-requests/2.32.3" },
    client: null,
    expect: ["client:missing-client-layer", "server:scripting-user-agent"],
    verdict: "agent",
  },
  {
    name: "declared bot User-Agent",
    headers: { "user-agent": "Googlebot/2.1 (+http://www.google.com/bot.html)" },
    client: baseClient({ userAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)" }),
    expect: ["server:bot-user-agent"],
    verdict: "agent",
  },
  {
    name: "header UA vs browser UA mismatch",
    client: baseClient({ userAgent: UA.replace("Chrome/140.0.0.0", "Chrome/122.0.0.0") }),
    expect: ["server:client-user-agent-mismatch"],
    verdict: "agent",
  },
  {
    name: "sec-ch-ua version mismatch",
    headers: { "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120", "Not=A?Brand";v="24"' },
    expect: ["server:client-hints-mismatch"],
    verdict: "agent",
  },
  {
    name: "platform mismatch",
    client: baseClient({ platform: "MacIntel" }),
    expect: ["server:client-platform-mismatch"],
    verdict: "agent",
  },
  {
    name: "sec-ch-ua-mobile mismatch",
    headers: { "sec-ch-ua-mobile": "?1" },
    expect: ["server:client-hints-mobile-mismatch"],
    verdict: "agent",
  },
  {
    name: "missing Fetch Metadata headers",
    headers: { "sec-fetch-site": undefined, "sec-fetch-mode": undefined, "sec-fetch-dest": undefined },
    expect: ["server:missing-browser-headers"],
    verdict: "human",
  },
  {
    name: "Accept-Language vs navigator.languages",
    client: baseClient({ language: "de-DE", languages: ["de-DE", "de"] }),
    expect: ["server:client-language-mismatch"],
    verdict: "human",
  },
  {
    name: "US visitor, GeoIP in another US timezone",
    headers: { "x-forwarded-for": "8.8.8.8" },  // GeoIP: US / America/Chicago
    client: baseClient({ timezone: "America/Los_Angeles" }),
    expect: [],
    verdict: "human",
  },
  {
    name: "US IP, traveller keeping an IST clock",
    headers: { "x-forwarded-for": "8.8.8.8" },  // GeoIP: US / America/Chicago
    client: baseClient({ timezone: "Asia/Kolkata" }),
    expect: ["server:timezone-mismatch"],
    verdict: "human",
  },
  {
    name: "US IP, VPN user with a non-US locale",
    headers: { "x-forwarded-for": "8.8.8.8", "accept-language": "hi-IN,hi;q=0.9" },
    client: baseClient({ timezone: "Asia/Kolkata", language: "hi-IN", languages: ["hi-IN", "hi"] }),
    expect: ["server:timezone-mismatch", "server:accept-language-geo-mismatch"],
    verdict: "human",
  },
  {
    name: "advisory notes plus one real signal",
    headers: { "x-forwarded-for": "8.8.8.8", "sec-ch-ua-mobile": "?1" },
    client: baseClient({ timezone: "Asia/Kolkata" }),
    expect: ["server:timezone-mismatch", "server:client-hints-mobile-mismatch"],
    verdict: "agent",
  },
  {
    name: "Accept-Language vs GeoIP country",
    headers: { "x-forwarded-for": "8.8.8.8", "accept-language": "de-DE,de;q=0.9" },
    client: baseClient({ language: "de-DE", languages: ["de-DE", "de"], timezone: "America/Chicago" }),
    expect: ["server:accept-language-geo-mismatch"],
    verdict: "human",
  },
  {
    name: "datacenter IP with browser UA",
    headers: { "x-forwarded-for": "3.0.0.1", "accept-language": "en-SG,en;q=0.9" },
    client: baseClient({ timezone: "Asia/Singapore", language: "en-SG", languages: ["en-SG", "en"] }),
    expect: ["server:datacenter-browser-mismatch"],
    verdict: "human",
  },
  {
    name: "AU human on a US corporate VPN (datacenter egress)",
    headers: { "x-forwarded-for": "3.16.0.1", "accept-language": "en-AU,en;q=0.9" },  // AWS us-east-2
    client: baseClient({ timezone: "Australia/Sydney", language: "en-AU", languages: ["en-AU", "en"] }),
    expect: [
      "server:datacenter-browser-mismatch",
      "server:timezone-mismatch",
      "server:accept-language-geo-mismatch",
    ],
    verdict: "human",
  },
  {
    name: "datacenter egress plus missing Fetch Metadata",
    headers: {
      "x-forwarded-for": "3.0.0.1",
      "accept-language": "en-SG,en;q=0.9",
      "sec-fetch-site": undefined,
      "sec-fetch-mode": undefined,
      "sec-fetch-dest": undefined,
    },
    client: baseClient({ timezone: "Asia/Singapore", language: "en-SG", languages: ["en-SG", "en"] }),
    expect: ["server:datacenter-browser-mismatch", "server:missing-browser-headers"],
    verdict: "agent",
  },
  {
    name: "AbuseIPDB listed IP",
    headers: { "x-forwarded-for": "1.0.164.165", "accept-language": "th-TH,th;q=0.9" },
    client: baseClient({ timezone: "Asia/Bangkok", language: "th-TH", languages: ["th-TH", "th"] }),
    expect: ["server:abuse-listed-ip"],
    verdict: "agent",
  },
  {
    name: "iCloud Private Relay egress IP",
    headers: { "x-forwarded-for": "172.224.226.1", "accept-language": "en-GB,en;q=0.9" },
    client: baseClient({ timezone: "Europe/London", language: "en-GB", languages: ["en-GB", "en"] }),
    expect: ["server:icloud-private-relay"],
    verdict: "human",
  },
  {
    name: "edge says crawler identity spoofed",
    headers: { "x-crawler-verification": "spoofed" },
    expect: ["server:crawler-identity-spoofed"],
    verdict: "agent",
  },
  {
    name: "suspicious JA3 from TLS terminator",
    headers: { "x-ja3-hash": DEMO_JA3 },
    expect: ["server:known-suspicious-tls", "server:tls-user-agent-mismatch"],
    verdict: "agent",
  },
  {
    name: "suspicious JA4 from TLS terminator",
    headers: { "x-ja4": DEMO_JA4 },
    expect: ["server:known-suspicious-tls", "server:tls-user-agent-mismatch"],
    verdict: "agent",
  },
  {
    name: "instant layer forwarded from the page",
    client: baseClient({
      instant: cleanInstant({
        suspicionScore: 0.9,
        isLegitClient: false,
        signals: [
          { id: "isHeadless", description: "Headless browser", triggered: true, weight: 0.9, confidence: "high", score: 0.9 },
        ],
        automation: { isAutomated: true, kind: "playwright", confidence: "high", evidence: ["headless"], alternatives: [] },
      }),
    }),
    expect: ["instant:isHeadless"],
    verdict: "agent",
  },
  {
    name: "behavioral layer forwarded from the page",
    client: baseClient({
      behavioral: cleanBehavioral({
        suspicionScore: 0.5,
        isLegitClient: false,
        signals: [
          { id: "synthetic-events", description: "Untrusted events", triggered: true, weight: 0.5, confidence: "high", score: 0.5 },
        ],
      }),
    }),
    expect: ["behavioral:synthetic-events"],
    verdict: "agent",
  },
  {
    name: "browser UA without a TLS fingerprint (REQUIRE_TLS=1)",
    env: { REQUIRE_TLS: "1" },
    expect: ["server:missing-tls-fingerprint"],
    verdict: "human",
  },
];

async function startServer(port, env) {
  const child = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      PORT: String(port),
      DB_FILE: ":memory:",
      TRUST_EDGE_HEADERS: "1",
      SUSPICIOUS_TLS: `${DEMO_JA3},${DEMO_JA4}`,
      SUSPICIOUS_TLS_ENTRIES: DEMO_TLS_ENTRIES,
      ...env,
    },
    stdio: "ignore",
  });

  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/submissions`);
      if (response.ok) return child;
    } catch {
      /* not listening yet */
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, 150));
  }

  child.kill();
  throw new Error(`server on ${port} did not start`);
}

async function runCase(port, testCase) {
  const client = testCase.client === null ? undefined : (testCase.client ?? baseClient());
  const headers = baseHeaders(testCase.headers);
  let challengeToken;
  if (client && testCase.challenge !== false) {
    const challengeResponse = await fetch(`http://127.0.0.1:${port}/api/challenge`, { headers });
    challengeToken = (await challengeResponse.json()).token;
  }
  const request = {
    method: "POST",
    headers,
    body: JSON.stringify({
      form: { name: testCase.name, email: "demo@example.com", company: "Demo", message: "crosscheck" },
      ...(challengeToken ? { challengeToken } : {}),
      ...(client ? { client } : {}),
    }),
  };
  if (testCase.replayChallenge) {
    await fetch(`http://127.0.0.1:${port}/api/submit`, request);
  }
  const response = await fetch(`http://127.0.0.1:${port}/api/submit`, request);

  const data = await response.json();
  const fired = data.signals.map((signal) => `${signal.layer}:${signal.id}`);
  const expectedVerdict = "agent";
  const requiredSignals = [
    ...testCase.expect,
    "client:invalid-request-provenance",
    "client:invalid-page-session",
  ];
  const missing = requiredSignals.filter((id) => !fired.includes(id));
  const extra = fired.filter((id) => !requiredSignals.includes(id));
  const verdictOk = data.verdict === expectedVerdict;

  return { fired, missing, extra, verdictOk, verdict: data.verdict, expectedVerdict, score: data.score };
}

const basePort = Number(process.env.PORT ?? 8899);
let port = basePort;
let server = await startServer(port, {});
let currentEnv = "";
let failures = 0;

console.log("case                                        expected actual   score  result");
console.log("-".repeat(105));

for (const testCase of CASES) {
  const envKey = JSON.stringify(testCase.env ?? {});
  if (envKey !== currentEnv) {
    server.kill();
    port += 1;
    server = await startServer(port, testCase.env ?? {});
    currentEnv = envKey;
  }

  const result = await runCase(port, testCase);
  const ok = result.missing.length === 0 && result.verdictOk;
  if (!ok) failures += 1;

  console.log(
    `${testCase.name.padEnd(43)} ${result.expectedVerdict.padEnd(8)} ${result.verdict.padEnd(8)} ${result.score.toFixed(2).padEnd(6)} ${ok ? "PASS" : "FAIL"}`,
  );
  if (result.missing.length) console.log(`    missing: ${result.missing.join(", ")}`);
  if (!result.verdictOk) console.log(`    expected verdict ${result.expectedVerdict}`);
  if (result.extra.length) console.log(`    also fired: ${result.extra.join(", ")}`);
}

server.kill();
console.log("-".repeat(96));
console.log(failures === 0 ? `All ${CASES.length} checks wired correctly.` : `${failures} of ${CASES.length} checks failed.`);
process.exit(failures === 0 ? 0 : 1);
