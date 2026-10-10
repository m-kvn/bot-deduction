import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
  createBotProtection,
  createUpstashRateLimitStore,
  detectServerClientAsync,
  getTlsClientHello,
  isPublicIp,
  preloadIpLists,
  resolveClientIp,
  trackTlsClientHellos,
} from "../../dist/server.js";
import { analyzeBehavioralSamples } from "../../dist/index.js";
import {
  AGGREGATE_BEHAVIORAL_THRESHOLD,
  AGGREGATE_SCORE_THRESHOLD,
  BEHAVIORAL_SCORE_THRESHOLD,
  INSTANT_SCORE_THRESHOLD,
  MIN_CORROBORATING_LAYERS,
  combineScores,
  decideVerdict,
  hasHardEvidence,
} from "./verdict.mjs";
import {
  clearSubmissions,
  closeDatabase,
  countByVerdict,
  dbFile,
  getSubmission,
  insertSubmission,
  labeledSubmissions,
  listSubmissions,
  updateSubmission,
} from "./db.mjs";

const configErrors = [];

function numberSetting(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER, integer = false } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) {
    configErrors.push(`${name}=${JSON.stringify(raw)} must be ${integer ? "an integer" : "a number"} from ${min} to ${max}`);
    return fallback;
  }
  return value;
}

function choiceSetting(name, fallback, choices) {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  if (!choices.includes(raw.trim())) {
    configErrors.push(`${name}=${JSON.stringify(raw)} must be one of: ${choices.join(", ")}`);
    return fallback;
  }
  return raw.trim();
}

function listSetting(name, fallback = "") {
  return (process.env[name] ?? fallback)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

const here = fileURLToPath(new URL(".", import.meta.url));
const publicDir = join(here, "public");
const globalBuild = join(here, "..", "..", "dist", "browser.global.js");
const PORT = numberSetting("PORT", 8787, { integer: true, max: 65_535 });
const HOST = process.env.HOST ?? "127.0.0.1";
const LIST_LIMIT = 200;
const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_ACTIVE_CHALLENGES = 10_000;
const MIN_INTERACTION_OBSERVATION_MS = 500;
const MAX_SUBMIT_INTENT_AGE_MS = 5_000;
const MIN_INJECTED_KEY_EVENTS = 5;
const INJECTED_KEY_EVENT_RATIO = 0.6;

// Enough inserted text to be a field's worth rather than an autocorrect, and the
// share of it that must be unaccounted for before the form reads as filled in by
// a program rather than typed.
const MIN_BULK_INSERTED_CHARACTERS = 12;
const BULK_INSERTION_RATIO = 0.6;

// Per-layer thresholds alone let a careful client spread its tells so that no
// single layer crosses the bar: 0.30 instant + 0.30 behavioral + 0.35 server is
// a combined 0.68 and three independent pieces of evidence, but each layer
// individually says "fine". Corroboration across layers is the thing worth
// acting on, so the combined score decides too — but only when more than one
// layer actually contributed, which keeps a single noisy environment signal from
// carrying a verdict on its own.

// Caps on the raw sample streams the page submits, so recomputation stays cheap
// and a client cannot turn the audit trail into a memory attack.
const MAX_SAMPLES = {
  mouseMoves: 600,
  scrolls: 200,
  keyPresses: 400,
  clicks: 60,
  touches: 200,
  buttons: 120,
  keyReleases: 400,
};

// Clock drift and the gap between the document response and the detector's first
// tick, both of which make an honest observation window look marginally long.
const OBSERVATION_SLACK_MS = 2_000;

// The collector stamps every sample with `Date.now()`, so an honest stream is in
// epoch milliseconds. A stream authored from scratch tends to start near zero
// because it was generated relative to itself.
const MIN_EPOCH_MS = 1_600_000_000_000;

// Proof of work. One submission costs a person a fraction of a second; a client
// running the form in a loop pays it again on every request and cannot amortise
// it, so the difficulty rises with how much that address has already sent.
const POW_BASE_DIFFICULTY = numberSetting("POW_BASE_DIFFICULTY", 16, { integer: true, max: 32 });
const POW_MAX_DIFFICULTY = numberSetting("POW_MAX_DIFFICULTY", 22, { integer: true, max: 32 });
const POW_ESCALATION_BITS = numberSetting("POW_ESCALATION_BITS", 2, { integer: true, max: 16 });

// Telemetry beacons. The point is not what the beacon says — it is that the
// server watches it arrive, on the server's own clock. A payload claiming thirty
// seconds of interaction has to be accompanied by thirty seconds of the session
// actually existing and reporting, rather than being authored in one go and slept
// in front of.
const TELEMETRY_INTERVAL_MS = numberSetting("TELEMETRY_INTERVAL_MS", 2_000, { min: 100 });
const MAX_TELEMETRY_BEACONS = 400;
const TELEMETRY_STALE_MS = numberSetting("TELEMETRY_STALE_MS", 20_000);
const TELEMETRY_COVERAGE = numberSetting("TELEMETRY_COVERAGE", 0.5, { max: 1 });

// How far the page's own behavioral score may sit from the server's recomputation
// before the difference reads as tampering rather than rounding.
const SCORE_MISMATCH_TOLERANCE = 0.05;

// Volume controls. OS-level input injection with real scan codes, and a raw CDP
// Input client driving a normal browser, both produce input a page cannot tell
// from a person's — see README "Known-open vectors". What they cannot hide is
// repetition: a hand fills this form once, a loop fills it all afternoon. These
// do not classify a single submission and deliberately never touch the verdict;
// they mark a clean-looking submission for review instead of silently accepting it.
const RISK_WINDOW_MS = numberSetting("RISK_WINDOW_MS", 10 * 60_000, { min: 1_000 });
const MAX_SUBMISSIONS_PER_SESSION = numberSetting("MAX_SUBMISSIONS_PER_SESSION", 3, { integer: true, min: 1 });
const MAX_SUBMISSIONS_PER_IP = numberSetting("MAX_SUBMISSIONS_PER_IP", 10, { integer: true, min: 1 });
const MAX_SESSIONS_PER_IP = numberSetting("MAX_SESSIONS_PER_IP", 12, { integer: true, min: 1 });
const MAX_CHALLENGES_PER_SESSION = numberSetting("MAX_CHALLENGES_PER_SESSION", 24, { integer: true, min: 1 });
const MAX_IDENTICAL_SUBMISSIONS = numberSetting("MAX_IDENTICAL_SUBMISSIONS", 1, { integer: true, min: 1 });
const MAX_RISK_KEYS = 10_000;
const ipActivity = new Map();
const TRUST_EDGE_HEADERS = process.env.TRUST_EDGE_HEADERS === "1";
const CONFIDENCE_LEVELS = new Set(["low", "medium", "high"]);
const challenges = new Map();
const PAGE_SESSION_COOKIE = "bs_page";
const PAGE_SESSION_TTL_MS = 30 * 60_000;
const MAX_PAGE_SESSIONS = 10_000;
const REQUIRED_PAGE_ASSETS = ["/styles.css", "/vendor/bot-signal.global.js", "/app.js"];
const ASSET_FETCH_DEST = { ".css": "style", ".js": "script" };
const pageSessions = new Map();

// Location/locale signals are routine for travellers, VPN users and anyone whose
// GeoIP record sits in another US timezone, so they are reported as notes and
// never decide the verdict on their own.
const ADVISORY_SIGNALS = new Set([
  "timezone-mismatch",
  "accept-language-geo-mismatch",
  "client-language-mismatch",
  "icloud-private-relay",
]);

// A single sub-0.5 signal (datacenter egress, missing Fetch Metadata, no TLS
// fingerprint) describes plenty of real people on corporate VPNs, so two of them
// must corroborate before the verdict flips.
const STRONG_SIGNAL_WEIGHT = 0.5;
const MIN_SUPPORTING_SIGNALS = 2;

// A US visitor geolocated to another US zone is off by up to 3 hours, so the
// default 60-minute tolerance would flag them.
const TZ_TOLERANCE_MINUTES = numberSetting("TZ_TOLERANCE_MINUTES", 180, { max: 1_440 });

const PROTECTION_MODE = choiceSetting("PROTECTION_MODE", "enforce", ["enforce", "monitor"]);
const TRUST_PROXY_HOPS = numberSetting("TRUST_PROXY_HOPS", 1, { integer: true });
const RATE_LIMIT_WINDOW_MS = numberSetting("RATE_LIMIT_WINDOW_MS", 60_000, { min: 1 });
const RATE_LIMIT_MAX = numberSetting("RATE_LIMIT_MAX", 600, { integer: true });
const SUBMIT_RATE_LIMIT_MAX = numberSetting("SUBMIT_RATE_LIMIT_MAX", 30, { integer: true });
const TRAP_LOCKOUT_MS = numberSetting("TRAP_LOCKOUT_MS", 0);
const BOT_POLICY_DENY = listSetting("BOT_POLICY_DENY", "training_crawler");
const TLS_CERT_FILE = process.env.TLS_CERT_FILE;
const TLS_KEY_FILE = process.env.TLS_KEY_FILE;
const RATE_LIMIT_ALGORITHM = choiceSetting("RATE_LIMIT_ALGORITHM", "sliding", ["fixed", "sliding", "token-bucket"]);
const RATE_LIMIT_STORE = choiceSetting("RATE_LIMIT_STORE", "memory", ["memory", "upstash"]);
const RATE_LIMIT_ON_STORE_ERROR = choiceSetting("RATE_LIMIT_ON_STORE_ERROR", "open", ["open", "closed"]);
const DECOY_ENABLED = choiceSetting("DECOY", "1", ["0", "1"]) === "1";
const DEMOTED_SIGNALS = new Set(listSetting("DEMOTED_SIGNALS"));
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";
const SHUTDOWN_TIMEOUT_MS = numberSetting("SHUTDOWN_TIMEOUT_MS", 10_000, { min: 0 });

if (Boolean(TLS_CERT_FILE) !== Boolean(TLS_KEY_FILE)) {
  configErrors.push("TLS_CERT_FILE and TLS_KEY_FILE must be set together");
}
if (POW_MAX_DIFFICULTY < POW_BASE_DIFFICULTY) {
  configErrors.push("POW_MAX_DIFFICULTY must not be lower than POW_BASE_DIFFICULTY");
}
if (ADMIN_TOKEN && ADMIN_TOKEN.length < 16) {
  configErrors.push("ADMIN_TOKEN must be at least 16 characters");
}
if (RATE_LIMIT_STORE === "upstash" && !(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN)) {
  configErrors.push("RATE_LIMIT_STORE=upstash needs UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN");
}
for (const [name, value, min, max] of [
  ["AGGREGATE_SCORE_THRESHOLD", AGGREGATE_SCORE_THRESHOLD, 0, 1],
  ["AGGREGATE_BEHAVIORAL_THRESHOLD", AGGREGATE_BEHAVIORAL_THRESHOLD, 0, 1],
  ["MIN_CORROBORATING_LAYERS", MIN_CORROBORATING_LAYERS, 1, 4],
]) {
  if (!Number.isFinite(value) || value < min || value > max) {
    configErrors.push(`${name} must be a number from ${min} to ${max}`);
  }
}
const HONEYPOT_FIELD = "hp_check";
const MAX_PROTECTION_EVENTS = 500;
const protectionEvents = [];

function parseTlsEntries(raw) {
  if (!raw) return [];
  try {
    const entries = JSON.parse(raw);
    return Array.isArray(entries) ? entries : [];
  } catch {
    console.warn("SUSPICIOUS_TLS_ENTRIES is not valid JSON — ignoring");
    return [];
  }
}

const detectorOptions = {
  requireBrowserHeaders: true,
  timezoneToleranceMinutes: TZ_TOLERANCE_MINUTES,
  requireTlsFingerprint: process.env.REQUIRE_TLS === "1",
  suspiciousTlsFingerprints: (process.env.SUSPICIOUS_TLS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean),
  suspiciousTlsFingerprintEntries: parseTlsEntries(process.env.SUSPICIOUS_TLS_ENTRIES),
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function header(req, name) {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function expectedRequestOrigin(req) {
  const forwardedProto = TRUST_EDGE_HEADERS
    ? header(req, "x-forwarded-proto")?.split(",")[0]?.trim()
    : undefined;
  const protocol = forwardedProto || (req.socket.encrypted ? "https" : "http");
  const host = header(req, "host");
  return host ? `${protocol}://${host}` : null;
}

function validateRequestProvenance(req) {
  const expectedOrigin = expectedRequestOrigin(req);
  const origin = header(req, "origin");
  const referer = header(req, "referer");
  const reasons = [];

  if (!expectedOrigin || origin !== expectedOrigin) {
    reasons.push("missing or cross-origin Origin header");
  }
  if (!expectedOrigin || !referer?.startsWith(`${expectedOrigin}/`)) {
    reasons.push("missing or cross-origin Referer header");
  }

  return reasons;
}

function parseCookies(req) {
  const jar = new Map();
  const raw = header(req, "cookie");
  if (!raw) return jar;
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    jar.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return jar;
}

function prunePageSessions(now = Date.now()) {
  for (const [id, session] of pageSessions) {
    if (session.expiresAt <= now) pageSessions.delete(id);
  }
}

function currentPageSession(req) {
  prunePageSessions();
  const id = parseCookies(req).get(PAGE_SESSION_COOKIE);
  if (!id) return { id: null, session: null };
  return { id, session: pageSessions.get(id) ?? null };
}

function startPageSession(req, res, documentPath) {
  prunePageSessions();
  while (pageSessions.size >= MAX_PAGE_SESSIONS) {
    pageSessions.delete(pageSessions.keys().next().value);
  }
  const id = randomUUID();
  const now = Date.now();
  ipRecord(clientIp(req), now).sessions += 1;
  pageSessions.set(id, {
    documentPath,
    startedAt: now,
    expiresAt: now + PAGE_SESSION_TTL_MS,
    ip: clientIp(req),
    userAgent: header(req, "user-agent") ?? "",
    navigated:
      header(req, "sec-fetch-mode") === "navigate" && header(req, "sec-fetch-dest") === "document",
    assets: new Map(),
    beacons: [],
    telemetryNonce: randomUUID(),
  });
  res.setHeader(
    "set-cookie",
    `${PAGE_SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(
      PAGE_SESSION_TTL_MS / 1000,
    )}`,
  );
  return id;
}

function recordAssetLoad(req, assetPath) {
  const { session } = currentPageSession(req);
  if (!session) return;
  if (session.ip !== clientIp(req)) return;
  if (session.userAgent !== (header(req, "user-agent") ?? "")) return;
  session.assets.set(assetPath, {
    at: Date.now(),
    dest: header(req, "sec-fetch-dest") ?? "",
    mode: header(req, "sec-fetch-mode") ?? "",
    site: header(req, "sec-fetch-site") ?? "",
  });
}

// A real browser cannot submit without first rendering the document and pulling
// every subresource it references, each carrying its own Fetch Metadata. A direct
// HTTP client that only calls /api/challenge and /api/submit leaves no such trail,
// even when it copies the Origin, Referer and User-Agent of a browser.
function validatePageSession(req, challengePageSessionId) {
  const { id, session } = currentPageSession(req);
  const reasons = [];

  if (!id) {
    reasons.push("no page-load session was established by loading the form page");
    return reasons;
  }
  if (!session) {
    reasons.push("page-load session is unknown or expired");
    return reasons;
  }
  if (session.ip !== clientIp(req)) {
    reasons.push("page-load session was opened from a different IP");
  }
  if (session.userAgent !== (header(req, "user-agent") ?? "")) {
    reasons.push("page-load session was opened with a different user agent");
  }
  if (!session.navigated) {
    reasons.push("document was not requested as a browser navigation");
  }

  const missingAssets = REQUIRED_PAGE_ASSETS.filter((asset) => !session.assets.has(asset));
  if (missingAssets.length > 0) {
    reasons.push(`page subresources were never fetched: ${missingAssets.join(", ")}`);
  } else {
    const mislabelled = REQUIRED_PAGE_ASSETS.filter((asset) => {
      const record = session.assets.get(asset);
      const expectedDest = ASSET_FETCH_DEST[extname(asset)];
      return record.dest !== expectedDest || record.site !== "same-origin";
    });
    if (mislabelled.length > 0) {
      reasons.push(`page subresources lacked browser fetch metadata: ${mislabelled.join(", ")}`);
    }
    const beforeDocument = REQUIRED_PAGE_ASSETS.filter(
      (asset) => session.assets.get(asset).at < session.startedAt,
    );
    if (beforeDocument.length > 0) {
      reasons.push(`page subresources were fetched before the document: ${beforeDocument.join(", ")}`);
    }
  }

  if (!challengePageSessionId) {
    reasons.push("page challenge was not issued inside a page-load session");
  } else if (challengePageSessionId !== id) {
    reasons.push("page challenge was issued to a different page-load session");
  }

  return reasons;
}

// Set CLIENT_IP_HEADER to whatever your proxy/CDN writes (cf-connecting-ip,
// x-real-ip, true-client-ip). Without the real visitor IP every request inherits
// the proxy's datacenter address and looks alike.
const CLIENT_IP_HEADER = (process.env.CLIENT_IP_HEADER ?? "x-forwarded-for").toLowerCase();

const TRUST_PROXY = !TRUST_EDGE_HEADERS
  ? false
  : CLIENT_IP_HEADER === "x-forwarded-for"
    ? TRUST_PROXY_HOPS
    : { header: CLIENT_IP_HEADER };

function clientIp(req) {
  return (
    resolveClientIp({ headers: req.headers, peer: req.socket.remoteAddress, trustProxy: TRUST_PROXY }) ??
    ""
  );
}

function webBotAuthSetting() {
  const raw = process.env.WEB_BOT_AUTH_KEYS;
  let keys = [];
  if (raw) {
    try {
      keys = JSON.parse(raw);
      if (!Array.isArray(keys)) throw new Error("expected an array");
    } catch (error) {
      configErrors.push(`WEB_BOT_AUTH_KEYS must be a JSON array of {name, category, jwk}: ${error.message}`);
      keys = [];
    }
  }
  const directories = choiceSetting("WEB_BOT_AUTH", "0", ["0", "1"]) === "1";
  if (!directories && keys.length === 0) return false;
  return { keys, ...(directories ? {} : { directories: [] }) };
}

const rateLimitStore =
  RATE_LIMIT_STORE === "upstash" && configErrors.length === 0
    ? createUpstashRateLimitStore({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
        prefix: process.env.RATE_LIMIT_PREFIX || "bot-signal-demo:rl:",
      })
    : undefined;

function rateLimitRule(rule) {
  return {
    windowMs: RATE_LIMIT_WINDOW_MS,
    algorithm: RATE_LIMIT_ALGORITHM,
    store: rateLimitStore,
    onStoreError: RATE_LIMIT_ON_STORE_ERROR,
    ...rule,
  };
}

let protection;
try {
  protection = createBotProtection({
    mode: PROTECTION_MODE,
    trustProxy: TRUST_PROXY,
    trustedHeaders: TRUST_EDGE_HEADERS ? { crawlerVerification: "x-crawler-verification" } : {},
    skipPaths: ["/healthz", "/readyz"],
    honeytoken: { secret: process.env.HONEYTOKEN_SECRET || undefined },
    decoy: DECOY_ENABLED ? { secret: process.env.HONEYTOKEN_SECRET || undefined } : false,
    webBotAuth: webBotAuthSetting(),
    tripwire: { lockoutMs: TRAP_LOCKOUT_MS },
    attackSignatures: { dryRun: false },
    bots: BOT_POLICY_DENY.length > 0 ? { deny: BOT_POLICY_DENY } : false,
    rateLimit: [
      ...(RATE_LIMIT_MAX > 0
        ? [rateLimitRule({ name: "api-rate-limit", max: RATE_LIMIT_MAX, paths: ["/api/"] })]
        : []),
      ...(SUBMIT_RATE_LIMIT_MAX > 0
        ? [
            rateLimitRule({
              name: "submit-rate-limit",
              max: SUBMIT_RATE_LIMIT_MAX,
              paths: ["/api/submit"],
              methods: ["POST"],
            }),
          ]
        : []),
    ],
    detection: false,
  });
} catch (error) {
  configErrors.push(`Request protection rejected its configuration: ${error.message}`);
}

if (configErrors.length > 0) {
  console.error(`Invalid configuration:\n  ${configErrors.join("\n  ")}`);
  process.exit(1);
}

function recordProtectionEvent(req, decision) {
  const flagged = decision.results.find((outcome) => outcome.action !== "ALLOW");
  if (!flagged) return;
  const enforcedTrap = decision.results.some(
    (outcome) =>
      (outcome.rule === "honeytoken" || outcome.rule === "tripwire" || outcome.rule === "decoy") &&
      outcome.state === "RUN" &&
      outcome.action === "DENY",
  );
  if (enforcedTrap && decision.trapHit) {
    const { session } = currentPageSession(req);
    if (session && !session.trapped) {
      session.trapped = {
        path: decision.trapHit.path,
        at: Date.now(),
        honeytoken: decision.trapHit.honeytoken,
        matchedBy: decision.trapHit.matchedBy,
      };
    }
  }
  protectionEvents.unshift({
    at: new Date().toISOString(),
    rule: flagged.rule,
    state: flagged.state,
    action: flagged.action,
    reason: flagged.reason ?? "",
    blocked: decision.blocked,
    method: decision.method,
    path: decision.path,
    ip: decision.clientIp ?? "unknown",
    userAgent: (header(req, "user-agent") ?? "").slice(0, 200),
  });
  protectionEvents.length = Math.min(protectionEvents.length, MAX_PROTECTION_EVENTS);
}

let proxyWarningShown = false;

// One-time nudge when requests arrive with no forwarding header from a public
// address: that is usually a proxy in front of the app, not the visitor.
function warnOnProxyIp(req, ip) {
  if (
    proxyWarningShown ||
    (TRUST_EDGE_HEADERS && header(req, CLIENT_IP_HEADER)) ||
    !isPublicIp(ip)
  ) {
    return;
  }
  proxyWarningShown = true;
  console.warn(
    `Client IP ${ip} arrived without a ${CLIENT_IP_HEADER} header. If a proxy or CDN sits in ` +
      "front of this app, forward the visitor IP or set CLIENT_IP_HEADER.",
  );
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScore(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0 && value <= 1_000_000;
}

function isValidSignal(signal) {
  return (
    isObject(signal) &&
    typeof signal.id === "string" &&
    signal.id.length > 0 &&
    signal.id.length <= 100 &&
    typeof signal.description === "string" &&
    signal.description.length <= 500 &&
    signal.triggered === true &&
    isScore(signal.score) &&
    CONFIDENCE_LEVELS.has(signal.confidence)
  );
}

function validateClientLayer(result, scoreThreshold, kind) {
  if (
    !isObject(result) ||
    !isScore(result.suspicionScore) ||
    typeof result.isLegitClient !== "boolean" ||
    !CONFIDENCE_LEVELS.has(result.confidence) ||
    !Array.isArray(result.signals) ||
    result.signals.length > 100 ||
    !result.signals.every(isValidSignal)
  ) {
    return false;
  }

  const calculatedScore = combineScores(result.signals.map((signal) => signal.score));
  if (Math.abs(calculatedScore - result.suspicionScore) > 0.005) return false;
  if (result.isLegitClient !== (result.suspicionScore < scoreThreshold)) return false;

  if (kind === "behavioral") {
    const counts = result.sampleCounts;
    if (
      !isObject(counts) ||
      !["mouseMoves", "scrolls", "keyPresses", "clicks", "touches", "syntheticEvents"].every(
        (key) => isNonNegativeInteger(counts[key]),
      ) ||
      typeof result.observationMs !== "number" ||
      !Number.isFinite(result.observationMs) ||
      result.observationMs < 0 ||
      result.observationMs > 86_400_000
    ) {
      return false;
    }
  }

  return true;
}

function validateInteraction(interaction) {
  if (!isObject(interaction)) return ["missing interaction evidence"];

  const reasons = [];
  const editedFields = Array.isArray(interaction.editedFields)
    ? new Set(interaction.editedFields.filter((field) => typeof field === "string"))
    : new Set();

  if (
    typeof interaction.observationMs !== "number" ||
    !Number.isFinite(interaction.observationMs) ||
    interaction.observationMs < MIN_INTERACTION_OBSERVATION_MS
  ) {
    reasons.push("observation window was too short");
  }
  if (!isNonNegativeInteger(interaction.trustedInputEvents) || interaction.trustedInputEvents < 2) {
    reasons.push("required fields lacked trusted input events");
  }
  if (!editedFields.has("name") || !editedFields.has("email")) {
    reasons.push("required fields lacked trusted edit history");
  }
  if (interaction.submitEventTrusted !== true) {
    reasons.push("submit event was not trusted");
  }
  if (
    interaction.submitIntentTrusted !== true ||
    typeof interaction.submitIntentAgeMs !== "number" ||
    !Number.isFinite(interaction.submitIntentAgeMs) ||
    interaction.submitIntentAgeMs < 0 ||
    interaction.submitIntentAgeMs > MAX_SUBMIT_INTENT_AGE_MS ||
    !["pointer", "keyboard"].includes(interaction.submitIntentType)
  ) {
    reasons.push("no recent trusted submit intent");
  }
  if (
    !isNonNegativeInteger(interaction.untrustedFormEvents) ||
    interaction.untrustedFormEvents > 0
  ) {
    reasons.push("untrusted form events were observed");
  }

  // Text pushed in with SendInput/KEYEVENTF_UNICODE arrives as a trusted keydown
  // with no physical key behind it (empty code, VK_PACKET). Enforced here as well
  // as in the browser layer so a tampered page bundle cannot drop the evidence.
  const printableKeys = isNonNegativeInteger(interaction.printableKeyEvents)
    ? interaction.printableKeyEvents
    : 0;
  const injectedKeys = isNonNegativeInteger(interaction.injectedKeyEvents)
    ? interaction.injectedKeyEvents
    : 0;
  if (injectedKeys > printableKeys) {
    reasons.push("keystroke counters were inconsistent");
  } else if (
    injectedKeys >= MIN_INJECTED_KEY_EVENTS &&
    injectedKeys / Math.max(printableKeys, 1) >= INJECTED_KEY_EVENT_RATIO
  ) {
    reasons.push(
      `form text was injected at the OS level (${injectedKeys}/${printableKeys} keystrokes had no physical key)`,
    );
  }

  // A keyboard delivers one character per insertText event. A single event
  // carrying a whole field is a program setting a value — Playwright's fill(),
  // CDP Input.insertText, or an element.value assignment. Paste, autofill, drag
  // and IME commits arrive under their own inputType and never reach this count,
  // and the ratio keeps a mobile word-suggestion from flagging a real typist.
  const typed = isNonNegativeInteger(interaction.typedCharacters)
    ? interaction.typedCharacters
    : 0;
  const bulk = isNonNegativeInteger(interaction.bulkInsertedCharacters)
    ? interaction.bulkInsertedCharacters
    : 0;
  if (
    bulk >= MIN_BULK_INSERTED_CHARACTERS &&
    bulk / Math.max(bulk + typed, 1) >= BULK_INSERTION_RATIO
  ) {
    reasons.push(
      `form text was inserted programmatically (${bulk} of ${bulk + typed} characters arrived without a keystroke)`,
    );
  }


  return reasons;
}

function leadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

// Everyone pays the base cost, which is a tenth of a second. Escalation starts
// only past the point the volume controls already consider abusive, so a shared
// office address does not get progressively punished for being busy.
function powDifficultyFor(ip) {
  const record = ipActivity.get(ip);
  const sent = record?.submissions ?? 0;
  const excess = Math.max(0, sent - MAX_SUBMISSIONS_PER_IP);
  return Math.min(POW_MAX_DIFFICULTY, POW_BASE_DIFFICULTY + excess * POW_ESCALATION_BITS);
}

function verifyProofOfWork(challenge, nonce) {
  if (!challenge || typeof nonce !== "string" || nonce.length > 64) {
    return false;
  }
  const digest = createHash("sha256").update(`${challenge.powPrefix}:${nonce}`).digest();
  return leadingZeroBits(digest) >= challenge.powDifficulty;
}

function finiteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/**
 * Rebuilds the raw sample streams from an untrusted payload: wrong types are
 * dropped rather than coerced, and each stream keeps only its most recent
 * entries. Returns `null` only when no sample object was sent at all, which is
 * itself a finding — the page always sends one.
 */
function sanitizeSamples(raw) {
  if (!isObject(raw)) return null;

  const stream = (value, limit, map) => {
    if (!Array.isArray(value)) return [];
    return value
      .slice(-limit)
      .map((entry) => (isObject(entry) ? map(entry) : null))
      .filter((entry) => entry !== null && finiteNumber(entry.t) !== undefined);
  };

  const point = (entry) => ({
    x: finiteNumber(entry.x) ?? 0,
    y: finiteNumber(entry.y) ?? 0,
    movementX: finiteNumber(entry.movementX),
    movementY: finiteNumber(entry.movementY),
    pageX: finiteNumber(entry.pageX),
    pageY: finiteNumber(entry.pageY),
    screenX: finiteNumber(entry.screenX),
    screenY: finiteNumber(entry.screenY),
    isFullscreen: entry.isFullscreen === true,
    t: finiteNumber(entry.t),
    isTrusted: entry.isTrusted === true,
  });

  const samples = {
    mouseMoves: stream(raw.mouseMoves, MAX_SAMPLES.mouseMoves, point),
    scrolls: stream(raw.scrolls, MAX_SAMPLES.scrolls, (entry) => ({
      deltaY: finiteNumber(entry.deltaY) ?? 0,
      t: finiteNumber(entry.t),
      isTrusted: entry.isTrusted === true,
    })),
    keyPresses: stream(raw.keyPresses, MAX_SAMPLES.keyPresses, (entry) => ({
      t: finiteNumber(entry.t),
      isTrusted: entry.isTrusted === true,
      repeat: entry.repeat === true,
      code: typeof entry.code === "string" ? entry.code.slice(0, 32) : undefined,
      keyCode: finiteNumber(entry.keyCode),
      printable: entry.printable === true,
      composing: entry.composing === true,
    })),
    clicks: stream(raw.clicks, MAX_SAMPLES.clicks, (entry) => ({
      ...point(entry),
      detail: finiteNumber(entry.detail),
    })),
    touches: stream(raw.touches, MAX_SAMPLES.touches, (entry) => ({
      t: finiteNumber(entry.t),
      isTrusted: entry.isTrusted === true,
      kind: entry.kind === "move" ? "move" : "start",
      x: finiteNumber(entry.x),
      y: finiteNumber(entry.y),
    })),
    keyReleases: stream(raw.keyReleases, MAX_SAMPLES.keyReleases, (entry) => ({
      t: finiteNumber(entry.t),
      isTrusted: entry.isTrusted === true,
      code: typeof entry.code === "string" ? entry.code.slice(0, 40) : undefined,
      composing: entry.composing === true,
    })),
    buttons: stream(raw.buttons, MAX_SAMPLES.buttons, (entry) => ({
      kind: entry.kind === "up" ? "up" : "down",
      x: finiteNumber(entry.x) ?? 0,
      y: finiteNumber(entry.y) ?? 0,
      screenX: finiteNumber(entry.screenX),
      screenY: finiteNumber(entry.screenY),
      t: finiteNumber(entry.t),
      isTrusted: entry.isTrusted === true,
      pointerType: typeof entry.pointerType === "string" ? entry.pointerType.slice(0, 16) : undefined,
      pressure: finiteNumber(entry.pressure),
    })),
    observationMs: finiteNumber(raw.observationMs) ?? 0,
  };

  // An empty-but-present set is honest reporting of a session with no input; the
  // interaction gate already covers that. Only a missing `samples` object means
  // the client declined to show its working, which is what `null` signals here.
  return samples;
}

/**
 * Compares what the page said about itself against what its own raw samples
 * actually score. A page that reports a clean verdict it cannot derive is not a
 * page the server should be taking a verdict from.
 */
function compareClaimedBehavioral(claimed, recomputed) {
  if (!isObject(claimed)) return [];

  const reasons = [];
  const claimedScore = finiteNumber(claimed.suspicionScore);

  if (
    claimedScore === undefined ||
    Math.abs(claimedScore - recomputed.suspicionScore) > SCORE_MISMATCH_TOLERANCE
  ) {
    reasons.push(
      `reported score ${claimedScore ?? "none"} but its samples score ${recomputed.suspicionScore.toFixed(2)}`,
    );
  }

  const recomputedIds = new Set(
    recomputed.signals.filter((signal) => signal.triggered).map((signal) => signal.id),
  );
  const claimedIds = new Set(
    (Array.isArray(claimed.signals) ? claimed.signals : [])
      .filter((signal) => isObject(signal) && typeof signal.id === "string")
      .map((signal) => signal.id),
  );
  const dropped = [...recomputedIds].filter((id) => !claimedIds.has(id));

  if (dropped.length > 0) {
    reasons.push(`withheld triggered signals: ${dropped.join(", ")}`);
  }

  const counts = isObject(claimed.sampleCounts) ? claimed.sampleCounts : {};
  const actual = {
    mouseMoves: recomputed.sampleCounts.mouseMoves,
    keyPresses: recomputed.sampleCounts.keyPresses,
    clicks: recomputed.sampleCounts.clicks,
  };
  for (const [key, value] of Object.entries(actual)) {
    const reported = finiteNumber(counts[key]);
    // Streams are capped and windowed, so a report may legitimately exceed what
    // arrived; claiming fewer events than were sent cannot happen honestly.
    if (reported !== undefined && reported < value) {
      reasons.push(`reported ${reported} ${key} but sent ${value}`);
    }
  }

  return reasons;
}

function ipRecord(ip, now = Date.now()) {
  for (const [key, record] of ipActivity) {
    if (record.lastSeen + RISK_WINDOW_MS <= now) ipActivity.delete(key);
  }
  while (ipActivity.size >= MAX_RISK_KEYS) {
    ipActivity.delete(ipActivity.keys().next().value);
  }

  let record = ipActivity.get(ip);
  if (!record || record.startedAt + RISK_WINDOW_MS <= now) {
    record = { startedAt: now, submissions: 0, sessions: 0, forms: new Map() };
    ipActivity.set(ip, record);
  }
  record.lastSeen = now;
  return record;
}

function formDigest(form) {
  return JSON.stringify([form.name, form.email, form.company, form.message]);
}

/**
 * Repetition the input itself cannot hide. Returns reasons, never signals: the
 * verdict stays a statement about one submission, and volume is a separate axis.
 */
function assessRisk(req, form, pageSession) {
  const ip = clientIp(req);
  const record = ipRecord(ip);
  const reasons = [];

  record.submissions += 1;
  if (record.submissions > MAX_SUBMISSIONS_PER_IP) {
    reasons.push(
      `${record.submissions} submissions from this address in ${Math.round(RISK_WINDOW_MS / 60_000)} minutes`,
    );
  }

  const digest = formDigest(form);
  const repeats = (record.forms.get(digest) ?? 0) + 1;
  record.forms.set(digest, repeats);
  if (repeats > MAX_IDENTICAL_SUBMISSIONS) {
    reasons.push(`identical form content submitted ${repeats} times from this address`);
  }

  if (record.sessions > MAX_SESSIONS_PER_IP) {
    reasons.push(`${record.sessions} page loads from this address in the same window`);
  }

  const trap = protection.getTrap(ip);
  if (trap && !pageSession?.trapped) {
    reasons.push(
      `this address requested the hidden trap path ${trap.path} ${Math.round((Date.now() - trap.lastAt) / 1000)}s ago`,
    );
  }

  if (pageSession) {
    pageSession.submissions = (pageSession.submissions ?? 0) + 1;
    if (pageSession.submissions > MAX_SUBMISSIONS_PER_SESSION) {
      reasons.push(`${pageSession.submissions} submissions from a single page load`);
    }
    if ((pageSession.challenges ?? 0) > MAX_CHALLENGES_PER_SESSION) {
      reasons.push(`${pageSession.challenges} challenges taken by a single page load`);
    }
  }

  return reasons;
}

function pruneChallenges(now = Date.now()) {
  for (const [token, challenge] of challenges) {
    if (challenge.expiresAt <= now) challenges.delete(token);
  }
}

function createChallenge(req) {
  pruneChallenges();
  while (challenges.size >= MAX_ACTIVE_CHALLENGES) {
    challenges.delete(challenges.keys().next().value);
  }
  const token = randomUUID();
  const now = Date.now();
  const issuingSession = currentPageSession(req).session;
  if (issuingSession) {
    issuingSession.challenges = (issuingSession.challenges ?? 0) + 1;
  }
  const powPrefix = randomUUID();
  const powDifficulty = powDifficultyFor(clientIp(req));
  challenges.set(token, {
    expiresAt: now + CHALLENGE_TTL_MS,
    ip: clientIp(req),
    userAgent: header(req, "user-agent") ?? "",
    pageSessionId: currentPageSession(req).session ? currentPageSession(req).id : null,
    powPrefix,
    powDifficulty,
  });
  return {
    token,
    expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString(),
    pow: { prefix: powPrefix, difficulty: powDifficulty },
  };
}

function consumeChallenge(req, token) {
  pruneChallenges();
  if (typeof token !== "string") return { valid: false, pageSessionId: null };
  const challenge = challenges.get(token);
  challenges.delete(token);
  const valid = Boolean(
    challenge &&
      challenge.expiresAt > Date.now() &&
      challenge.ip === clientIp(req) &&
      challenge.userAgent === (header(req, "user-agent") ?? ""),
  );
  return {
    valid,
    pageSessionId: valid ? (challenge.pageSessionId ?? null) : null,
    record: valid ? challenge : null,
  };
}

/**
 * Records one telemetry beacon against the page session.
 *
 * Each reply carries the nonce the next beacon must quote, so the stream is a
 * chain rather than a set of independent posts, and every link is timestamped by
 * the server as it arrives. What matters is not the contents — a client can lie
 * about those — but that the session was demonstrably alive and reporting across
 * the window it later claims to have observed.
 */
async function handleTelemetry(req, res) {
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "invalid JSON body" });
  }

  const { session } = currentPageSession(req);
  if (!session) {
    return sendJson(res, 403, { error: "no page session" });
  }
  if (session.ip !== clientIp(req)) {
    return sendJson(res, 403, { error: "page session belongs to another address" });
  }
  // A beacon with no nonce is the opening handshake: hand out the first link of
  // the chain without recording anything.
  if (payload?.nonce === null || payload?.nonce === undefined) {
    return sendJson(res, 200, {
      nonce: session.telemetryNonce,
      intervalMs: TELEMETRY_INTERVAL_MS,
    });
  }
  if (payload.nonce !== session.telemetryNonce) {
    return sendJson(res, 409, { error: "stale telemetry nonce", nonce: session.telemetryNonce });
  }
  if (session.beacons.length >= MAX_TELEMETRY_BEACONS) {
    return sendJson(res, 429, { error: "too many beacons" });
  }

  const now = Date.now();
  const previous = session.beacons[session.beacons.length - 1];
  if (previous && now - previous.serverAt < TELEMETRY_INTERVAL_MS * 0.5) {
    return sendJson(res, 429, { error: "beacon too soon" });
  }

  session.beacons.push({
    serverAt: now,
    events: isNonNegativeInteger(payload?.events) ? payload.events : 0,
    lastT: finiteNumber(payload?.lastT),
  });
  session.telemetryNonce = randomUUID();

  return sendJson(res, 200, { nonce: session.telemetryNonce, intervalMs: TELEMETRY_INTERVAL_MS });
}

/**
 * Checks the claimed observation window against the stretch of time the server
 * actually watched this session report for. Authoring a long history offline and
 * sleeping in front of it satisfies the duration check but leaves no beacons.
 */
function validateTelemetryStream(session, claimedObservationMs) {
  if (!session) {
    return ["no page session to carry a telemetry stream"];
  }
  if (typeof claimedObservationMs !== "number" || !Number.isFinite(claimedObservationMs)) {
    return [];
  }

  const reasons = [];
  const beacons = session.beacons;
  // No fixed minimum: a page that submits in three seconds owes almost nothing,
  // while one claiming half a minute of watching has to have been reporting for
  // most of it. The requirement scales with the claim rather than the clock.
  const observedMs =
    beacons.length >= 2 ? beacons[beacons.length - 1].serverAt - beacons[0].serverAt : 0;
  // The span is quantised by the beacon interval and starts one interval after
  // the page does, so a short honest session can only ever prove most of itself.
  const requiredMs =
    claimedObservationMs * TELEMETRY_COVERAGE - OBSERVATION_SLACK_MS - TELEMETRY_INTERVAL_MS;

  if (observedMs < requiredMs) {
    reasons.push(
      `claimed ${Math.round(claimedObservationMs)}ms of observation but the session only reported for ` +
        `${Math.round(observedMs)}ms across ${beacons.length} beacon${beacons.length === 1 ? "" : "s"}`,
    );
  }

  if (beacons.length > 0) {
    const sinceLast = Date.now() - beacons[beacons.length - 1].serverAt;
    if (sinceLast > TELEMETRY_STALE_MS) {
      reasons.push(
        `last telemetry beacon arrived ${Math.round(sinceLast / 1000)}s before the submission`,
      );
    }
  }

  return reasons;
}

function clientSignal(id, description, score = 0.9) {
  return { layer: "client", id, description, score, confidence: "high" };
}

function layerScore(result) {
  const fired = (result.signals ?? []).filter((signal) => signal.triggered);
  if (!fired.some((signal) => DEMOTED_SIGNALS.has(signal.id))) {
    return result.suspicionScore;
  }
  return combineScores(fired.filter((signal) => !DEMOTED_SIGNALS.has(signal.id)).map((signal) => signal.score));
}

function triggered(layer, result) {
  return (result?.signals ?? [])
    .filter((signal) => signal.triggered)
    .map((signal) => ({
      layer,
      id: signal.id,
      description: signal.description,
      score: signal.score,
      confidence: signal.confidence,
    }));
}

function cleanForm(form = {}) {
  const pick = (key) => String(form[key] ?? "").slice(0, 500);
  return {
    name: pick("name"),
    email: pick("email"),
    company: pick("company"),
    message: pick("message"),
  };
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error("payload too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function sendFile(res, path) {
  try {
    const body = await readFile(path);
    res.writeHead(200, {
      "content-type": MIME[extname(path)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("Not found");
  }
}

async function handleSubmit(req, res, decision) {
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "invalid JSON body" });
  }
  if (!isObject(payload)) {
    return sendJson(res, 400, { error: "JSON body must be an object" });
  }

  const client = isObject(payload.client) ? payload.client : {};
  const form = cleanForm(isObject(payload.form) ? payload.form : {});
  const instant = client.instant ?? null;
  const claimedBehavioral = client.behavioral ?? null;

  // The page's own behavioral verdict is advisory. Recompute it here from the raw
  // samples so a forged `{score: 0, signals: []}` buys nothing, and keep the
  // recomputed object as the one that decides.
  const samples = sanitizeSamples(client.samples);
  const recomputed = samples
    ? analyzeBehavioralSamples(samples, BEHAVIORAL_SCORE_THRESHOLD)
    : null;
  // Same shape the page reports — triggered signals only — so the recomputed
  // layer goes through exactly the same validation as a claimed one instead of
  // failing it on the untriggered entries a full analysis carries.
  const behavioral = recomputed
    ? {
        suspicionScore: recomputed.suspicionScore,
        isLegitClient: recomputed.isLegitClient,
        confidence: recomputed.confidence,
        sampleCounts: recomputed.sampleCounts,
        observationMs: recomputed.observationMs,
        signals: recomputed.signals.filter((signal) => signal.triggered),
      }
    : claimedBehavioral;
  const claimMismatchReasons = recomputed
    ? compareClaimedBehavioral(claimedBehavioral, recomputed)
    : [];

  const instantValid = validateClientLayer(instant, INSTANT_SCORE_THRESHOLD, "instant");
  const behavioralValid = validateClientLayer(
    behavioral,
    BEHAVIORAL_SCORE_THRESHOLD,
    "behavioral",
  );
  const missingClientLayer = !instant || !behavioral;
  const { session: pageSession } = currentPageSession(req);
  // Read before consumeChallenge deletes nothing relevant, but kept here so the
  // signals below all see the same session object.
  const sessionAgeMs = pageSession ? Date.now() - pageSession.startedAt : undefined;
  const observationReasons = [];

  if (samples) {
    const stamps = [
      ...samples.mouseMoves,
      ...samples.scrolls,
      ...samples.keyPresses,
      ...samples.clicks,
      ...samples.touches,
      ...samples.buttons,
      ...samples.keyReleases,
    ].map((sample) => sample.t);
    const earliest = stamps.length > 0 ? Math.min(...stamps) : undefined;
    if (earliest !== undefined && earliest < MIN_EPOCH_MS) {
      observationReasons.push(
        `sample timestamps are not wall-clock times (earliest ${earliest})`,
      );
    }
  }

  // Durations on both sides, never absolute timestamps — a visitor whose clock is
  // wrong is still a visitor, but nobody can watch a page for longer than the page
  // has existed.
  if (sessionAgeMs !== undefined) {
    for (const [label, claimed] of [
      ["behavioral", finiteNumber(behavioral?.observationMs)],
      ["interaction", finiteNumber(client.interaction?.observationMs)],
    ]) {
      if (claimed !== undefined && claimed > sessionAgeMs + OBSERVATION_SLACK_MS) {
        observationReasons.push(
          `${label} claims ${Math.round(claimed)}ms of observation in a ${Math.round(sessionAgeMs)}ms page session`,
        );
      }
    }
  }
  const invalidClientLayer = !missingClientLayer && (!instantValid || !behavioralValid);
  const interactionReasons = validateInteraction(client.interaction);
  const provenanceReasons = validateRequestProvenance(req);
  const challenge = consumeChallenge(req, payload.challengeToken);
  const challengeValid = challenge.valid;
  const powValid = challengeValid && verifyProofOfWork(challenge.record, payload.powNonce);
  const pageSessionReasons = validatePageSession(req, challenge.pageSessionId);
  const clientSignals = [];

  if (missingClientLayer) {
    clientSignals.push(
      clientSignal("missing-client-layer", "Submission did not include both browser detection layers"),
    );
  } else if (invalidClientLayer) {
    clientSignals.push(
      clientSignal("invalid-client-layer", "Browser detection results were malformed or inconsistent"),
    );
  }
  if (!challengeValid) {
    clientSignals.push(
      clientSignal("invalid-challenge", "Submission did not use a valid one-time page challenge"),
    );
  }
  if (challengeValid && !powValid) {
    clientSignals.push(
      clientSignal(
        "invalid-proof-of-work",
        `Submission did not carry the work its challenge demanded (${challenge.record.powDifficulty} bits)`,
      ),
    );
  }
  if (interactionReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "untrusted-form-interaction",
        `Form interaction could not be verified: ${interactionReasons.join("; ")}`,
        0.8,
      ),
    );
  }
  if (provenanceReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "invalid-request-provenance",
        `Submission did not originate from the served page: ${provenanceReasons.join("; ")}`,
      ),
    );
  }
  if (pageSessionReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "invalid-page-session",
        `Submission was not preceded by a genuine page load: ${pageSessionReasons.join("; ")}`,
      ),
    );
  }
  if (!samples && !missingClientLayer) {
    clientSignals.push(
      clientSignal(
        "missing-behavioral-samples",
        "Submission reported a behavioral verdict without the samples it was derived from",
      ),
    );
  }
  if (claimMismatchReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "forged-client-verdict",
        `Reported browser verdict did not match its own samples: ${claimMismatchReasons.join("; ")}`,
      ),
    );
  }
  if (observationReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "impossible-observation-window",
        `Client evidence outlived its page session: ${observationReasons.join("; ")}`,
      ),
    );
  }
  const telemetryReasons = validateTelemetryStream(
    pageSession,
    finiteNumber(behavioral?.observationMs) ?? finiteNumber(client.interaction?.observationMs),
  );
  if (telemetryReasons.length > 0) {
    clientSignals.push(
      clientSignal(
        "missing-telemetry-stream",
        `Session did not report while it claims to have been observed: ${telemetryReasons.join("; ")}`,
      ),
    );
  }
  const honeypotValue = isObject(payload.form) ? payload.form[HONEYPOT_FIELD] : undefined;
  if (honeypotValue !== undefined && honeypotValue !== null && String(honeypotValue).trim() !== "") {
    clientSignals.push(
      clientSignal(
        "honeypot-field-filled",
        "A form field that is invisible, unfocusable and hidden from assistive technology was filled in",
      ),
    );
  }
  if (pageSession?.trapped) {
    const { matchedBy, path } = pageSession.trapped;
    clientSignals.push(
      matchedBy === "canary-credential"
        ? clientSignal(
            "decoy-api-tripped",
            "This page session presented the canary API key that exists only in the page's hidden decoy config",
          )
        : matchedBy === "decoy-endpoint"
          ? clientSignal(
              "decoy-api-tripped",
              `This page session called the decoy API endpoint ${path}, which only code mining the page for endpoints finds`,
            )
          : clientSignal(
              "honeytoken-tripped",
              `This page session requested the hidden trap path ${path}, which only link-harvesting automation can find`,
            ),
    );
  }

  const ja4 = TRUST_EDGE_HEADERS ? header(req, "x-ja4") : undefined;
  const ja3 = TRUST_EDGE_HEADERS ? header(req, "x-ja3-hash") : undefined;

  const ip = clientIp(req);
  warnOnProxyIp(req, ip);

  const server = await detectServerClientAsync(
    {
      clientIp: isPublicIp(ip) ? ip : undefined,
      userAgent: header(req, "user-agent"),
      acceptLanguage: header(req, "accept-language"),
      secChUa: header(req, "sec-ch-ua"),
      secChUaPlatform: header(req, "sec-ch-ua-platform"),
      secChUaMobile: header(req, "sec-ch-ua-mobile"),
      secFetchSite: header(req, "sec-fetch-site"),
      secFetchMode: header(req, "sec-fetch-mode"),
      secFetchDest: header(req, "sec-fetch-dest"),
      tlsFingerprint: ja4 ?? ja3,
      tlsFingerprintType: ja4 ? "ja4" : "ja3",
      tlsClientHello: getTlsClientHello(req.socket),
      crawlerVerificationStatus: decision?.crawlerVerification,
      clientUserAgent: typeof client.userAgent === "string" ? client.userAgent : undefined,
      clientTimezone: typeof client.timezone === "string" ? client.timezone : undefined,
      clientLanguage: typeof client.language === "string" ? client.language : undefined,
      clientLanguages: Array.isArray(client.languages)
        ? client.languages.filter((language) => typeof language === "string").slice(0, 20)
        : undefined,
      clientPlatform: typeof client.platform === "string" ? client.platform : undefined,
    },
    detectorOptions,
  );

  const serverSignals = triggered("server", server);
  const advisoryNotes = serverSignals.filter((signal) => ADVISORY_SIGNALS.has(signal.id));
  const decisive = serverSignals.filter(
    (signal) => !ADVISORY_SIGNALS.has(signal.id) && !DEMOTED_SIGNALS.has(signal.id),
  );
  const countedClientSignals = clientSignals.filter((signal) => !DEMOTED_SIGNALS.has(signal.id));
  const verdict = decideVerdict({
    instantScore: instantValid ? layerScore(instant) : null,
    behavioralScore: behavioralValid ? layerScore(behavioral) : null,
    serverScore: layerScore(server),
    clientSignalScores: countedClientSignals.map((signal) => signal.score),
    decisiveServerScores: decisive.map((signal) => signal.score),
  });
  const { isAgent, score, corroboratingLayers } = verdict;

  const signals = [
    ...clientSignals,
    ...triggered("instant", instantValid ? instant : null),
    ...triggered("behavioral", behavioralValid ? behavioral : null),
    ...serverSignals,
  ].sort((a, b) => b.score - a.score);

  const automation = [instantValid ? instant?.automation : null, server.automation].find(
    (item) => item?.isAutomated && item.kind !== "unknown",
  );

  const record = {
    id: randomUUID(),
    receivedAt: new Date().toISOString(),
    form,
    verdict: isAgent ? "agent" : "human",
    score: Number(score.toFixed(3)),
    automationKind: automation?.kind ?? (isAgent ? "unknown" : null),
    automationEvidence: automation?.evidence ?? [],
    ip: ip || "unknown",
    country: server.context.ipCountry ?? null,
    userAgent: header(req, "user-agent") ?? "",
    timezone:
      (typeof client.timezone === "string" ? client.timezone : undefined) ??
      server.context.ipTimezone ??
      null,
    layers: {
      instant: instantValid
        ? {
            score: Number(instant.suspicionScore.toFixed(3)),
            isLegitClient: instant.isLegitClient,
            confidence: instant.confidence,
          }
        : null,
      behavioral: behavioralValid
        ? {
            score: Number(behavioral.suspicionScore.toFixed(3)),
            isLegitClient: behavioral.isLegitClient,
            confidence: behavioral.confidence,
            sampleCounts: behavioral.sampleCounts,
            observationMs: behavioral.observationMs,
          }
        : null,
      server: {
        score: Number(server.suspicionScore.toFixed(3)),
        isLegitClient: server.isLegitClient,
        confidence: server.confidence,
      },
    },
    signals: signals.slice(0, 12),
    signalIds: signals.map((signal) => `${signal.layer}:${signal.id}`),
    notes: advisoryNotes.map((signal) => signal.id),
    demoted: signals.filter((signal) => DEMOTED_SIGNALS.has(signal.id)).map((signal) => `${signal.layer}:${signal.id}`),
    agent:
      decision?.agent && decision.agent.status !== "none"
        ? { status: decision.agent.status, name: decision.agent.agentName ?? null }
        : null,
    crawlerVerification: decision?.crawlerVerification ?? null,
    corroboratingLayers,
  };

  // Deliberately after the verdict and never folded into it: `verdict` stays a
  // statement about this one submission, `outcome` is what to do about it.
  const riskReasons = assessRisk(req, form, pageSession);
  // Circumstantial evidence holds a submission; it does not refuse one. A virtual
  // machine, a touch typist and a trackpad can each produce one of these on their
  // own, and a real person managed all three at once.
  const hardEvidence = hasHardEvidence(
    signals.map((signal) => signal.id).filter((id) => !DEMOTED_SIGNALS.has(id)),
    countedClientSignals.map((signal) => signal.score),
  );
  const outcome = isAgent
    ? hardEvidence
      ? "rejected"
      : "review"
    : riskReasons.length > 0
      ? "review"
      : "accepted";
  record.outcome = outcome;
  record.risk = riskReasons;

  insertSubmission(record);

  const status = outcome === "rejected" ? 403 : outcome === "review" ? 202 : 200;
  sendJson(res, status, {
    accepted: outcome === "accepted",
    outcome,
    risk: riskReasons,
    verdict: record.verdict,
    score: record.score,
    automationKind: record.automationKind,
    layers: record.layers,
    signals: record.signals,
    notes: record.notes,
    demoted: record.demoted,
  });
}

function isAuthorized(req) {
  if (!ADMIN_TOKEN) return true;
  const supplied = (header(req, "authorization") ?? "").replace(/^Bearer\s+/i, "");
  const expected = createHash("sha256").update(ADMIN_TOKEN).digest();
  return timingSafeEqual(createHash("sha256").update(supplied).digest(), expected);
}

function signalStats() {
  const labeled = labeledSubmissions();
  const bySignal = new Map();
  let falsePositives = 0;
  let falseNegatives = 0;
  for (const record of labeled) {
    if (record.verdict === "agent" && record.label === "human") falsePositives += 1;
    if (record.verdict === "human" && record.label === "agent") falseNegatives += 1;
    const ids = record.signalIds ?? record.signals.map((signal) => `${signal.layer}:${signal.id}`);
    for (const id of new Set(ids)) {
      const entry = bySignal.get(id) ?? { signal: id, human: 0, agent: 0 };
      entry[record.label] += 1;
      bySignal.set(id, entry);
    }
  }
  const signals = [...bySignal.values()]
    .map((entry) => ({
      ...entry,
      precision: Number((entry.agent / (entry.agent + entry.human)).toFixed(3)),
      demoted: DEMOTED_SIGNALS.has(entry.signal.slice(entry.signal.indexOf(":") + 1)),
    }))
    .sort((a, b) => a.precision - b.precision || b.human - a.human || a.signal.localeCompare(b.signal));
  return {
    labeled: labeled.length,
    humans: labeled.filter((record) => record.label === "human").length,
    agents: labeled.filter((record) => record.label === "agent").length,
    falsePositives,
    falseNegatives,
    demoted: [...DEMOTED_SIGNALS],
    signals,
  };
}

async function handleReview(req, res, id) {
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: "invalid JSON body" });
  }
  const label = payload?.label;
  if (label !== "human" && label !== "agent") {
    return sendJson(res, 400, { error: 'label must be "human" or "agent"' });
  }
  const record = getSubmission(id);
  if (!record) {
    return sendJson(res, 404, { error: "no such submission" });
  }
  record.label = label;
  record.labeledAt = new Date().toISOString();
  if (record.outcome === "review") {
    record.outcome = label === "human" ? "released" : "discarded";
  }
  updateSubmission(record);
  return sendJson(res, 200, { id, label, outcome: record.outcome });
}

let ready = false;
let shuttingDown = false;

function readiness() {
  if (!ready || shuttingDown) return { status: shuttingDown ? "draining" : "starting", ok: false };
  try {
    countByVerdict();
    return { status: "ready", ok: true };
  } catch (error) {
    return { status: `database unavailable: ${error.message}`, ok: false };
  }
}

const ADMIN_ROUTES = new Set(["GET /api/submissions", "GET /api/protection", "GET /api/signal-stats", "POST /api/reset"]);

async function handleRequest(req, res) {
  const decision = await protection.handle(req, res, { serveRobotsTxt: true });
  recordProtectionEvent(req, decision);
  if (decision.responded) return;

  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "GET" && url.pathname === "/healthz") {
    return sendJson(res, 200, { status: "ok" });
  }

  if (req.method === "GET" && url.pathname === "/readyz") {
    const state = readiness();
    return sendJson(res, state.ok ? 200 : 503, { status: state.status });
  }

  const review = /^\/api\/submissions\/([0-9a-f-]{36})\/review$/.exec(url.pathname);
  if ((ADMIN_ROUTES.has(`${req.method} ${url.pathname}`) || review) && !isAuthorized(req)) {
    res.writeHead(401, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "www-authenticate": 'Bearer realm="dashboard"',
    });
    return res.end(JSON.stringify({ error: "admin token required" }));
  }

  if (req.method === "POST" && review) {
    return handleReview(req, res, review[1]);
  }

  if (req.method === "GET" && url.pathname === "/api/signal-stats") {
    return sendJson(res, 200, signalStats());
  }

  if (req.method === "GET" && url.pathname === "/api/challenge") {
    return sendJson(res, 200, createChallenge(req));
  }

  if (req.method === "POST" && url.pathname === "/api/telemetry") {
    return handleTelemetry(req, res);
  }

  if (req.method === "POST" && url.pathname === "/api/submit") {
    return handleSubmit(req, res, decision);
  }

  if (req.method === "GET" && url.pathname === "/api/submissions") {
    return sendJson(res, 200, {
      ...countByVerdict(),
      submissions: listSubmissions(LIST_LIMIT),
    });
  }

  if (req.method === "GET" && url.pathname === "/api/protection") {
    return sendJson(res, 200, {
      mode: PROTECTION_MODE,
      transport: TLS_CERT_FILE && TLS_KEY_FILE ? "https" : "http",
      events: protectionEvents.slice(0, LIST_LIMIT),
    });
  }

  if (req.method === "POST" && url.pathname === "/api/reset") {
    clearSubmissions();
    protectionEvents.length = 0;
    return sendJson(res, 200, { ok: true });
  }

  if (req.method !== "GET") {
    res.writeHead(405, { "content-type": "text/plain" });
    return res.end("Method not allowed");
  }

  if (url.pathname === "/vendor/bot-signal.global.js") {
    recordAssetLoad(req, url.pathname);
    return sendFile(res, globalBuild);
  }

  const name = url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/+/, "");
  const target = join(publicDir, name);
  if (!target.startsWith(publicDir)) {
    res.writeHead(403, { "content-type": "text/plain" });
    return res.end("Forbidden");
  }
  if (name.endsWith(".html")) startPageSession(req, res, `/${name}`);
  else recordAssetLoad(req, `/${name}`);
  return sendFile(res, target);
}

const scheme = TLS_CERT_FILE && TLS_KEY_FILE ? "https" : "http";
const server =
  scheme === "https"
    ? createHttpsServer({ cert: readFileSync(TLS_CERT_FILE), key: readFileSync(TLS_KEY_FILE) }, handleRequest)
    : createHttpServer(handleRequest);
if (scheme === "https") trackTlsClientHellos(server);

await preloadIpLists();

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, draining connections`);
  const force = setTimeout(() => {
    console.warn(`Connections still open after ${SHUTDOWN_TIMEOUT_MS}ms, closing them`);
    server.closeAllConnections();
  }, SHUTDOWN_TIMEOUT_MS);
  force.unref();
  server.close(async () => {
    clearTimeout(force);
    await protection.destroy();
    closeDatabase();
    process.exit(0);
  });
  server.closeIdleConnections();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

server.listen(PORT, HOST, () => {
  ready = true;
  console.log(`Listening:  ${HOST}:${PORT} (${scheme})`);
  console.log(`Form:      ${scheme}://localhost:${PORT}/`);
  console.log(`Dashboard: ${scheme}://localhost:${PORT}/dashboard.html`);
  console.log(`SQLite:    ${dbFile}`);
  console.log(`Protection: ${PROTECTION_MODE}, robots.txt at /robots.txt`);
  console.log(`Health:    /healthz (liveness), /readyz (readiness)`);
  if (!ADMIN_TOKEN && HOST !== "127.0.0.1" && HOST !== "localhost" && HOST !== "::1") {
    console.warn("ADMIN_TOKEN is unset: the dashboard and its APIs are open to anyone who can reach this host");
  }
});
