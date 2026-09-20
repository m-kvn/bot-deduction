import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { detectServerClientAsync, preloadIpLists } from "../../dist/server.js";
import {
  clearSubmissions,
  countByVerdict,
  dbFile,
  insertSubmission,
  listSubmissions,
} from "./db.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const publicDir = join(here, "public");
const globalBuild = join(here, "..", "..", "dist", "browser.global.js");
const PORT = Number(process.env.PORT ?? 8787);
const LIST_LIMIT = 200;
const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_ACTIVE_CHALLENGES = 10_000;
const INSTANT_SCORE_THRESHOLD = 0.5;
const BEHAVIORAL_SCORE_THRESHOLD = 0.5;
const MIN_INTERACTION_OBSERVATION_MS = 500;
const MAX_SUBMIT_INTENT_AGE_MS = 5_000;
const TRUST_EDGE_HEADERS = process.env.TRUST_EDGE_HEADERS === "1";
const CONFIDENCE_LEVELS = new Set(["low", "medium", "high"]);
const challenges = new Map();
const PAGE_SESSION_COOKIE = "bs_page";
const PAGE_SESSION_TTL_MS = 30 * 60_000;
const MAX_PAGE_SESSIONS = 10_000;
const REQUIRED_PAGE_ASSETS = ["/styles.css", "/vendor/bot-signal.global.js", "/app.js"];
const ASSET_FETCH_DEST = { ".css": "style", ".js": "script" };
const pageSessions = new Map();

const CRAWLER_STATUSES = new Set(["verified", "spoofed", "unverified"]);

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
const TZ_TOLERANCE_MINUTES = Number(process.env.TZ_TOLERANCE_MINUTES ?? 180);

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
  pageSessions.set(id, {
    documentPath,
    startedAt: now,
    expiresAt: now + PAGE_SESSION_TTL_MS,
    ip: clientIp(req),
    userAgent: header(req, "user-agent") ?? "",
    navigated:
      header(req, "sec-fetch-mode") === "navigate" && header(req, "sec-fetch-dest") === "document",
    assets: new Map(),
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

function clientIp(req) {
  const forwarded = TRUST_EDGE_HEADERS ? header(req, CLIENT_IP_HEADER) : undefined;
  const raw = forwarded?.split(",")[0]?.trim() || req.socket.remoteAddress || "";
  return raw.replace(/^::ffff:/, "");
}

// The bundled GeoIP database answers for loopback and RFC1918 ranges too
// (127.0.0.1 resolves to Asia/Tokyo), which would fire timezone and country
// mismatches for every local visitor — so those addresses are never looked up.
function isPublicIp(ip) {
  if (!ip) return false;

  const ipv4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
  if (ipv4) {
    const [first, second] = [Number(ipv4[1]), Number(ipv4[2])];
    if (first === 0 || first === 10 || first === 127) return false;
    if (first === 169 && second === 254) return false;
    if (first === 172 && second >= 16 && second <= 31) return false;
    if (first === 192 && second === 168) return false;
    if (first === 100 && second >= 64 && second <= 127) return false;
    return true;
  }

  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return false;
  return !/^(f[cd]|fe[89ab])/.test(lower);
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

function combineScores(scores) {
  return 1 - scores.reduce((acc, score) => acc * (1 - score), 1);
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
  challenges.set(token, {
    expiresAt: now + CHALLENGE_TTL_MS,
    ip: clientIp(req),
    userAgent: header(req, "user-agent") ?? "",
    pageSessionId: currentPageSession(req).session ? currentPageSession(req).id : null,
  });
  return { token, expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString() };
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
  return { valid, pageSessionId: valid ? (challenge.pageSessionId ?? null) : null };
}

function clientSignal(id, description, score = 0.9) {
  return { layer: "client", id, description, score, confidence: "high" };
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

async function handleSubmit(req, res) {
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
  const behavioral = client.behavioral ?? null;

  const instantValid = validateClientLayer(instant, INSTANT_SCORE_THRESHOLD, "instant");
  const behavioralValid = validateClientLayer(
    behavioral,
    BEHAVIORAL_SCORE_THRESHOLD,
    "behavioral",
  );
  const missingClientLayer = !instant || !behavioral;
  const invalidClientLayer = !missingClientLayer && (!instantValid || !behavioralValid);
  const interactionReasons = validateInteraction(client.interaction);
  const provenanceReasons = validateRequestProvenance(req);
  const challenge = consumeChallenge(req, payload.challengeToken);
  const challengeValid = challenge.valid;
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

  const ja4 = TRUST_EDGE_HEADERS ? header(req, "x-ja4") : undefined;
  const ja3 = TRUST_EDGE_HEADERS ? header(req, "x-ja3-hash") : undefined;
  const crawlerVerification = TRUST_EDGE_HEADERS
    ? header(req, "x-crawler-verification")
    : undefined;

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
      crawlerVerificationStatus: CRAWLER_STATUSES.has(crawlerVerification)
        ? crawlerVerification
        : undefined,
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
  const decisive = serverSignals.filter((signal) => !ADVISORY_SIGNALS.has(signal.id));
  const serverRejects =
    decisive.some((signal) => signal.score >= STRONG_SIGNAL_WEIGHT) ||
    decisive.length >= MIN_SUPPORTING_SIGNALS;

  const scores = [server.suspicionScore];
  if (instantValid) scores.push(instant.suspicionScore);
  if (behavioralValid) scores.push(behavioral.suspicionScore);
  if (clientSignals.length > 0) scores.push(combineScores(clientSignals.map((signal) => signal.score)));

  const score = combineScores(scores);
  const clientRejects = clientSignals.length > 0;
  const isAgent =
    clientRejects ||
    serverRejects ||
    (instantValid ? instant.suspicionScore >= INSTANT_SCORE_THRESHOLD : false) ||
    (behavioralValid ? behavioral.suspicionScore >= BEHAVIORAL_SCORE_THRESHOLD : false);

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
    notes: advisoryNotes.map((signal) => signal.id),
  };

  insertSubmission(record);

  sendJson(res, isAgent ? 403 : 200, {
    accepted: !isAgent,
    verdict: record.verdict,
    score: record.score,
    automationKind: record.automationKind,
    layers: record.layers,
    signals: record.signals,
    notes: record.notes,
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "GET" && url.pathname === "/api/challenge") {
    return sendJson(res, 200, createChallenge(req));
  }

  if (req.method === "POST" && url.pathname === "/api/submit") {
    return handleSubmit(req, res);
  }

  if (req.method === "GET" && url.pathname === "/api/submissions") {
    return sendJson(res, 200, {
      ...countByVerdict(),
      submissions: listSubmissions(LIST_LIMIT),
    });
  }

  if (req.method === "POST" && url.pathname === "/api/reset") {
    clearSubmissions();
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
});

await preloadIpLists();

server.listen(PORT, () => {
  console.log(`Form:      http://localhost:${PORT}/`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard.html`);
  console.log(`SQLite:    ${dbFile}`);
});
