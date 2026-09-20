const form = document.getElementById("contact-form");
const resultBox = document.getElementById("result");
const chipInstant = document.getElementById("chip-instant");
const chipBehavioral = document.getElementById("chip-behavioral");

let instantResult = null;
let behavioralResult = null;
let challengeReady = requestChallenge();

const interaction = {
  trustedBeforeInputEvents: 0,
  trustedInputEvents: 0,
  trustedChangeEvents: 0,
  trustedFocusEvents: 0,
  untrustedFormEvents: 0,
  printableKeyEvents: 0,
  injectedKeyEvents: 0,
  typedCharacters: 0,
  bulkInsertedCharacters: 0,
  editedFields: new Set(),
  submitIntent: null,
};

const detector = BotSignal.createBehavioralClientDetector({
  context: window,
  scoreThreshold: 0.5,
  sampleWindowMs: 60_000,
  pollIntervalMs: 1000,
  onUpdate(result) {
    behavioralResult = result;
    paintChip(chipBehavioral, "behavioral", result.suspicionScore, result.isLegitClient);
  },
});
detector.start();
startTelemetry();

const encoder = new TextEncoder();

// A synchronous SHA-256, because the proof of work needs tens of thousands of
// digests and crypto.subtle only offers a promise per call — the await overhead
// dwarfs the hashing and pushes a 16-bit puzzle past ten seconds.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W = new Uint32Array(64);

function sha256(bytes) {
  const len = bytes.length;
  const withPad = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(withPad);
  buf.set(bytes);
  buf[len] = 0x80;
  const bits = len * 8;
  buf[withPad - 4] = (bits >>> 24) & 0xff;
  buf[withPad - 3] = (bits >>> 16) & 0xff;
  buf[withPad - 2] = (bits >>> 8) & 0xff;
  buf[withPad - 1] = bits & 0xff;

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  for (let off = 0; off < withPad; off += 64) {
    for (let i = 0; i < 16; i += 1) {
      W[i] = (buf[off + i * 4] << 24) | (buf[off + i * 4 + 1] << 16) | (buf[off + i * 4 + 2] << 8) | buf[off + i * 4 + 3];
    }
    for (let i = 16; i < 64; i += 1) {
      const a = W[i - 15], b = W[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i += 1) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  const out = new Uint8Array(32);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i += 1) {
    out[i * 4] = (hs[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (hs[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (hs[i] >>> 8) & 0xff;
    out[i * 4 + 3] = hs[i] & 0xff;
  }
  return out;
}

function leadingZeroBits(bytes) {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function solveProofOfWork(pow) {
  if (!pow) return "";
  for (let nonce = 0; ; nonce += 1) {
    if (leadingZeroBits(sha256(encoder.encode(`${pow.prefix}:${nonce}`))) >= pow.difficulty) {
      return String(nonce);
    }
  }
}

// Beacons carry almost nothing. Their job is to let the server timestamp, on its
// own clock, the fact that this session was alive and reporting — so a payload
// claiming a long observation window has to have been collected over one.
let telemetryNonce = null;
let telemetryTimer = null;

async function sendBeacon() {
  if (!telemetryNonce) return;
  try {
    const response = await fetch("/api/telemetry", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: telemetryNonce,
        events: detector.getSamples().mouseMoves.length + detector.getSamples().keyPresses.length,
        lastT: Date.now(),
      }),
    });
    const data = await response.json();
    if (data.nonce) telemetryNonce = data.nonce;
  } catch {
    // A dropped beacon is not fatal; the next one re-establishes the chain.
  }
}

async function startTelemetry() {
  const response = await fetch("/api/telemetry", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: null }),
  });
  const data = await response.json();
  telemetryNonce = data.nonce ?? null;
  if (!telemetryNonce) return;
  telemetryTimer = setInterval(sendBeacon, data.intervalMs ?? 3000);
}

async function requestChallenge() {
  const response = await fetch("/api/challenge", { cache: "no-store" });
  if (!response.ok) throw new Error(`challenge request failed: ${response.status}`);
  return response.json();
}

async function takeFreshChallenge() {
  let challenge = await challengeReady;
  if (Date.parse(challenge.expiresAt) - Date.now() < 10_000) {
    challenge = await requestChallenge();
  }
  challengeReady = requestChallenge();
  return challenge;
}

function fieldName(event) {
  const target = event.target;
  return target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement
    ? target.name
    : null;
}

function isSubmitControl(target) {
  return (
    target instanceof Element &&
    Boolean(target.closest('button[type="submit"], input[type="submit"]'))
  );
}

// A keyboard delivers one character per `insertText`. Automation that sets a
// field's value in one call — Playwright's fill(), CDP Input.insertText, and the
// element.value assignments behind most form bots — delivers the whole string in
// a single event with no keystroke behind it. Paste, autofill, drag and IME
// commits all carry their own inputType and are not counted here.
function recordInsertion(event) {
  if (event.isComposing) return;
  const inserted = typeof event.data === "string" ? [...event.data].length : 0;
  if (inserted === 0 || event.inputType !== "insertText") return;
  if (inserted === 1) interaction.typedCharacters += 1;
  else interaction.bulkInsertedCharacters += inserted;
}

function recordEditEvent(event) {
  if (!event.isTrusted) {
    interaction.untrustedFormEvents += 1;
    return;
  }

  if (event.type === "beforeinput") recordInsertion(event);

  const name = fieldName(event);
  if (event.type === "beforeinput") interaction.trustedBeforeInputEvents += 1;
  if (event.type === "input") interaction.trustedInputEvents += 1;
  if (event.type === "change") interaction.trustedChangeEvents += 1;
  if (name && (event.type === "input" || event.type === "change")) {
    interaction.editedFields.add(name);
  }
}

for (const type of ["beforeinput", "input", "change"]) {
  form.addEventListener(type, recordEditEvent, true);
}

form.addEventListener(
  "keydown",
  (event) => {
    if (!event.isTrusted || event.isComposing || event.repeat) return;
    if (typeof event.key !== "string" || [...event.key].length !== 1) return;
    interaction.printableKeyEvents += 1;
    if (event.code === "" || event.keyCode === 231 || event.keyCode === 0) {
      interaction.injectedKeyEvents += 1;
    }
  },
  true,
);

form.addEventListener(
  "focusin",
  (event) => {
    if (event.isTrusted) interaction.trustedFocusEvents += 1;
    else interaction.untrustedFormEvents += 1;
  },
  true,
);

form.addEventListener(
  "pointerdown",
  (event) => {
    if (!isSubmitControl(event.target)) return;
    if (event.isTrusted) {
      interaction.submitIntent = { type: "pointer", at: performance.now() };
    } else {
      interaction.untrustedFormEvents += 1;
    }
  },
  true,
);

form.addEventListener(
  "click",
  (event) => {
    if (!isSubmitControl(event.target)) return;
    if (event.isTrusted && !interaction.submitIntent) {
      interaction.submitIntent = {
        type: event.detail === 0 ? "keyboard" : "pointer",
        at: performance.now(),
      };
    } else if (!event.isTrusted) {
      interaction.untrustedFormEvents += 1;
    }
  },
  true,
);

form.addEventListener(
  "keydown",
  (event) => {
    const keyboardSubmit =
      event.key === "Enter" ||
      ((event.key === " " || event.key === "Spacebar") && isSubmitControl(event.target));
    if (!keyboardSubmit) return;
    if (event.isTrusted) {
      interaction.submitIntent = { type: "keyboard", at: performance.now() };
    } else {
      interaction.untrustedFormEvents += 1;
    }
  },
  true,
);

const instantReady = BotSignal.detectInstantClientAsync(window).then((result) => {
  instantResult = result;
  paintChip(chipInstant, "instant", result.suspicionScore, result.isLegitClient);
  return result;
});

function paintChip(node, label, score, isLegit) {
  node.textContent = `${label}: ${score.toFixed(2)} ${isLegit ? "human" : "agent"}`;
  node.className = `chip ${isLegit ? "ok" : "bad"}`;
}

function slim(result) {
  return {
    suspicionScore: result.suspicionScore,
    isLegitClient: result.isLegitClient,
    confidence: result.confidence,
    automation: result.automation,
    signals: result.signals.filter((signal) => signal.triggered),
  };
}

const SAMPLE_LIMITS = {
  mouseMoves: 600,
  scrolls: 200,
  keyPresses: 400,
  clicks: 60,
  touches: 200,
  buttons: 120,
  keyReleases: 400,
};

function slimSamples(samples) {
  const take = (stream, limit) => (Array.isArray(stream) ? stream.slice(-limit) : []);
  return {
    mouseMoves: take(samples.mouseMoves, SAMPLE_LIMITS.mouseMoves),
    scrolls: take(samples.scrolls, SAMPLE_LIMITS.scrolls),
    keyPresses: take(samples.keyPresses, SAMPLE_LIMITS.keyPresses),
    clicks: take(samples.clicks, SAMPLE_LIMITS.clicks),
    touches: take(samples.touches, SAMPLE_LIMITS.touches),
    buttons: take(samples.buttons, SAMPLE_LIMITS.buttons),
    keyReleases: take(samples.keyReleases, SAMPLE_LIMITS.keyReleases),
    observationMs: samples.observationMs,
  };
}

function slimBehavioral(result) {
  return {
    suspicionScore: result.suspicionScore,
    isLegitClient: result.isLegitClient,
    confidence: result.confidence,
    sampleCounts: result.sampleCounts,
    observationMs: result.observationMs,
    signals: result.signals.filter((signal) => signal.triggered),
  };
}

function render(data) {
  const isAgent = data.verdict === "agent";
  const notes = new Set(data.notes ?? []);
  const decisiveSignals = data.signals.filter(
    (signal) => !(signal.layer === "server" && notes.has(signal.id)),
  );

  resultBox.className = `result ${isAgent ? "bad" : "ok"}`;
  resultBox.replaceChildren();

  const heading = document.createElement("h2");
  heading.textContent = `${isAgent ? "Agent / bot detected" : "Human"} — score ${data.score.toFixed(2)}`;
  resultBox.appendChild(heading);

  const layers = document.createElement("p");
  layers.className = "muted";
  const layerSummary = [
    `instant ${data.layers.instant ? data.layers.instant.score.toFixed(2) : "n/a"}`,
    `behavioral ${data.layers.behavioral ? data.layers.behavioral.score.toFixed(2) : "n/a"}`,
    `server ${data.layers.server.score.toFixed(2)}`,
  ];
  if (data.automationKind) layerSummary.push(`looks like ${data.automationKind}`);
  layers.textContent = layerSummary.join(" · ");
  resultBox.appendChild(layers);

  if (decisiveSignals.length > 0) {
    const list = document.createElement("ul");
    for (const signal of decisiveSignals) {
      const item = document.createElement("li");
      const layer = document.createElement("code");
      layer.textContent = signal.layer;
      const score = document.createElement("span");
      score.className = "muted";
      score.textContent = ` (${signal.score.toFixed(2)})`;
      item.append(layer, ` ${signal.description}`, score);
      list.appendChild(item);
    }
    resultBox.appendChild(list);
  } else {
    const clean = document.createElement("p");
    clean.className = "muted";
    clean.textContent = "No suspicious signals triggered.";
    resultBox.appendChild(clean);
  }

  if (notes.size > 0) {
    const advisory = document.createElement("p");
    advisory.className = "muted";
    advisory.textContent = `Advisory only (travel / VPN / GeoIP drift): ${[...notes].join(", ")}`;
    resultBox.appendChild(advisory);
  }

  const linkRow = document.createElement("p");
  const link = document.createElement("a");
  link.className = "link";
  link.href = "./dashboard.html";
  link.textContent = "See it on the dashboard →";
  linkRow.appendChild(link);
  resultBox.appendChild(linkRow);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!event.isTrusted) interaction.untrustedFormEvents += 1;
  behavioralResult = detector.getResult();
  const instant = instantResult ?? (await instantReady);
  const challenge = await takeFreshChallenge();
  const powNonce = solveProofOfWork(challenge.pow);
  const submitIntentAgeMs = interaction.submitIntent
    ? Math.max(0, performance.now() - interaction.submitIntent.at)
    : null;

  const payload = {
    form: Object.fromEntries(new FormData(form)),
    challengeToken: challenge.token,
    powNonce,
    client: {
      instant: slim(instant),
      behavioral: slimBehavioral(behavioralResult),
      samples: slimSamples(detector.getSamples()),
      userAgent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      languages: Array.from(navigator.languages ?? []),
      platform: navigator.platform,
      interaction: {
        observationMs: behavioralResult.observationMs,
        trustedBeforeInputEvents: interaction.trustedBeforeInputEvents,
        trustedInputEvents: interaction.trustedInputEvents,
        trustedChangeEvents: interaction.trustedChangeEvents,
        trustedFocusEvents: interaction.trustedFocusEvents,
        editedFields: [...interaction.editedFields],
        submitEventTrusted: event.isTrusted,
        submitIntentTrusted: Boolean(interaction.submitIntent),
        submitIntentType: interaction.submitIntent?.type ?? null,
        submitIntentAgeMs,
        untrustedFormEvents: interaction.untrustedFormEvents,
        printableKeyEvents: interaction.printableKeyEvents,
        injectedKeyEvents: interaction.injectedKeyEvents,
        typedCharacters: interaction.typedCharacters,
        bulkInsertedCharacters: interaction.bulkInsertedCharacters,
      },
    },
  };

  const response = await fetch("/api/submit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  render(await response.json());
});
