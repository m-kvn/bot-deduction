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

function recordEditEvent(event) {
  if (!event.isTrusted) {
    interaction.untrustedFormEvents += 1;
    return;
  }

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
  const submitIntentAgeMs = interaction.submitIntent
    ? Math.max(0, performance.now() - interaction.submitIntent.at)
    : null;

  const payload = {
    form: Object.fromEntries(new FormData(form)),
    challengeToken: challenge.token,
    client: {
      instant: slim(instant),
      behavioral: slimBehavioral(behavioralResult),
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
