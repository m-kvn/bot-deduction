/**
 * The agent/human decision, kept separate from the request handling so it can be
 * exercised directly.
 *
 * It lives in its own file because of a specific failure: per-layer thresholds
 * alone let a careful client spread its evidence so that no single layer crosses
 * the bar. A session scoring 0.30 instant, 0.30 behavioral and 0.35 server is
 * three independent tells and a combined 0.68, and the old rule called it human
 * because it only ever compared each layer against its own threshold. The
 * combined score was computed, recorded and displayed, and nothing read it.
 */

export const INSTANT_SCORE_THRESHOLD = 0.5;
export const BEHAVIORAL_SCORE_THRESHOLD = 0.5;

/** A single sub-0.5 server signal describes plenty of real people on VPNs. */
export const STRONG_SIGNAL_WEIGHT = 0.5;
export const MIN_SUPPORTING_SIGNALS = 2;

export const AGGREGATE_SCORE_THRESHOLD = Number(process.env.AGGREGATE_SCORE_THRESHOLD ?? 0.6);
export const MIN_CORROBORATING_LAYERS = Number(process.env.MIN_CORROBORATING_LAYERS ?? 2);

/**
 * Not every 0.30 is worth the same.
 *
 * "This desktop has no webcam" and "this address is a datacenter" describe an
 * environment that millions of real people are sitting in. "Every click released
 * on the pixel it pressed" describes how the input was produced, which is a
 * statement about the session rather than the machine. When the evidence includes
 * at least one of the latter, less of it is needed — so a run that spreads two
 * tells across an environment layer and a behavioural one still gets caught,
 * while a VPN user without a webcam keeps the higher bar.
 */
export const AGGREGATE_BEHAVIORAL_THRESHOLD = Number(
  process.env.AGGREGATE_BEHAVIORAL_THRESHOLD ?? 0.5,
);

/**
 * Evidence that a person essentially cannot produce: an automation driver
 * announcing itself, events the page itself synthesised, text that arrived with
 * no keystroke behind it, or a protocol-level gate the browser could not have
 * failed honestly.
 *
 * Everything else is circumstantial. A GPU string that does not match the
 * platform is a virtual machine, a remote desktop or a browser started with
 * --disable-gpu. Rhythmic typing is a touch typist. Clicks that release on the
 * pixel they pressed are tap-to-click on a trackpad. Each of those is worth
 * noting and none of them is worth calling someone a robot over on its own, so a
 * verdict built only from them is held for review rather than refused outright.
 */
export const HARD_SIGNAL_IDS = new Set([
  "isWebDriver",
  "isWebDriverInWorker",
  "isSuspiciousWebDriverDescriptor",
  "isPlaywright",
  "isPuppeteer",
  "isChromeDriver",
  "isSelenium",
  "isPhantomJS",
  "isNightmare",
  "isDomAutomation",
  "isAutomationArtifacts",
  "isHeadless",
  "isErrorStackAutomation",
  "isNativeFunctionTampered",
  "synthetic-events",
  "injected-key-input",
  // A median key hold under 25ms is a claim about physiology, not circumstance:
  // the check already stands down for soft keyboards, IME composition and auto
  // repeat, so what is left is a key that was never actually held.
  "synthetic-key-dwell",
]);

/** True when any triggered signal is something a person could not have produced. */
export function hasHardEvidence(signalIds = [], clientSignalScores = []) {
  return clientSignalScores.length > 0 || signalIds.some((id) => HARD_SIGNAL_IDS.has(id));
}

/** Independent-probability union: extra evidence always raises the score, never past 1. */
export function combineScores(scores) {
  return 1 - scores.reduce((accumulator, score) => accumulator * (1 - score), 1);
}

/**
 * @param {object} input
 * @param {number|null} input.instantScore     null when the layer was absent or malformed
 * @param {number|null} input.behavioralScore  null when the layer was absent or malformed
 * @param {number} input.serverScore
 * @param {number[]} input.clientSignalScores  hard gates — any one of these rejects
 * @param {number[]} input.decisiveServerScores server signals excluding advisory notes
 */
export function decideVerdict({
  instantScore = null,
  behavioralScore = null,
  serverScore = 0,
  clientSignalScores = [],
  decisiveServerScores = [],
}) {
  const scores = [serverScore];
  if (instantScore !== null) scores.push(instantScore);
  if (behavioralScore !== null) scores.push(behavioralScore);
  if (clientSignalScores.length > 0) scores.push(combineScores(clientSignalScores));

  const score = combineScores(scores);

  const clientRejects = clientSignalScores.length > 0;
  const serverRejects =
    decisiveServerScores.some((value) => value >= STRONG_SIGNAL_WEIGHT) ||
    decisiveServerScores.length >= MIN_SUPPORTING_SIGNALS;

  // Only layers that actually put something on the table count, and the advisory
  // server notes for travellers and VPN users are already excluded upstream.
  const corroboratingLayers = [
    clientSignalScores.length > 0,
    instantScore !== null && instantScore > 0,
    behavioralScore !== null && behavioralScore > 0,
    decisiveServerScores.length > 0,
  ].filter(Boolean).length;

  // Evidence about how the session behaved, as opposed to what machine it is on.
  const hasConductEvidence =
    clientSignalScores.length > 0 || (behavioralScore !== null && behavioralScore > 0);
  const aggregateThreshold = hasConductEvidence
    ? AGGREGATE_BEHAVIORAL_THRESHOLD
    : AGGREGATE_SCORE_THRESHOLD;
  const aggregateRejects =
    score >= aggregateThreshold && corroboratingLayers >= MIN_CORROBORATING_LAYERS;

  const isAgent =
    clientRejects ||
    serverRejects ||
    aggregateRejects ||
    (instantScore !== null ? instantScore >= INSTANT_SCORE_THRESHOLD : false) ||
    (behavioralScore !== null ? behavioralScore >= BEHAVIORAL_SCORE_THRESHOLD : false);

  return {
    isAgent,
    score,
    corroboratingLayers,
    reasons: {
      clientRejects,
      serverRejects,
      aggregateRejects,
      instantRejects: instantScore !== null && instantScore >= INSTANT_SCORE_THRESHOLD,
      behavioralRejects: behavioralScore !== null && behavioralScore >= BEHAVIORAL_SCORE_THRESHOLD,
    },
  };
}
