import type {
  BehavioralSamples,
  BehavioralSignal,
  ButtonSample,
  ClickSample,
  ConfidenceLevel,
  KeyReleaseSample,
  KeySample,
  MouseSample,
  ScrollSample,
  TouchSample,
} from "./types.js";

/**
 * Behavioral heuristic tuning constants.
 *
 * These thresholds are empirical and chosen to balance detection of obvious
 * automation against common false positives (touch devices, high-DPI mice,
 * human variance, window re-entry, OS key repeat, etc.).
 *
 * They are intentionally not exposed as runtime options for the main API to
 * keep the surface small and the behavior predictable. Power users can copy
 * the analysis functions if they need to tune.
 */

/** Injected characters need a few samples before the ratio below means anything —
 * an emoji picker or a voice-typing snippet legitimately injects one or two. */
const MIN_INJECTED_KEYS = 5;

/** Share of printable keystrokes that must be injected before it reads as a
 * machine filling the field rather than a human reaching for an input tool. */
const INJECTED_KEY_RATIO = 0.6;

/** `VK_PACKET` — the virtual key Windows reports for `KEYEVENTF_UNICODE` input. */
const VK_PACKET = 231;

/** A reach shorter than this is too small to carry a readable path shape. */
const MIN_REACH_CHORD_PX = 60;

/** Fewer points than this and the fitted arc is describing noise. */
const MIN_REACH_POINTS = 10;

/** A gap this long means the pointer came to rest, ending the reach. */
const REACH_REST_MS = 180;

/** Reaches needed before a run of perfectly smooth arcs means anything. */
const MIN_GENERATED_REACHES = 3;

/** Deviation from the fitted arc, as a fraction of the chord, that still reads as
 * "generated from a curve" rather than produced by a hand. */
const MAX_GENERATED_ARC_RESIDUAL = 0.0025;

/** Excursion a wobble must reach before it counts as crossing the arc, so pixel
 * quantisation on a slow drag cannot manufacture crossings. */
const MIN_ARC_EXCURSION_PX = 0.75;

/** Below this a press is too quick for a finger to have lifted it. */
const MIN_CLICK_HOLD_MS = 40;

/** How many zero-jitter clicks must stack up before the run means anything. */
const MIN_ZERO_JITTER_CLICKS = 3;


/** How far back a mouse move or touch still explains a click */
const CLICK_ORIGIN_WINDOW_MS = 2_000;

/**
 * A finger cannot press and release a key inside this. Synthesisers that emit a
 * keystroke as one atomic action land near zero: a patched-Playwright agent
 * measured here held every key for a mean of 2.2ms while randomising the gaps
 * between them convincingly.
 */
const MIN_HUMAN_DWELL_MS = 25;

/** Enough paired keys that a short median is the generator, not a stray event. */
const MIN_DWELL_SAMPLES = 12;

/**
 * Median release-to-press gap at or under this is typing fast enough that hands
 * overlap keys. Slower than this is hunt-and-peck, where never overlapping is
 * perfectly human and proves nothing.
 */
const FAST_TYPING_FLIGHT_MS = 220;

/** Enough gaps at speed to expect at least one overlap from a real typist. */
const MIN_ROLLOVER_SAMPLES = 24;

/** Cursor jumps only count as teleports when they happen quickly — a large
 * gap means the pointer likely left and re-entered the window. */
const TELEPORT_MAX_ELAPSED_MS = 100;

/** Very fast teleport (implausible human reaction + distance). */
const TELEPORT_FAST_ELAPSED_MS = 20;
const TELEPORT_FAST_DISTANCE_PX = 200;
const TELEPORT_ANY_DISTANCE_PX = 600;

// Linearity is checked over every sliding sub-window as well as the whole
// trace, so a scripted burst can't hide inside replayed human noise by sitting
// at an off-grid offset.
const MOUSE_LINEAR_WINDOW = 14;
const SCROLL_LINEAR_WINDOW = 8;

/** Minimum samples required before we consider a trace for linearity. */
const MIN_MOUSE_FOR_LINEAR = 6;
const MIN_TOUCH_MOVES_FOR_LINEAR = 6;
const MIN_TAPS_FOR_LINEAR = 5;
const MIN_MOUSE_FOR_ZERO_DELTAS = 51;
const MIN_SCROLL_FOR_LINEAR = 4;
const MIN_KEYS_FOR_LINEAR = 5;

/** Coefficient of variation cutoffs for "too uniform". Lower = more robotic. */
const MOUSE_CV_SPEED_MAX = 0.08;
const SCROLL_CV_DELTA_MAX = 0.1;
const SCROLL_CV_INTERVAL_MAX = 0.12;
const TYPING_CV_INTERVAL_MAX = 0.08;

/**
 * Programmed "humanized" typing often loops a short delay template instead
 * of using one constant interval. Compare sliding windows at short lags so
 * that a repeated template is caught without treating ordinary variance as
 * automation.
 */
const TYPING_REPEAT_WINDOW = 12;
const TYPING_REPEAT_MIN_LAG = 2;
const TYPING_REPEAT_MAX_LAG = 6;
const TYPING_REPEAT_TOLERANCE_MS = 12;
const TYPING_REPEAT_MATCH_RATIO = 0.8;

/** Max perpendicular deviation (pixels) allowed for a "straight" mouse line. */
const MOUSE_MAX_LINE_DEVIATION = 4;

/** Typing faster than this average interval (ms) is considered superhuman. */
const TYPING_SUPERHUMAN_INTERVAL_MS = 25;

/** Tap rhythm cutoffs, mirroring the typing ones — a finger is no steadier. */
const TAP_CV_INTERVAL_MAX = 0.08;
const TAP_SUPERHUMAN_INTERVAL_MS = 25;

/**
 * Returns true if the whole trace, or any contiguous `window`-length slice of
 * it, satisfies `isLinear`. Sliding by one guarantees a linear run of at least
 * `window` samples is caught regardless of where it starts.
 */
function anyLinearWindow<T>(
  samples: T[],
  window: number,
  isLinear: (segment: T[]) => boolean,
): boolean {
  if (samples.length <= window) {
    return isLinear(samples);
  }

  for (let start = 0; start + window <= samples.length; start += 1) {
    if (isLinear(samples.slice(start, start + window))) {
      return true;
    }
  }

  return false;
}

function mean(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function coefficientOfVariation(values: number[]): number {
  const average = mean(values);
  if (average === 0) {
    return 0;
  }

  const variance =
    values.reduce((sum, value) => sum + (value - average) ** 2, 0) /
    values.length;

  return Math.sqrt(variance) / Math.abs(average);
}

/** Anything with a position and a timestamp — a mouse move or a touch move. */
interface PointSample {
  x: number;
  y: number;
  t: number;
}

function maxLineDeviation(points: PointSample[]): number {
  const start = points[0];
  const end = points[points.length - 1];
  const lineLength = Math.hypot(end.x - start.x, end.y - start.y);

  if (lineLength === 0) {
    return 0;
  }

  let maxDeviation = 0;

  for (const point of points) {
    const area = Math.abs(
      (end.x - start.x) * (start.y - point.y) -
        (start.x - point.x) * (end.y - start.y),
    );
    maxDeviation = Math.max(maxDeviation, area / lineLength);
  }

  return maxDeviation;
}

function createSignal(
  id: string,
  description: string,
  triggered: boolean,
  weight: number,
  confidence: ConfidenceLevel,
): BehavioralSignal {
  return {
    id,
    description,
    triggered,
    weight,
    confidence,
    score: triggered ? weight : 0,
  };
}

function isLinearPointerSegment(points: PointSample[]): boolean {
  const speeds: number[] = [];

  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    const elapsed = current.t - previous.t;

    if (elapsed <= 0) {
      continue;
    }

    speeds.push(
      Math.hypot(current.x - previous.x, current.y - previous.y) / elapsed,
    );
  }

  if (speeds.length < 5) {
    return false;
  }

  return coefficientOfVariation(speeds) < MOUSE_CV_SPEED_MAX && maxLineDeviation(points) < MOUSE_MAX_LINE_DEVIATION;
}

/**
 * Mouse path is a near-perfect line traversed at near-constant speed.
 * @internal
 */
export function hasLinearMouseMovement(mouseMoves: MouseSample[]): boolean {
  if (mouseMoves.length < MIN_MOUSE_FOR_LINEAR) {
    return false;
  }

  return anyLinearWindow(mouseMoves, MOUSE_LINEAR_WINDOW, isLinearPointerSegment);
}

/** More than 50 mouse events all report zero browser-provided movement deltas. */
export function hasZeroMouseMovementDeltas(mouseMoves: MouseSample[]): boolean {
  return mouseMoves.length >= MIN_MOUSE_FOR_ZERO_DELTAS &&
    mouseMoves.every(
      (event) => event.movementX === 0 && event.movementY === 0,
    );
}

/**
 * Cursor covered an implausible distance between closely-spaced events.
 * @internal
 */
function hasTeleport(points: PointSample[]): boolean {
  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    const elapsed = current.t - previous.t;

    if (elapsed > TELEPORT_MAX_ELAPSED_MS) {
      continue;
    }

    const distance = Math.hypot(current.x - previous.x, current.y - previous.y);

    if (elapsed <= TELEPORT_FAST_ELAPSED_MS && distance > TELEPORT_FAST_DISTANCE_PX) {
      return true;
    }

    if (distance > TELEPORT_ANY_DISTANCE_PX) {
      return true;
    }
  }

  return false;
}

export function hasTeleportMouse(mouseMoves: MouseSample[]): boolean {
  return hasTeleport(mouseMoves);
}

/**
 * Trusted clicks with `detail === 0` come from keyboard activation
 * (Enter/Space on a control) — not from a pointer. Untrusted clicks never
 * get this exemption: synthetic events also default to `detail: 0`.
 */
function isPointerClick(click: ClickSample): boolean {
  return !(click.isTrusted && click.detail === 0);
}

interface InputCoordinateSample {
  pageX?: number;
  pageY?: number;
  screenX?: number;
  screenY?: number;
  isFullscreen?: boolean;
  isTrusted: boolean;
}

function hasLeakedInputCoordinates(sample: InputCoordinateSample): boolean {
  return (
    sample.isTrusted &&
    sample.isFullscreen === false &&
    typeof sample.pageX === "number" &&
    typeof sample.pageY === "number" &&
    typeof sample.screenX === "number" &&
    typeof sample.screenY === "number" &&
    sample.pageX === sample.screenX &&
    sample.pageY === sample.screenY
  );
}

/**
 * Repeated trusted pointer events expose CDP Input's page/screen coordinate
 * equality. Fullscreen and keyboard-activated clicks are excluded.
 * @internal
 */
export function hasCdpInputCoordinateLeak(
  mouseMoves: MouseSample[],
  clicks: ClickSample[],
): boolean {
  const leaked = [
    ...mouseMoves,
    ...clicks.filter(isPointerClick),
  ].filter(hasLeakedInputCoordinates);
  const distinctPositions = new Set(
    leaked.map((sample) => `${sample.pageX},${sample.pageY}`),
  );
  return distinctPositions.size >= 2;
}

function hasRecentSample(
  samples: Array<{ t: number }>,
  at: number,
  windowMs: number,
): boolean {
  return samples.some((sample) => sample.t >= at - windowMs && sample.t <= at);
}

/**
 * A pointer click landed with no mouse or touch activity in the preceding 2s.
 * @internal
 */
export function hasClickWithoutMouseMovement(
  mouseMoves: MouseSample[],
  clicks: ClickSample[],
  touches: TouchSample[] = [],
): boolean {
  return clicks.some(
    (click) =>
      isPointerClick(click) &&
      !hasRecentSample(mouseMoves, click.t, CLICK_ORIGIN_WINDOW_MS) &&
      !hasRecentSample(touches, click.t, CLICK_ORIGIN_WINDOW_MS),
  );
}

/**
 * Pointer clicks were recorded in a session with zero mouse or touch events.
 * @internal
 */
export function hasNoMouseActivity(
  mouseMoves: MouseSample[],
  clicks: ClickSample[],
  touches: TouchSample[] = [],
): boolean {
  return (
    clicks.some(isPointerClick) &&
    mouseMoves.length === 0 &&
    touches.length === 0
  );
}

function isLinearScrollSegment(scrollEvents: ScrollSample[]): boolean {
  const deltas = scrollEvents.map((event) => Math.abs(event.deltaY));
  const intervals: number[] = [];

  for (let index = 1; index < scrollEvents.length; index += 1) {
    intervals.push(scrollEvents[index].t - scrollEvents[index - 1].t);
  }

  return (
    coefficientOfVariation(deltas) < SCROLL_CV_DELTA_MAX &&
    coefficientOfVariation(intervals) < SCROLL_CV_INTERVAL_MAX
  );
}

/**
 * Scroll deltas and inter-event timing are too uniform to be a human hand.
 * @internal
 */
export function hasLinearScroll(scrollEvents: ScrollSample[]): boolean {
  if (scrollEvents.length < MIN_SCROLL_FOR_LINEAR) {
    return false;
  }

  return anyLinearWindow(scrollEvents, SCROLL_LINEAR_WINDOW, isLinearScrollSegment);
}

/**
 * Keystroke rhythm is metronome-uniform or faster than humanly possible.
 * @internal
 */
export function hasLinearTyping(keyPresses: KeySample[]): boolean {
  // OS key auto-repeat is perfectly uniform and fast — only analyze
  // deliberate keystrokes.
  const deliberate = keyPresses.filter(
    (key) => !key.repeat && key.composing !== true,
  );

  if (deliberate.length < MIN_KEYS_FOR_LINEAR) {
    return false;
  }

  const intervals: number[] = [];

  for (let index = 1; index < deliberate.length; index += 1) {
    intervals.push(deliberate[index].t - deliberate[index - 1].t);
  }

  const intervalUniformity = coefficientOfVariation(intervals);
  const averageInterval = mean(intervals);

  return intervalUniformity < TYPING_CV_INTERVAL_MAX || averageInterval < TYPING_SUPERHUMAN_INTERVAL_MS;
}

function isRepeatedTypingWindow(intervals: number[]): boolean {
  for (let lag = TYPING_REPEAT_MIN_LAG; lag <= TYPING_REPEAT_MAX_LAG; lag += 1) {
    let matches = 0;
    let comparisons = 0;

    for (let index = lag; index < intervals.length; index += 1) {
      comparisons += 1;
      if (Math.abs(intervals[index] - intervals[index - lag]) <= TYPING_REPEAT_TOLERANCE_MS) {
        matches += 1;
      }
    }

    if (comparisons >= 6 && matches / comparisons >= TYPING_REPEAT_MATCH_RATIO) {
      return true;
    }
  }

  return false;
}

/**
 * A short delay template repeats across otherwise varied keystrokes.
 * This catches automation that evades the constant-cadence heuristic by
 * cycling through a handful of human-looking delays.
 * @internal
 */
export function hasRepeatedTypingCadence(keyPresses: KeySample[]): boolean {
  const deliberate = keyPresses.filter(
    (key) => !key.repeat && key.composing !== true,
  );
  if (deliberate.length < TYPING_REPEAT_WINDOW + 1) return false;

  const intervals: number[] = [];
  for (let index = 1; index < deliberate.length; index += 1) {
    intervals.push(deliberate[index].t - deliberate[index - 1].t);
  }

  for (
    let start = 0;
    start + TYPING_REPEAT_WINDOW <= intervals.length;
    start += 1
  ) {
    if (isRepeatedTypingWindow(intervals.slice(start, start + TYPING_REPEAT_WINDOW))) {
      return true;
    }
  }

  return false;
}

/** Samples without `kind` predate gesture analysis and were all contacts. */
function isTouchContact(touch: TouchSample): boolean {
  return touch.kind !== "move";
}

function isLocatedTouch(
  touch: TouchSample,
): touch is TouchSample & PointSample {
  return typeof touch.x === "number" && typeof touch.y === "number";
}

/**
 * Splits a touch stream into individual gestures. Each new contact starts a
 * fresh one, so a finger lifting and landing elsewhere — or a second finger
 * joining — never reads as one continuous path.
 */
function splitTouchGestures(touches: TouchSample[]): PointSample[][] {
  const gestures: PointSample[][] = [];
  let current: PointSample[] = [];

  for (const touch of touches) {
    if (isTouchContact(touch)) {
      if (current.length > 0) {
        gestures.push(current);
      }
      current = [];
    }
    if (isLocatedTouch(touch)) {
      current.push(touch);
    }
  }

  if (current.length > 0) {
    gestures.push(current);
  }

  return gestures;
}

/**
 * A swipe traced a near-perfect line at near-constant speed. Real fingers
 * arc and vary; a dispatched touch sequence interpolates.
 * @internal
 */
export function hasLinearTouchMovement(touches: TouchSample[] = []): boolean {
  return splitTouchGestures(touches).some(
    (gesture) =>
      gesture.length >= MIN_TOUCH_MOVES_FOR_LINEAR &&
      anyLinearWindow(gesture, MOUSE_LINEAR_WINDOW, isLinearPointerSegment),
  );
}

/**
 * A contact point jumped an implausible distance mid-gesture.
 * @internal
 */
export function hasTeleportTouch(touches: TouchSample[] = []): boolean {
  return splitTouchGestures(touches).some(hasTeleport);
}

/**
 * Taps land on a metronome, or faster than a finger can lift and fall.
 * @internal
 */
export function hasLinearTapRhythm(touches: TouchSample[] = []): boolean {
  const contacts = touches.filter(isTouchContact);

  if (contacts.length < MIN_TAPS_FOR_LINEAR) {
    return false;
  }

  const intervals: number[] = [];
  for (let index = 1; index < contacts.length; index += 1) {
    intervals.push(contacts[index].t - contacts[index - 1].t);
  }

  return (
    coefficientOfVariation(intervals) < TAP_CV_INTERVAL_MAX ||
    mean(intervals) < TAP_SUPERHUMAN_INTERVAL_MS
  );
}

/**
 * Any observed event was script-dispatched (`isTrusted === false`).
 * @internal
 */
/**
 * Detects text pushed in at the OS level rather than typed on a keyboard.
 *
 * `SendInput` with `KEYEVENTF_UNICODE` (and the AutoHotkey / AutoIt / PowerShell
 * wrappers around it) sets `wVk = 0` and carries the character in the scan-code
 * field, so Windows reports `VK_PACKET` and Chromium has no physical key to map:
 * `code` comes through empty and `keyCode` is `231`. Real hardware always names
 * the key it came from. The events are `isTrusted`, because the browser really
 * did receive them from the OS — this is the only layer that can tell them apart.
 *
 * Verified against Chrome 140 on Windows 11: injected `"K"` reports
 * `{ key: "K", code: "", keyCode: 231 }`, while a scan-code press of the same key
 * reports `{ key: "b", code: "KeyB", keyCode: 66 }`.
 *
 * A ratio rather than a flat count, so someone who picks one emoji or dictates a
 * word in an otherwise hand-typed form is not flagged for it.
 * @internal
 */
export function hasInjectedKeyInput(keyPresses: KeySample[]): boolean {
  const printable = keyPresses.filter(
    (key) =>
      key.isTrusted &&
      key.printable === true &&
      key.composing !== true &&
      key.repeat !== true &&
      key.code !== undefined,
  );

  if (printable.length === 0) {
    return false;
  }

  const injected = printable.filter(
    (key) => key.code === "" || key.keyCode === VK_PACKET || key.keyCode === 0,
  );

  return (
    injected.length >= MIN_INJECTED_KEYS &&
    injected.length / printable.length >= INJECTED_KEY_RATIO
  );
}

/**
 * A trusted contact in the 2s before the press means the browser synthesised it
 * from a finger, so its coordinates and hold time describe the touch stack
 * rather than a hand on a mouse.
 *
 * The window has to look backwards and be generous. Touch Events § "the user
 * agent must dispatch touchstart before any mouse event types for that action",
 * and the compatibility events arrive only once the finger lifts, so a contact
 * precedes its press by however long the tap was held. `CLICK_ORIGIN_WINDOW_MS`
 * is the span this file already uses to decide that a touch explains a click.
 * @internal
 */
function isTouchDerivedPress(down: ButtonSample, touches: TouchSample[]): boolean {
  return hasRecentSample(
    touches.filter((touch) => touch.isTrusted),
    down.t,
    CLICK_ORIGIN_WINDOW_MS,
  );
}

/** A press worth timing: a real, deliberate, physical key. */
function isTimeableKey(key: KeySample): boolean {
  return (
    key.isTrusted &&
    !key.repeat &&
    key.composing !== true &&
    typeof key.code === "string" &&
    key.code.length > 0
  );
}

/**
 * Presses matched to the release that ended them, in press order.
 *
 * Each release is consumed once, so a key held across another keystroke pairs
 * with its own release rather than the nearest one.
 * @internal
 */
function pairKeystrokes(
  keyPresses: KeySample[],
  keyReleases: KeyReleaseSample[],
): Array<{ down: number; up: number }> {
  const releases = keyReleases.filter(
    (release) =>
      release.isTrusted &&
      release.composing !== true &&
      typeof release.code === "string",
  );
  const taken = new Set<number>();
  const pairs: Array<{ down: number; up: number }> = [];

  for (const press of keyPresses.filter(isTimeableKey)) {
    const index = releases.findIndex(
      (release, at) =>
        !taken.has(at) && release.code === press.code && release.t >= press.t,
    );
    if (index === -1) continue;
    taken.add(index);
    pairs.push({ down: press.t, up: releases[index].t });
  }

  return pairs;
}

function medianOf(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

/**
 * Keys that were never really held down.
 *
 * Dwell time is the half of typing rhythm that evasion tooling forgets: an
 * agent can randomise the gaps between keystrokes into a convincing
 * distribution and still emit each key as an instantaneous press, because the
 * API it drives takes a character rather than a hold.
 * @internal
 */
export function hasSyntheticKeyDwell(
  keyPresses: KeySample[],
  keyReleases: KeyReleaseSample[] = [],
  touches: TouchSample[] = [],
): boolean {
  // A soft keyboard manufactures its own key events, so their hold time belongs
  // to the input method and says nothing about the hand using it.
  if (touches.length > 0) return false;

  const dwell = pairKeystrokes(keyPresses, keyReleases).map(
    (pair) => pair.up - pair.down,
  );
  if (dwell.length < MIN_DWELL_SAMPLES) return false;

  return medianOf(dwell) < MIN_HUMAN_DWELL_MS;
}

/**
 * Fast typing in which no two keys were ever down together.
 *
 * Hands overlap keys at speed — the next key goes down before the last one
 * comes up, which is why flight times in keystroke-dynamics data go negative.
 * A synthesiser stepping one discrete press at a time never does, however well
 * it randomises the intervals. Gated on speed, because hunt-and-peck typing
 * genuinely has no overlap.
 * @internal
 */
export function hasAbsentKeyRollover(
  keyPresses: KeySample[],
  keyReleases: KeyReleaseSample[] = [],
  touches: TouchSample[] = [],
): boolean {
  if (touches.length > 0) return false;

  const pairs = pairKeystrokes(keyPresses, keyReleases);
  if (pairs.length < MIN_ROLLOVER_SAMPLES) return false;

  const flights: number[] = [];
  for (let index = 1; index < pairs.length; index += 1) {
    flights.push(pairs[index].down - pairs[index - 1].up);
  }

  if (medianOf(flights) > FAST_TYPING_FLIGHT_MS) return false;

  return flights.every((flight) => flight > 0);
}

/**
 * Detects primary-button presses that no hand produced.
 *
 * `mouse_event(MOUSEEVENTF_LEFTDOWN)` followed by `MOUSEEVENTF_LEFTUP` releases
 * on the exact coordinate it pressed, and a scripted clicker often releases
 * within a few milliseconds. A hand resting on a mouse drifts, and takes tens of
 * milliseconds to lift, so a run of presses that does neither points at injection.
 *
 * Supporting evidence only: a steady hand on a low-DPI mouse can do this once or
 * twice, so this never decides a verdict on its own.
 * @internal
 */
export function hasZeroJitterClicks(
  buttons: ButtonSample[] | undefined,
  mouseMoves: MouseSample[],
  touches: TouchSample[] = [],
): boolean {
  const presses = (buttons ?? []).filter((button) => button.isTrusted);

  if (presses.length < MIN_ZERO_JITTER_CLICKS * 2) {
    return false;
  }

  let inhuman = 0;
  let measured = 0;

  for (let index = 1; index < presses.length; index += 1) {
    const up = presses[index];
    const down = presses[index - 1];

    if (down.kind !== "down" || up.kind !== "up") {
      continue;
    }

    // Touch Events requires a tap's compatibility events to be dispatched "at
    // the location of the touchend event", so press and release share one
    // coordinate by specification and the hold is the browser's, not a hand's.
    // Every tap therefore has zero jitter, and measuring one against a mouse
    // marks every touchscreen user as a machine.
    if (isTouchDerivedPress(down, touches)) {
      continue;
    }

    measured += 1;

    const heldMs = up.t - down.t;
    const movedWhileHeld = mouseMoves.some(
      (move) => move.isTrusted && move.t > down.t && move.t < up.t,
    );
    const samePoint =
      up.x === down.x &&
      up.y === down.y &&
      up.screenX === down.screenX &&
      up.screenY === down.screenY;

    // Two ways a press reads as machine-made: it releases on the pixel it
    // pressed, or it is gone before a finger could lift. Skipping the quick ones
    // entirely, as this check used to, just told a synthetic clicker to hurry.
    if (heldMs < MIN_CLICK_HOLD_MS || (samePoint && !movedWhileHeld)) {
      inhuman += 1;
    }
  }

  return measured >= MIN_ZERO_JITTER_CLICKS && inhuman === measured;
}

interface ChordFrame {
  chord: number;
  samples: Array<{ s: number; d: number }>;
}

/** Re-expresses a reach as progress along its straight chord plus perpendicular offset. */
function toChordFrame(points: MouseSample[]): ChordFrame | null {
  const first = points[0];
  const last = points[points.length - 1];
  const dx = last.x - first.x;
  const dy = last.y - first.y;
  const chord = Math.hypot(dx, dy);

  if (chord < MIN_REACH_CHORD_PX) {
    return null;
  }

  const ux = dx / chord;
  const uy = dy / chord;

  return {
    chord,
    samples: points.map((point) => {
      const rx = point.x - first.x;
      const ry = point.y - first.y;
      return { s: (rx * ux + ry * uy) / chord, d: rx * -uy + ry * ux };
    }),
  };
}

/** Splits pointer samples into reaches, breaking wherever the pointer rested. */
function toReaches(mouseMoves: MouseSample[]): MouseSample[][] {
  const trusted = mouseMoves.filter((move) => move.isTrusted);
  const reaches: MouseSample[][] = [];
  let current: MouseSample[] = [];

  for (let index = 0; index < trusted.length; index += 1) {
    const previous = trusted[index - 1];
    if (previous && trusted[index].t - previous.t > REACH_REST_MS) {
      if (current.length >= MIN_REACH_POINTS) reaches.push(current);
      current = [];
    }
    current.push(trusted[index]);
  }
  if (current.length >= MIN_REACH_POINTS) reaches.push(current);

  return reaches;
}

/**
 * Detects a pointer path that was drawn from a curve rather than produced by a hand.
 *
 * The standard way to "humanise" a bot is a quadratic Bezier with a random
 * perpendicular bow, eased timing, and jitter applied to the curve parameter. That
 * jitter slides each point *along* the curve; it never moves it off. So every
 * sample lands on one smooth convex arc, on one side of it, for the whole reach.
 *
 * A quadratic Bezier's offset from its chord is exactly `2t(1-t)·bow` — a parabola
 * in progress along the chord. Fitting that one-parameter shape and asking what is
 * left over separates the two: physiological tremor and the corrective
 * sub-movements at the end of a real reach push the pointer back and forth across
 * any such arc, repeatedly.
 *
 * Measured against the bypass scripts' own movement code: median residual 0.04% of
 * the chord and zero crossings across 18 reaches. The thresholds here sit well
 * clear of that, and several reaches must agree before the signal fires.
 * @internal
 */
export function hasGeneratedPointerPath(mouseMoves: MouseSample[]): boolean {
  const reaches = toReaches(mouseMoves);
  let generated = 0;
  let measured = 0;

  for (const reach of reaches) {
    const frame = toChordFrame(reach);
    if (!frame || frame.samples.length < MIN_REACH_POINTS) {
      continue;
    }

    let numerator = 0;
    let denominator = 0;
    for (const { s, d } of frame.samples) {
      const basis = s * (1 - s);
      numerator += d * basis;
      denominator += basis * basis;
    }
    if (denominator === 0) {
      continue;
    }

    measured += 1;
    const bow = numerator / denominator;

    let squared = 0;
    let crossings = 0;
    let sign = 0;
    let peak = 0;
    for (const { s, d } of frame.samples) {
      const residual = d - bow * s * (1 - s);
      squared += residual * residual;

      const current = Math.sign(residual);
      if (current === 0) continue;
      if (sign === 0) {
        sign = current;
        peak = Math.abs(residual);
      } else if (current === sign) {
        peak = Math.max(peak, Math.abs(residual));
      } else {
        if (peak >= MIN_ARC_EXCURSION_PX) crossings += 1;
        sign = current;
        peak = Math.abs(residual);
      }
    }

    const residual = Math.sqrt(squared / frame.samples.length) / frame.chord;
    if (crossings === 0 && residual <= MAX_GENERATED_ARC_RESIDUAL) {
      generated += 1;
    }
  }

  return measured >= MIN_GENERATED_REACHES && generated === measured;
}

export function hasSyntheticEvents(samples: BehavioralSamples): boolean {
  const events = [
    ...samples.mouseMoves,
    ...samples.scrolls,
    ...samples.keyPresses,
    ...samples.clicks,
    ...(samples.touches ?? []),
  ];

  return events.some((event) => !event.isTrusted);
}

/**
 * Evaluates every behavioral heuristic and returns the weighted signal list.
 * @internal
 */
export function buildBehavioralSignals(samples: BehavioralSamples): BehavioralSignal[] {
  const touches = samples.touches ?? [];

  return [
    createSignal(
      "no-mouse-activity",
      "Clicks were recorded without any mouse or touch activity",
      hasNoMouseActivity(samples.mouseMoves, samples.clicks, touches),
      0.2,
      "low",
    ),
    createSignal(
      "click-without-mouse-movement",
      "At least one click had no recent mouse or touch activity",
      hasClickWithoutMouseMovement(samples.mouseMoves, samples.clicks, touches),
      0.35,
      "high",
    ),
    createSignal(
      "linear-mouse-movement",
      "Mouse path is unusually straight with uniform speed",
      hasLinearMouseMovement(samples.mouseMoves),
      0.25,
      "medium",
    ),
    createSignal(
      "zero-mouse-movement-deltas",
      "More than 50 mouse events all reported zero movement deltas",
      hasZeroMouseMovementDeltas(samples.mouseMoves),
      0.3,
      "medium",
    ),
    createSignal(
      "cdp-input-coordinate-leak",
      "Repeated trusted pointer events exposed identical page and screen coordinates",
      hasCdpInputCoordinateLeak(samples.mouseMoves, samples.clicks),
      0.2,
      "low",
    ),
    createSignal(
      "teleport-mouse",
      "Mouse position jumped implausibly between events",
      hasTeleportMouse(samples.mouseMoves),
      0.4,
      "high",
    ),
    createSignal(
      "linear-touch-movement",
      "Swipe path is unusually straight with uniform speed",
      hasLinearTouchMovement(touches),
      0.25,
      "medium",
    ),
    createSignal(
      "teleport-touch",
      "Touch point jumped implausibly mid-gesture",
      hasTeleportTouch(touches),
      0.4,
      "high",
    ),
    createSignal(
      "linear-tap-rhythm",
      "Tap intervals are robotic or superhuman",
      hasLinearTapRhythm(touches),
      0.3,
      "medium",
    ),
    createSignal(
      "linear-scroll",
      "Scroll deltas and timing are overly uniform",
      hasLinearScroll(samples.scrolls),
      0.3,
      "medium",
    ),
    createSignal(
      "linear-typing",
      "Typing intervals are robotic or superhuman",
      hasLinearTyping(samples.keyPresses),
      0.35,
      "high",
    ),
    createSignal(
      "repeated-typing-cadence",
      "Typing reused a short programmed delay pattern",
      hasRepeatedTypingCadence(samples.keyPresses),
      0.55,
      "high",
    ),
    createSignal(
      "generated-pointer-path",
      "Pointer reaches trace a generated curve instead of a hand's path",
      hasGeneratedPointerPath(samples.mouseMoves),
      0.6,
      "high",
    ),
    createSignal(
      "injected-key-input",
      "Text was injected at the OS level instead of typed on a keyboard",
      hasInjectedKeyInput(samples.keyPresses),
      0.7,
      "high",
    ),
    createSignal(
      "zero-jitter-clicks",
      "Every measured click released on the exact pixel it pressed, or too fast to be a finger",
      hasZeroJitterClicks(samples.buttons, samples.mouseMoves, touches),
      0.3,
      "medium",
    ),
    createSignal(
      "synthetic-key-dwell",
      "Keys were released as fast as they were pressed, with no hold a finger could make",
      hasSyntheticKeyDwell(samples.keyPresses, samples.keyReleases, touches),
      0.6,
      "high",
    ),
    createSignal(
      "absent-key-rollover",
      "Typing was fast yet no two keys were ever down together",
      hasAbsentKeyRollover(samples.keyPresses, samples.keyReleases, touches),
      0.3,
      "medium",
    ),
    createSignal(
      "synthetic-events",
      "Observed pointer or keyboard events were not trusted",
      hasSyntheticEvents(samples),
      0.5,
      "high",
    ),
  ];
}
