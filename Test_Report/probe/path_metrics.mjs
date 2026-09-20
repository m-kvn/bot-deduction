// Motor-control metrics for a pointer path.
//
// Every "humanized" bot in the bypass set moves the same way: a quadratic Bezier
// with one random perpendicular bow, smoothstep easing, and jitter applied to the
// curve *parameter* rather than to position. Jittering t slides the point along
// the curve — it never moves it off. So every sample lies on a single convex arc.
//
// A hand does not do that. Physiological tremor and corrective sub-movements push
// the pointer off any smooth arc repeatedly, and a reach that overshoots comes
// back. These two measures capture that difference without caring about timing,
// which is the part a bot can trivially randomise.

/** Perpendicular offset of each point from the straight chord, and progress along it. */
function chordFrame(points) {
  const first = points[0];
  const last = points[points.length - 1];
  const dx = last.x - first.x;
  const dy = last.y - first.y;
  const chord = Math.hypot(dx, dy);
  if (chord < 1) return null;

  const ux = dx / chord;
  const uy = dy / chord;

  return {
    chord,
    samples: points.map((point) => {
      const rx = point.x - first.x;
      const ry = point.y - first.y;
      return {
        s: (rx * ux + ry * uy) / chord,
        d: rx * -uy + ry * ux,
      };
    }),
  };
}

/**
 * How far the path sits from the single bowed arc that best explains it.
 *
 * A quadratic Bezier's perpendicular offset is exactly `2t(1-t)·bow` — a parabola
 * in the progress along the chord. Fitting that one-parameter shape and measuring
 * what is left over separates "generated from a curve" from "produced by a hand".
 * Returned as a fraction of the chord so it does not depend on how far the pointer
 * travelled.
 */
export function arcResidual(points) {
  const frame = chordFrame(points);
  if (!frame || frame.samples.length < 8) return null;

  let numerator = 0;
  let denominator = 0;
  for (const { s, d } of frame.samples) {
    const basis = s * (1 - s);
    numerator += d * basis;
    denominator += basis * basis;
  }
  if (denominator === 0) return null;

  const bow = numerator / denominator;
  let squared = 0;
  for (const { s, d } of frame.samples) {
    const residual = d - bow * s * (1 - s);
    squared += residual * residual;
  }

  return Math.sqrt(squared / frame.samples.length) / frame.chord;
}

/**
 * How often the path crosses back over that arc.
 *
 * Tremor and correction make a hand weave either side of the smooth curve; a
 * generated Bezier stays on one side of it for the whole reach. Crossings are
 * counted only when the excursion is big enough to outrun pixel quantisation.
 */
export function arcCrossings(points, minExcursionPx = 0.75) {
  const frame = chordFrame(points);
  if (!frame || frame.samples.length < 8) return null;

  let numerator = 0;
  let denominator = 0;
  for (const { s, d } of frame.samples) {
    const basis = s * (1 - s);
    numerator += d * basis;
    denominator += basis * basis;
  }
  if (denominator === 0) return null;
  const bow = numerator / denominator;

  let crossings = 0;
  let sign = 0;
  let peak = 0;
  for (const { s, d } of frame.samples) {
    const residual = d - bow * s * (1 - s);
    const current = Math.sign(residual);
    if (current === 0) continue;
    if (sign === 0) {
      sign = current;
      peak = Math.abs(residual);
      continue;
    }
    if (current === sign) {
      peak = Math.max(peak, Math.abs(residual));
      continue;
    }
    if (peak >= minExcursionPx) crossings += 1;
    sign = current;
    peak = Math.abs(residual);
  }

  return crossings;
}

/** Splits a stream of points into reaches, breaking wherever the pointer rested. */
export function splitReaches(points, restMs = 180, minPoints = 10, minChordPx = 60) {
  const reaches = [];
  let current = [];

  for (let index = 0; index < points.length; index += 1) {
    const point = points[index];
    const previous = points[index - 1];
    if (previous && point.t - previous.t > restMs) {
      if (current.length >= minPoints) reaches.push(current);
      current = [];
    }
    current.push(point);
  }
  if (current.length >= minPoints) reaches.push(current);

  return reaches.filter((reach) => {
    const dx = reach[reach.length - 1].x - reach[0].x;
    const dy = reach[reach.length - 1].y - reach[0].y;
    return Math.hypot(dx, dy) >= minChordPx;
  });
}

export function summarise(label, points) {
  const reaches = splitReaches(points);
  const residualsPx = [];
  const crossings = [];
  const rows = [];
  for (const reach of reaches) {
    const residual = arcResidual(reach);
    const crossing = arcCrossings(reach);
    if (residual === null || crossing === null) continue;
    const dx = reach[reach.length - 1].x - reach[0].x;
    const dy = reach[reach.length - 1].y - reach[0].y;
    const chord = Math.hypot(dx, dy);
    residualsPx.push(residual * chord);
    crossings.push(crossing);
    rows.push(
      `    chord=${chord.toFixed(0).padStart(4)}px  pts=${String(reach.length).padStart(3)}` +
        `  residual=${(residual * chord).toFixed(2)}px  crossings=${crossing}`,
    );
  }
  if (residualsPx.length === 0) return `${label}: no usable reaches (points=${points.length})`;

  const median = (list) => [...list].sort((a, b) => a - b)[Math.floor(list.length / 2)];
  return [
    `${label}:`,
    `  points=${points.length} reaches=${rows.length}`,
    `  arc residual  median=${median(residualsPx).toFixed(2)}px  min=${Math.min(...residualsPx).toFixed(2)}px  max=${Math.max(...residualsPx).toFixed(2)}px`,
    `  arc crossings median=${median(crossings)}  min=${Math.min(...crossings)}  max=${Math.max(...crossings)}`,
    ...rows,
  ].join(String.fromCharCode(10));
}
