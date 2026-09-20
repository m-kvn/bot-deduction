import { decideVerdict } from "./verdict.mjs";

const cases = [
  { name: "REPORTED RUN: 0.30 instant + 0.30 behavioral + 0.35 server",
    want: "agent",
    input: { instantScore: 0.30, behavioralScore: 0.30, serverScore: 0.35, decisiveServerScores: [0.35] } },

  { name: "clean human on a home connection",
    want: "human",
    input: { instantScore: 0, behavioralScore: 0, serverScore: 0 } },

  { name: "human on corporate VPN, no webcam (datacenter + missing media)",
    want: "human",
    input: { instantScore: 0.30, behavioralScore: 0, serverScore: 0.35, decisiveServerScores: [0.35] } },

  { name: "human on VPN, no webcam, straight trackpad path (0.25 behavioral)",
    want: "??",
    input: { instantScore: 0.30, behavioralScore: 0.25, serverScore: 0.35, decisiveServerScores: [0.35] } },

  { name: "my tailnet smoke test (behavioral 0.475 only)",
    want: "human",
    input: { instantScore: 0, behavioralScore: 0.475, serverScore: 0 } },

  { name: "datacenter IP alone (one decisive server signal)",
    want: "human",
    input: { instantScore: 0, behavioralScore: 0, serverScore: 0.35, decisiveServerScores: [0.35] } },

  { name: "single layer, high score (behavioral 0.7, nothing else)",
    want: "agent",
    input: { instantScore: 0, behavioralScore: 0.7, serverScore: 0 } },

  { name: "any hard client gate",
    want: "agent",
    input: { instantScore: 0, behavioralScore: 0, serverScore: 0, clientSignalScores: [0.9] } },
];

console.log("case".padEnd(62), "score".padEnd(7), "layers", "verdict", " expected");
console.log("-".repeat(100));
let bad = 0;
for (const c of cases) {
  const r = decideVerdict(c.input);
  const got = r.isAgent ? "agent" : "human";
  const flag = c.want === "??" ? "  <- trade-off" : got === c.want ? "" : "   MISMATCH";
  if (c.want !== "??" && got !== c.want) bad += 1;
  console.log(
    c.name.padEnd(62),
    r.score.toFixed(3).padEnd(7),
    String(r.corroboratingLayers).padEnd(6),
    got.padEnd(7),
    (c.want === "??" ? "-" : c.want).padEnd(6),
    flag,
  );
}
console.log("-".repeat(100));
console.log(bad === 0 ? "all expectations met" : `${bad} mismatches`);
