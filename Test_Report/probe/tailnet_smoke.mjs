import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
const base = process.env.TARGET ?? "https://x.tail6091f7.ts.net:10000";
const browser = await chromium.launch({
  headless: false,
  executablePath: process.env.CHROME_PATH ?? "C:/Program Files/Google/Chrome/Application/chrome.exe",
});
const ctx = await browser.newContext({ viewport: { width: 1380, height: 900 } });
const page = await ctx.newPage();
const errs = [];
page.on("pageerror", (e) => errs.push(String(e)));
await page.goto(`${base}/index.html`, { waitUntil: "load" });
await page.waitForTimeout(6000); // let the beacon chain establish

// Type like a person: real keystrokes, varied cadence, mouse travel between fields.
const fields = [
  ['input[name="name"]', "Kavin Kumar"],
  ['input[name="email"]', "kavin.tailnet@example.test"],
  ['input[name="company"]', "Neural Metrics"],
  ['textarea[name="message"]', "Checking the tailnet deployment end to end."],
];
for (const [sel, text] of fields) {
  const box = await page.locator(sel).boundingBox();
  await page.mouse.move(box.x + 40, box.y + 8, { steps: 14 });
  await page.waitForTimeout(120 + Math.random() * 200);
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  for (const ch of text) await page.keyboard.type(ch, { delay: 55 + Math.random() * 130 });
  await page.waitForTimeout(250 + Math.random() * 400);
}
const btn = await page.locator('button[type="submit"]').boundingBox();
await page.mouse.move(btn.x - 60, btn.y - 30, { steps: 10 });
await page.mouse.move(btn.x + btn.width / 2, btn.y + btn.height / 2, { steps: 8 });
await page.waitForTimeout(400);
const rp = page.waitForResponse((r) => r.url().endsWith("/api/submit"), { timeout: 60000 }).catch(() => null);
await page.mouse.click(btn.x + btn.width / 2, btn.y + btn.height / 2);
const res = await rp;
if (!res) console.log("NO SUBMISSION");
else {
  const d = await res.json();
  console.log("HTTP", res.status(), "| verdict:", d.verdict, "| score:", d.score, "| outcome:", d.outcome);
  console.log("signals:", (d.signals ?? []).map((s) => `${s.layer}:${s.id}`).join(", ") || "none");
  const plumbing = (d.signals ?? []).map((s) => `${s.layer}:${s.id}`).filter((id) =>
    ["client:invalid-proof-of-work", "client:missing-telemetry-stream", "client:invalid-page-session",
     "client:invalid-request-provenance", "client:missing-behavioral-samples",
     "client:forged-client-verdict", "client:impossible-observation-window"].includes(id));
  console.log(plumbing.length === 0 ? "PLUMBING OK behind the proxy" : "PLUMBING BROKEN: " + plumbing.join(", "));
}
console.log("pageerrors:", errs.slice(0, 2));
await browser.close();
