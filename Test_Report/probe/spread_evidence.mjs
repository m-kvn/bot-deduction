// Reproduction of the reported "spread the evidence across layers" run.
//
// Implements the techniques described for agentcloud/human.mjs: headful
// patchright with AutomationControlled disabled, trusted CDP input only, bezier
// pointer paths with overshoot-and-correct, human typing cadence with deliberate
// typos and Backspace corrections, Shift-as-three-events capitals, off-centre
// clicks, post-typing review keys, and fingerprint patches confined to surfaces
// the detector does not scan for native-function tampering.
//
// The point is not to be a better bot. It is to check whether the technique is
// caught end to end, rather than checking whether the decision rule would catch
// the numbers the technique produced.
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";

const base = process.env.TARGET ?? "http://127.0.0.1:8799";
const chromePath = process.env.CHROME_PATH ?? "C:/Program Files/Google/Chrome/Application/chrome.exe";

const rand = (min, max) => min + Math.random() * (max - min);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Only surfaces the detector does not check for native-function tampering.
// Function.prototype.bind/toString and the navigator accessors webdriver /
// hardwareConcurrency / languages / plugins are deliberately left alone.
const STEALTH_INIT = () => {
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (parameter) {
    if (parameter === 37445) return "Intel Inc.";
    if (parameter === 37446) return "Mesa Intel(R) UHD Graphics 630";
    return getParameter.call(this, parameter);
  };
  if (navigator.connection && navigator.connection.rtt === 0) {
    Object.defineProperty(navigator.connection, "rtt", {
      get: () => 50 + 25 * Math.floor(Math.random() * 4),
    });
  }
};

const KEY_NEIGHBOURS = {
  a: "sq", b: "vn", c: "xv", d: "sf", e: "wr", f: "dg", g: "fh", h: "gj",
  i: "uo", j: "hk", k: "jl", l: "k", m: "n", n: "bm", o: "ip", p: "o",
  q: "wa", r: "et", s: "ad", t: "ry", u: "yi", v: "cb", w: "qe", x: "zc",
  y: "tu", z: "x",
};

async function movePointer(page, state, x2, y2) {
  const [x1, y1] = state.pos;
  const dist = Math.hypot(x2 - x1, y2 - y1);
  if (dist < 3) return;
  const steps = Math.max(18, Math.min(52, Math.round(dist / 7)));
  const px = -(y2 - y1) / dist;
  const py = (x2 - x1) / dist;
  const bow = rand(20, 80) * (Math.random() < 0.5 ? -1 : 1);
  const cx = (x1 + x2) / 2 + px * bow;
  const cy = (y1 + y2) / 2 + py * bow;

  for (let i = 1; i <= steps; i += 1) {
    const t = i / steps;
    const e = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; // cubic ease-in-out
    const u = 1 - e;
    const bx = u * u * x1 + 2 * u * e * cx + e * e * x2 + rand(-0.9, 0.9);
    const by = u * u * y1 + 2 * u * e * cy + e * e * y2 + rand(-0.9, 0.9);
    await page.mouse.move(bx, by);
    // Never fast enough that a 100ms window covers more than 600px.
    await sleep(rand(8, 26));
    if (Math.random() < 0.06) await sleep(rand(40, 140)); // micro-hesitation
  }

  // Overshoot and correct on longer reaches.
  if (dist > 220) {
    await page.mouse.move(x2 + rand(3, 11), y2 + rand(-6, 6));
    await sleep(rand(40, 110));
  }
  await page.mouse.move(x2, y2);
  await sleep(rand(60, 210));
  state.pos = [x2, y2];
}

async function clickField(page, state, selector) {
  const box = await page.locator(selector).boundingBox();
  const x = box.x + box.width * rand(0.32, 0.68);
  const y = box.y + box.height * rand(0.32, 0.68);
  await movePointer(page, state, x, y);
  await page.mouse.down();
  await sleep(rand(45, 120));
  await page.mouse.up();
  await sleep(rand(120, 340));
}

async function typeHuman(page, text) {
  let previous = "";
  for (const ch of text) {
    // 7% chance of a neighbour-key typo, noticed and corrected.
    if (/[a-z]/i.test(ch) && Math.random() < 0.07) {
      const neighbours = KEY_NEIGHBOURS[ch.toLowerCase()];
      if (neighbours) {
        const wrong = neighbours[Math.floor(Math.random() * neighbours.length)];
        await page.keyboard.press(wrong);
        await sleep(rand(140, 420));
        await page.keyboard.press("Backspace");
        await sleep(rand(90, 220));
      }
    }

    if (ch >= "A" && ch <= "Z") {
      await page.keyboard.down("Shift");
      await sleep(rand(18, 45));
      await page.keyboard.press(`Key${ch}`);
      await sleep(rand(18, 45));
      await page.keyboard.up("Shift");
    } else {
      await page.keyboard.type(ch);
    }

    let delay = rand(65, 185);
    if (ch === " ") delay *= rand(1.05, 1.5);
    if (ch === previous) delay *= rand(0.7, 0.9);
    if (Math.random() < 0.09) delay += rand(180, 520);
    await sleep(delay);
    previous = ch;
  }

  if (Math.random() < 0.35) {
    await page.keyboard.press("Home");
    await sleep(rand(120, 300));
    await page.keyboard.press("ArrowRight");
    await sleep(rand(90, 200));
    await page.keyboard.press("End");
    await sleep(rand(150, 350));
  }
}

const browser = await chromium.launch({
  headless: false,
  executablePath: chromePath,
  args: ["--disable-blink-features=AutomationControlled", "--window-size=1400,950"],
});
const context = await browser.newContext({ viewport: null });
await context.addInitScript(STEALTH_INIT);
const page = await context.newPage();
await page.goto(`${base}/index.html`, { waitUntil: "load" });
await sleep(rand(2500, 4200));

const state = { pos: [rand(80, 300), rand(80, 260)] };
const fields = [
  ['input[name="name"]', "Kavin Kumar"],
  ['input[name="email"]', "kavin.spread@example.test"],
  ['input[name="company"]', "Neural Metrics"],
  ['textarea[name="message"]', "Following up on the demo, could you share pricing and timelines?"],
];

for (const [selector, text] of fields) {
  await clickField(page, state, selector);
  await typeHuman(page, text);
  await sleep(rand(250, 700));
}

const button = await page.locator('button[type="submit"]').boundingBox();
const bx = button.x + button.width * rand(0.32, 0.68);
const by = button.y + button.height * rand(0.32, 0.68);
await movePointer(page, state, bx, by);
await sleep(rand(300, 800));

const responsePromise = page
  .waitForResponse((r) => r.url().endsWith("/api/submit"), { timeout: 120_000 })
  .catch(() => null);
await page.mouse.down();
await sleep(rand(45, 120));
await page.mouse.up();

const response = await responsePromise;
if (!response) {
  console.log("NO SUBMISSION");
} else {
  const data = await response.json();
  console.log("HTTP", response.status(), "| verdict:", data.verdict, "| score:", data.score,
    "| outcome:", data.outcome);
  console.log("layers:", JSON.stringify(data.layers));
  console.log("signals:", (data.signals ?? []).map((s) => `${s.layer}:${s.id} ${s.score}`).join("  |  ") || "none");
}
await sleep(1500);
await browser.close();
