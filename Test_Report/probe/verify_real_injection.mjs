import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const base = process.env.TARGET ?? "http://localhost:8787";

function runPs(script, env = {}) {
  return new Promise((resolve) => {
    const child = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], {
      env: { ...process.env, ...env },
    });
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (out += c));
    child.on("exit", () => resolve(out.trim()));
  });
}

const CURSOR_DECL = `
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class C {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
}
"@
[void][C]::SetProcessDPIAware()
`;

const browser = await chromium.launch({
  headless: false,
  executablePath: chromePath,
  args: ["--window-position=0,0", "--window-size=1280,1000"],
});
const context = await browser.newContext({ viewport: null });

// Records the latest pointer position into the DOM, which both the isolated
// evaluate world and the page itself can read.
await context.addInitScript(() => {
  window.addEventListener(
    "mousemove",
    (event) => {
      document.documentElement.dataset.bsCursor = `${event.clientX},${event.clientY}`;
    },
    true,
  );
});

const page = await context.newPage();
await page.goto(`${base}/index.html`, { waitUntil: "load" });
await page.bringToFront();
await page.waitForTimeout(1200);

// Calibrate physical cursor coordinates against page client coordinates by
// moving to two known screen points and reading back what the page saw.
async function probePoint(px, py) {
  await page.evaluate(() => delete document.documentElement.dataset.bsCursor);
  await runPs(`${CURSOR_DECL}\n[void][C]::SetCursorPos(${px}, ${py})`);
  await page.waitForTimeout(450);
  const seen = await page.evaluate(() => document.documentElement.dataset.bsCursor ?? "");
  if (!seen) throw new Error(`calibration point ${px},${py} produced no mousemove`);
  const [x, y] = seen.split(",").map(Number);
  return { x, y };
}

const p1 = await probePoint(300, 400);
const p2 = await probePoint(900, 800);
const scaleX = (900 - 300) / (p2.x - p1.x);
const scaleY = (800 - 400) / (p2.y - p1.y);
const offsetX = 300 - p1.x * scaleX;
const offsetY = 400 - p1.y * scaleY;
console.log(
  `calibration: scale=${scaleX.toFixed(3)},${scaleY.toFixed(3)} offset=${offsetX.toFixed(1)},${offsetY.toFixed(1)}`,
);

const physicalOf = async (selector) => {
  const box = await page.evaluate((sel) => {
    const rect = document.querySelector(sel).getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  }, selector);
  return {
    x: Math.round(box.x * scaleX + offsetX),
    y: Math.round(box.y * scaleY + offsetY),
  };
};

const name = await physicalOf('input[name="name"]');
const email = await physicalOf('input[name="email"]');
const message = await physicalOf('textarea[name="message"]');
const submit = await physicalOf('button[type="submit"]');
console.log("targets:", JSON.stringify({ name, email, message, submit }));

const fields = [
  `${name.x},${name.y},Kavin Kumar`,
  `${email.x},${email.y},kavin.real.injection@example.test`,
  `${message.x},${message.y},Following up on the bot-signal demo - could you share pricing?`,
].join(";");

const responsePromise = page
  .waitForResponse((r) => r.url().endsWith("/api/submit") && r.request().method() === "POST", {
    timeout: 240_000,
  })
  .catch(() => null);

const psOut = await new Promise((resolve) => {
  const child = spawn(
    "powershell",
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      new URL("real_injection.ps1", import.meta.url).pathname.slice(1),
    ],
    { env: { ...process.env, BS_FIELDS: fields, BS_SUBMIT: `${submit.x},${submit.y}` } },
  );
  let out = "";
  child.stdout.on("data", (c) => (out += c));
  child.stderr.on("data", (c) => (out += c));
  child.on("exit", () => resolve(out.trim()));
});

console.log("powershell:", psOut.replaceAll("\n", " | "));

const response = await responsePromise;
if (!response) {
  console.log("NO SUBMISSION CAPTURED");
} else {
  const data = await response.json();
  console.log("HTTP", response.status());
  console.log("verdict:", data.verdict, "| score:", data.score);
  console.log("signals:", data.signals.map((s) => `${s.layer}:${s.id}`).join(", ") || "none");
}

await page.screenshot({
  path: new URL("real_injection_result.png", import.meta.url).pathname.slice(1),
  fullPage: true,
});
await browser.close();
