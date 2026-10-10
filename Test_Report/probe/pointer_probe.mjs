import { createServer } from "node:http";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";

const outFile = fileURLToPath(new URL("./pointer_probe_results.json", import.meta.url));
const headless = process.env.HEADFUL !== "1";
const executablePath = process.env.CHROME_PATH;

const PAGE = `<!doctype html><html><body style="margin:0">
<button id="target" style="position:absolute;left:100px;top:100px;width:200px;height:80px">target</button>
<script>
window.__events = [];
const record = (event) => window.__events.push({
  type: event.type,
  isTrusted: event.isTrusted,
  pointerType: event.pointerType ?? null,
  pressure: event.pressure ?? null,
  width: event.width ?? null,
  height: event.height ?? null,
  tiltX: event.tiltX ?? null,
  pointerId: event.pointerId ?? null,
  buttons: event.buttons,
  detail: event.detail,
  sourceCapabilities: event.sourceCapabilities === undefined ? "undefined" : event.sourceCapabilities === null ? null : { firesTouchEvents: event.sourceCapabilities.firesTouchEvents },
  webkitForce: event.webkitForce ?? null,
}) && (document.documentElement.dataset.events = JSON.stringify(window.__events));
for (const type of ["pointerdown", "pointerup", "mousedown", "mouseup", "click"]) {
  document.addEventListener(type, record, true);
}
</script></body></html>`;

const server = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end(PAGE);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const url = `http://127.0.0.1:${server.address().port}/`;

const browser = await chromium.launch({ headless, ...(executablePath ? { executablePath } : {}) });
const results = { browser: browser.version(), headless, cases: {} };

async function run(name, drive) {
  const page = await browser.newPage();
  await page.goto(url);
  await drive(page);
  await page.waitForTimeout(150);
  results.cases[name] = JSON.parse((await page.getAttribute("html", "data-events")) ?? "[]");
  await page.close();
}

await run("patchright page.mouse.click", (page) => page.mouse.click(200, 140));
await run("patchright locator.click", (page) => page.locator("#target").click());
await run("raw CDP Input.dispatchMouseEvent (no force)", async (page) => {
  const cdp = await page.context().newCDPSession(page);
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
    await cdp.send("Input.dispatchMouseEvent", { type, x: 200, y: 140, button: type === "mouseMoved" ? "none" : "left", buttons: type === "mousePressed" ? 1 : 0, clickCount: 1 });
  }
});
await run("raw CDP Input.dispatchMouseEvent (force 0.5)", async (page) => {
  const cdp = await page.context().newCDPSession(page);
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
    await cdp.send("Input.dispatchMouseEvent", { type, x: 200, y: 140, button: type === "mouseMoved" ? "none" : "left", buttons: type === "mousePressed" ? 1 : 0, clickCount: 1, force: 0.5 });
  }
});
await run("CDP Input.dispatchTouchEvent tap", async (page) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 200, y: 140 }] });
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
});
await run("element.click() (synthetic)", (page) => page.evaluate(() => document.getElementById("target").click()));
await run("keyboard Enter on focused button", async (page) => {
  await page.focus("#target");
  await page.keyboard.press("Enter");
});

await browser.close();
server.close();
writeFileSync(outFile, `${JSON.stringify(results, null, 2)}\n`);
for (const [name, events] of Object.entries(results.cases)) {
  const down = events.find((event) => event.type === "pointerdown");
  const mouseDown = events.find((event) => event.type === "mousedown");
  console.log(
    `${name.padEnd(46)} pointerdown: ${down ? `pressure=${down.pressure} type=${down.pointerType} w=${down.width} trusted=${down.isTrusted} caps=${JSON.stringify(down.sourceCapabilities)}` : "none"}` +
      ` | mousedown: ${mouseDown ? `trusted=${mouseDown.isTrusted} caps=${JSON.stringify(mouseDown.sourceCapabilities)}` : "none"}`,
  );
}
