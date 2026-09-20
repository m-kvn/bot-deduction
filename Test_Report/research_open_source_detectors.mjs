import { chromium } from "../bot-signal/node_modules/patchright/index.mjs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const botdBundle = await readFile(
  new URL("../bot-signal/node_modules/@fingerprintjs/botd/dist/botd.esm.js", import.meta.url),
);
const localServer = createServer((request, response) => {
  if (request.url === "/botd.js") {
    response.writeHead(200, { "content-type": "text/javascript" });
    return response.end(botdBundle);
  }
  response.writeHead(200, { "content-type": "text/html" });
  response.end("<!doctype html><title>BotD test</title><p>ready</p>");
});
await new Promise((resolve) => localServer.listen(8999, "127.0.0.1", resolve));

const browser = await chromium.launch({
  headless: false,
  executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
});

try {
  const page = await browser.newPage();
  for (const url of [
    "https://bot-detector.rebrowser.net/",
    "https://fingerprintjs.github.io/BotD/",
    "https://ttlns.github.io/brotector/",
  ]) {
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 });
      await page.waitForTimeout(5_000);
      if (url.includes("brotector")) {
        const button = page.locator("#clickHere");
        if (await button.count()) {
          await button.click();
          await page.waitForTimeout(2_000);
        }
      }
      console.log(`\nURL ${url}\n${(await page.locator("body").innerText()).slice(0, 12_000)}`);
    } catch (error) {
      console.log(`\nERROR ${url}: ${error.message}`);
    }
  }

  await page.goto("http://127.0.0.1:8999/", { waitUntil: "load" });
  const botd = await page.evaluate(async () => {
    const { load } = await import("/botd.js");
    const detector = await load();
    return detector.detect();
  });
  console.log(`\nBotD 2.0.0 result\n${JSON.stringify(botd, null, 2)}`);
} finally {
  await browser.close();
  await new Promise((resolve, reject) =>
    localServer.close((error) => (error ? reject(error) : resolve())),
  );
}
