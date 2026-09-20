import { chromium } from "patchright";

const base = process.env.DEMO_URL ?? "http://localhost:8787";
const headless = process.env.HEADFUL !== "1";

const browser = await chromium.launch({ headless });
const page = await browser.newPage();

await page.goto(base, { waitUntil: "load" });

await page.fill("input[name=name]", "Playwright Bot");
await page.fill("input[name=email]", "bot@automation.example");
await page.fill("input[name=company]", "Automation Inc.");
await page.fill("textarea[name=message]", "Filled by a scripted browser.");
await page.click("button[type=submit]");

await page.waitForSelector("#result h2");
console.log(await page.textContent("#result h2"));

await browser.close();
