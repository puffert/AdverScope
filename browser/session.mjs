import fs from "node:fs";
import { chromium } from "playwright-core";

function executable(configured) {
  const candidates = [
    configured,
    process.env.AISEC_BROWSER_EXECUTABLE,
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate));
}

async function main() {
  const config = JSON.parse(fs.readFileSync(0, "utf8"));
  const browserPath = executable(config.browser_executable);
  if (!browserPath) throw new Error("Chrome or Edge was not found; set AISEC_BROWSER_EXECUTABLE");
  fs.mkdirSync(config.user_data_directory, { recursive: true });
  const navigationTransport = String(config.navigation_transport || "auto").trim().toLocaleLowerCase();
  if (!["auto", "http1"].includes(navigationTransport)) throw new Error("unsupported browser navigation transport");
  const context = await chromium.launchPersistentContext(config.user_data_directory, {
    executablePath: browserPath,
    headless: false,
    args: navigationTransport === "http1" ? ["--disable-http2"] : [],
    viewport: null,
    ignoreHTTPSErrors: false,
  });
  const pages = context.pages();
  const page = pages.length ? pages[0] : await context.newPage();
  await page.goto(config.url, { waitUntil: "domcontentloaded", timeout: Number(config.timeout_ms || 30000) });
  await new Promise((resolve) => context.once("close", resolve));
}

main().catch(() => { process.exitCode = 1; });
