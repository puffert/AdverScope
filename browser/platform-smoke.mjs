import fs from "node:fs";
import path from "node:path";
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

async function closeContext(context, label) {
  let timer;
  try {
    await Promise.race([
      context.close(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} did not close cleanly`)), 15000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const config = JSON.parse(fs.readFileSync(0, "utf8"));
  const browserPath = executable(config.browser_executable);
  if (!browserPath) throw new Error("Chrome or Edge was not found; set AISEC_BROWSER_EXECUTABLE");
  const output = path.resolve(config.output_directory);
  if (!config.profile_directory) throw new Error("a separate temporary profile_directory is required");
  const profile = path.resolve(config.profile_directory);
  const profileRelativeToOutput = path.relative(output, profile);
  const profileIsInsideOutput = profileRelativeToOutput === ""
    || (!profileRelativeToOutput.startsWith(`..${path.sep}`)
      && profileRelativeToOutput !== ".."
      && !path.isAbsolute(profileRelativeToOutput));
  if (profileIsInsideOutput) throw new Error("profile_directory must be outside output_directory");
  fs.mkdirSync(output, { recursive: true });
  fs.mkdirSync(profile, { recursive: true });
  const options = {
    executablePath: browserPath,
    headless: true,
    viewport: { width: 1280, height: 900 },
    ignoreHTTPSErrors: false,
    args: ["--disable-background-mode", "--disable-background-networking"],
  };

  const first = await chromium.launchPersistentContext(profile, options);
  const loginPage = first.pages()[0] || await first.newPage();
  await loginPage.goto(`${config.base_url}/login`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await loginPage.fill("#username", "synthetic-user");
  await loginPage.fill("#password", "synthetic-password");
  await loginPage.screenshot({ path: path.join(output, "login-before.png"), fullPage: true });
  await Promise.all([
    loginPage.waitForURL(`${config.base_url}/chat`, { timeout: 30000 }),
    loginPage.click("#login-submit"),
  ]);
  await loginPage.screenshot({ path: path.join(output, "login-after.png"), fullPage: true });
  await closeContext(first, "first browser context");

  const second = await chromium.launchPersistentContext(profile, options);
  const chatPage = second.pages()[0] || await second.newPage();
  await chatPage.goto(`${config.base_url}/chat`, { waitUntil: "domcontentloaded", timeout: 30000 });
  const cookies = await second.cookies(config.base_url);
  const persisted = chatPage.url() === `${config.base_url}/chat`
    && cookies.some((item) => item.name === "adverscope_platform_session" && item.value === "qualified");
  let response = "";
  try {
    if (!persisted) throw new Error("authenticated browser session did not survive a persistent-context restart");
    await chatPage.fill("#message", "platform qualification message");
    await chatPage.screenshot({ path: path.join(output, "chat-request.png"), fullPage: true });
    await chatPage.click("#send");
    await chatPage.waitForFunction(() => document.querySelector("#response")?.textContent?.includes("qualified"), null, { timeout: 30000 });
    response = (await chatPage.locator("#response").innerText()).trim();
    await chatPage.screenshot({ path: path.join(output, "chat-response.png"), fullPage: true });
  } finally {
    await closeContext(second, "second browser context");
  }

  const screenshots = ["login-before.png", "login-after.png", "chat-request.png", "chat-response.png"];
  const result = {
    browser_executable: browserPath,
    login_completed: true,
    persistent_session: persisted,
    chat_response: response,
    screenshots: screenshots.map((name) => ({ name, bytes: fs.statSync(path.join(output, name)).size })),
    profile_entries: fs.readdirSync(profile).length,
  };
  fs.writeFileSync(path.join(output, "browser-platform-result.json"), JSON.stringify(result, null, 2));
  process.stdout.write(JSON.stringify(result));
}

main().catch((error) => {
  process.stderr.write(String(error?.message || error));
  process.exitCode = 1;
});
