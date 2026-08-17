import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { chromium } from "playwright-core";

const PROTECTED_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"]);

function originOf(value) {
  const parsed = new URL(String(value || ""));
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error("browser target must use HTTP or HTTPS");
  return parsed.origin;
}

function redactedHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name,
    PROTECTED_HEADERS.has(String(name).toLowerCase()) ? "[REDACTED]" : String(value).slice(0, 20000),
  ]));
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function boundedBody(buffer, limit = 500_000) {
  const value = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer || ""));
  return {
    body: value.subarray(0, limit).toString("utf8"),
    body_bytes: value.length,
    body_sha256: digest(value),
    truncated: value.length > limit,
  };
}

function assertAuthorizedPage(page, authorizedOrigin) {
  const current = page.url();
  if (originOf(current) !== authorizedOrigin) {
    throw new Error("scope boundary blocked a top-level navigation outside the authorized target origin");
  }
}

function readInput() {
  const parsed = JSON.parse(fs.readFileSync(0, "utf8"));
  if (!parsed || typeof parsed !== "object") throw new Error("capture configuration is required");
  return parsed;
}

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

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

let capturePhase = "startup";
let resultOutputPath = "";
let failureDiagnostics = {};

function evidenceUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    return `${parsed.origin}${parsed.pathname}`.slice(0, 4000);
  } catch {
    return "";
  }
}

function errorDetail(error) {
  const message = String(error?.message || "").trim();
  if (message) return message.slice(0, 1000);
  const name = String(error?.name || "").trim();
  if (name) return `${name} did not provide an error message`.slice(0, 1000);
  const rendered = String(error ?? "").trim();
  return (rendered || "browser helper failed without structured error details").slice(0, 1000);
}

async function latestResponse(locator) {
  const count = await locator.count();
  if (!count) return { count: 0, text: "" };
  return { count, text: (await locator.nth(count - 1).innerText()).trim() };
}

function compileTransientResponsePatterns(rawPatterns) {
  if (rawPatterns == null) return [];
  if (!Array.isArray(rawPatterns)) throw new Error("transient response patterns must be a list");
  return rawPatterns.map((rawPattern, index) => {
    const pattern = String(rawPattern || "").trim();
    if (!pattern) throw new Error(`transient response pattern ${index + 1} is empty`);
    // The target profile is validated by Python before it reaches this helper.
    // Accept the common leading Python inline flags that have direct JavaScript
    // equivalents so one reviewed profile behaves consistently in both
    // runtimes. Case-insensitive matching remains the default.
    let source = pattern;
    const flags = new Set(["i", "u"]);
    const leadingFlags = source.match(/^\(\?([imsu]+)\)/);
    if (leadingFlags) {
      for (const flag of leadingFlags[1]) flags.add(flag);
      source = source.slice(leadingFlags[0].length);
    }
    try {
      return { index, expression: new RegExp(source, [...flags].join("")) };
    } catch {
      throw new Error(`transient response pattern ${index + 1} is not a valid JavaScript regular expression`);
    }
  });
}

const BUILT_IN_TRANSIENT_RESPONSE_PATTERNS = [
  {
    id: "common-chat-status-placeholder",
    // Chat UIs commonly render one of these exact status messages while the
    // real answer is still streaming. Keep this deliberately narrow: it only
    // matches a standalone status token, with optional brackets and ellipsis.
    expression: /^\s*[\[(]?\s*(?:typing|thinking|processing|generating\s+(?:a\s+)?response|preparing\s+(?:a\s+)?response)\s*(?:\.{1,3}|…)?\s*[\])]?\s*$/iu,
  },
];

function matchingTransientPattern(text, patterns) {
  const candidate = String(text || "");
  if (!candidate || candidate.length > 2000) return null;
  // Some chat applications expose the entire transcript through one response
  // selector. In that shape, a standalone status token such as "[typing...]"
  // is the final line rather than the complete locator text. Test the complete
  // value first, then only the final non-empty line so prose that happens to
  // mention a status word is never treated as an unfinished response.
  const finalLine = candidate.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).at(-1) || "";
  const candidates = finalLine && finalLine !== candidate.trim() ? [candidate, finalLine] : [candidate];
  for (const value of candidates) {
    const configured = patterns.find((item) => item.expression.test(value));
    if (configured) return { source: "configured", ...configured };
    const builtIn = BUILT_IN_TRANSIENT_RESPONSE_PATTERNS.find((item) => item.expression.test(value));
    if (builtIn) return { source: "built-in", ...builtIn };
  }
  return null;
}

async function waitForInitialResponse(locator, before, timeout) {
  const started = Date.now();
  while (Date.now() - started < timeout) {
    const current = await latestResponse(locator);
    if (current.text && (current.count > before.count || current.text !== before.text)) return current;
    await sleep(150);
  }
  throw new Error("timed out waiting for the chatbot response to begin");
}

async function waitForStableResponse(locator, initial, stabilityMilliseconds, timeout, transientPatterns) {
  const started = Date.now();
  let current = initial;
  let lastChange = Date.now();
  let transientObservations = 0;
  let configuredTransientObservations = 0;
  let builtInTransientObservations = 0;
  const matchedTransientPatternIndexes = new Set();
  const matchedBuiltInTransientPatternIds = new Set();
  while (Date.now() - started < timeout) {
    await sleep(Math.min(200, Math.max(100, Math.floor(stabilityMilliseconds / 4))));
    const next = await latestResponse(locator);
    if (next.count !== current.count || next.text !== current.text) {
      current = next;
      lastChange = Date.now();
    }
    const transientMatch = matchingTransientPattern(current.text, transientPatterns);
    if (transientMatch) {
      transientObservations += 1;
      if (transientMatch.source === "configured") {
        configuredTransientObservations += 1;
        matchedTransientPatternIndexes.add(transientMatch.index);
      } else {
        builtInTransientObservations += 1;
        matchedBuiltInTransientPatternIds.add(transientMatch.id);
      }
      continue;
    }
    if (current.text && Date.now() - lastChange >= stabilityMilliseconds) {
      return {
        ...current,
        transient_observations: transientObservations,
        configured_transient_observations: configuredTransientObservations,
        built_in_transient_observations: builtInTransientObservations,
        matched_transient_pattern_indexes: [...matchedTransientPatternIndexes].sort((left, right) => left - right),
        matched_built_in_transient_pattern_ids: [...matchedBuiltInTransientPatternIds].sort(),
      };
    }
  }
  if (matchingTransientPattern(current.text, transientPatterns)) {
    throw new Error("chatbot response remained in a transient state before the timeout");
  }
  throw new Error("chatbot response did not become stable before the timeout");
}

async function waitForCompletionSignals(page, config, timeout) {
  const signals = [];
  if (config.streaming_selector) {
    await page.locator(config.streaming_selector).waitFor({ state: "hidden", timeout });
    signals.push("streaming-indicator-hidden");
  }
  if (config.completion_selector) {
    await page.locator(config.completion_selector).waitFor({ state: "visible", timeout });
    signals.push("completion-indicator-visible");
  }
  return signals;
}

async function visibleOutcomeObservation(page, rule) {
  const locator = page.locator(String(rule.selector || ""));
  const selectorMatches = await locator.count();
  const visibleTexts = [];
  for (let index = 0; index < Math.min(selectorMatches, 100); index += 1) {
    const item = locator.nth(index);
    if (await item.isVisible().catch(() => false)) {
      visibleTexts.push(String(await item.innerText().catch(() => "")).trim());
    }
  }
  const visibleText = visibleTexts.filter(Boolean).join("\n");
  const expected = String(rule.expected_text || "");
  const comparableText = rule.case_sensitive ? visibleText : visibleText.toLocaleLowerCase();
  const comparableExpected = rule.case_sensitive ? expected : expected.toLocaleLowerCase();
  return {
    selector_matches: selectorMatches,
    visible_matches: visibleTexts.length,
    expected_text_present: Boolean(comparableExpected && comparableText.includes(comparableExpected)),
    visible_text_sha256: digest(Buffer.from(visibleText, "utf8")),
    checked_url: page.url(),
  };
}

async function main() {
  capturePhase = "read-configuration";
  const config = readInput();
  capturePhase = "resolve-browser";
  const browserPath = executable(config.browser_executable);
  if (!browserPath) throw new Error("Chrome or Edge was not found; set AISEC_BROWSER_EXECUTABLE");
  const outputDirectory = path.resolve(config.output_directory);
  fs.mkdirSync(outputDirectory, { recursive: true });
  resultOutputPath = path.join(outputDirectory, "capture-result.json");
  const beforePath = path.join(outputDirectory, `${config.attempt || "initial"}-request.png`);
  const afterPath = path.join(outputDirectory, `${config.attempt || "initial"}-response.png`);
  const timeout = Math.max(1000, Number(config.timeout_ms || 30000));
  const stabilityMilliseconds = Math.max(300, Math.min(10000, Number(config.response_stability_ms || 1200)));
  const transientResponsePatterns = compileTransientResponsePatterns(config.transient_response_patterns);
  const navigationTransport = String(config.navigation_transport || "auto").trim().toLocaleLowerCase();
  if (!["auto", "http1"].includes(navigationTransport)) throw new Error("unsupported browser navigation transport");
  const browserArguments = navigationTransport === "http1" ? ["--disable-http2"] : [];
  const contextOptions = {
    viewport: { width: Number(config.viewport_width || 1440), height: Number(config.viewport_height || 1000) },
    ignoreHTTPSErrors: false,
  };
  let browser;
  let context;
  capturePhase = "launch-browser";
  if (config.user_data_directory) {
    fs.mkdirSync(path.resolve(config.user_data_directory), { recursive: true });
    context = await chromium.launchPersistentContext(path.resolve(config.user_data_directory), { executablePath: browserPath, headless: true, args: browserArguments, ...contextOptions });
  } else {
    browser = await chromium.launch({ executablePath: browserPath, headless: true, args: browserArguments });
    context = await browser.newContext(contextOptions);
  }
  let result = null;
  try {
    const existingPages = context.pages();
    const page = existingPages.length ? existingPages[0] : await context.newPage();
    const authorizedOrigin = originOf(config.url);
    const blockedRequests = [];
    await context.route("**/*", async (route) => {
      const request = route.request();
      const resourceType = request.resourceType();
      let requestOrigin = "";
      try { requestOrigin = originOf(request.url()); } catch { requestOrigin = "invalid"; }
      if (requestOrigin !== authorizedOrigin) {
        blockedRequests.push({
          url: String(request.url()).slice(0, 2000),
          method: request.method(),
          resource_type: resourceType,
          reason: "outside-authorized-origin",
          captured_after_submit: Boolean(captureTraffic),
        });
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });
    let captureTraffic = false;
    const networkExchanges = [];
    const requestRecords = new Map();
    const pendingNetwork = [];
    let networkSequence = 0;
    const registerNetworkCapture = (observedPage) => {
      observedPage.on("request", (request) => {
        if (!captureTraffic) return;
        if (networkExchanges.length >= 20) return;
        const postData = request.postData() || "";
        const record = {
          id: `network-${++networkSequence}`,
          resource_type: request.resourceType(),
          request: {
            method: request.method(),
            url: request.url(),
            headers: redactedHeaders(request.headers()),
            ...boundedBody(Buffer.from(postData)),
          },
          response: null,
          failure: "",
        };
        requestRecords.set(request, record);
        networkExchanges.push(record);
        if (typeof request.allHeaders === "function") {
          pendingNetwork.push(request.allHeaders().then((headers) => { record.request.headers = redactedHeaders(headers); }).catch(() => {}));
        }
      });
      observedPage.on("requestfailed", (request) => {
        const record = requestRecords.get(request);
        if (record) record.failure = String(request.failure()?.errorText || "request failed").slice(0, 1000);
      });
      observedPage.on("response", (response) => {
        const record = requestRecords.get(response.request());
        if (!record) return;
        pendingNetwork.push((async () => {
          let headers = response.headers();
          if (typeof response.allHeaders === "function") {
            try { headers = await response.allHeaders(); } catch {}
          }
          const body = await Promise.race([
            response.body().catch(() => null),
            sleep(1500).then(() => null),
          ]);
          record.response = {
            status: response.status(),
            status_text: response.statusText(),
            url: response.url(),
            headers: redactedHeaders(headers),
            ...(body ? boundedBody(body) : { body: "", body_bytes: 0, body_sha256: "", truncated: false, unavailable: true }),
          };
        })());
      });
    };
    registerNetworkCapture(page);
    capturePhase = "navigate-chat";
    let chatNavigationResponse = null;
    try {
      chatNavigationResponse = await page.goto(config.url, { waitUntil: "domcontentloaded", timeout });
    } catch (error) {
      if (blockedRequests.length) throw new Error("scope boundary blocked a redirect or active request outside the authorized target origin");
      throw error;
    }
    assertAuthorizedPage(page, authorizedOrigin);
    failureDiagnostics = {
      requested_url: evidenceUrl(config.url),
      final_url: evidenceUrl(page.url()),
      navigation_status: chatNavigationResponse ? chatNavigationResponse.status() : 0,
      navigation_status_text: chatNavigationResponse ? String(chatNavigationResponse.statusText() || "").slice(0, 200) : "",
      content_type: chatNavigationResponse ? String((await chatNavigationResponse.allHeaders().catch(() => ({})))["content-type"] || "").slice(0, 200) : "",
      page_title: String(await page.title().catch(() => "")).slice(0, 300),
    };
    if (String(config.mode || "chat") === "preflight") {
      capturePhase = "validate-preflight-selectors";
      const input = page.locator(config.input_selector || "");
      const submit = page.locator(config.submit_selector || "");
      const response = page.locator(config.response_selector || "");
      const selectorWaitMilliseconds = Math.max(500, Math.min(10000, Math.floor(timeout / 3)));
      const selectorWaitStartedAt = Date.now();
      await Promise.all([
        input.waitFor({ state: "attached", timeout: selectorWaitMilliseconds }),
        submit.waitFor({ state: "attached", timeout: selectorWaitMilliseconds }),
      ]).catch(() => {});
      const inputCount = await input.count();
      const submitCount = await submit.count();
      const responseCount = await response.count();
      const streamingCount = config.streaming_selector ? await page.locator(config.streaming_selector).count() : 0;
      const completionCount = config.completion_selector ? await page.locator(config.completion_selector).count() : 0;
      const selectorsReady = inputCount === 1 && submitCount === 1;
      failureDiagnostics = {
        ...failureDiagnostics,
        input_selector_matches: inputCount,
        submit_selector_matches: submitCount,
        selector_wait_ms: Math.max(0, Date.now() - selectorWaitStartedAt),
      };
      result = {
        ok: true,
        status_code: chatNavigationResponse ? chatNavigationResponse.status() : "browser",
        response: "",
        raw: JSON.stringify({
          url: page.url(),
          title: failureDiagnostics.page_title,
          input_selector_matches: inputCount,
          submit_selector_matches: submitCount,
          response_selector_matches: responseCount,
          streaming_selector_matches: streamingCount,
          completion_selector_matches: completionCount,
          persistent_session: Boolean(config.user_data_directory),
          navigation_transport: navigationTransport,
        }),
        network_exchanges: [],
        scope_enforcement: {
          authorized_origin: authorizedOrigin,
          final_origin: originOf(page.url()),
          blocked_requests: blockedRequests,
        },
        completion: {
          state: selectorsReady ? "complete" : "incomplete",
          signals: ["navigation-complete", selectorsReady ? "required-selectors-ready" : "required-selectors-incomplete"],
          persistent_session: Boolean(config.user_data_directory),
        },
        preflight: {
          selectors_ready: selectorsReady,
          input_selector_matches: inputCount,
          submit_selector_matches: submitCount,
          response_selector_matches: responseCount,
          streaming_selector_configured: Boolean(config.streaming_selector),
          streaming_selector_matches: streamingCount,
          completion_selector_configured: Boolean(config.completion_selector),
          completion_selector_matches: completionCount,
          persistent_session: Boolean(config.user_data_directory),
        },
        captures: [],
      };
      return result;
    }
    if (String(config.mode || "chat") === "page-evidence") {
      capturePhase = "capture-page-evidence";
      const selector = String(config.capture_selector || "body").trim() || "body";
      const carrier = page.locator(selector);
      await carrier.first().waitFor({ state: "attached", timeout: Math.max(500, Math.min(10000, Math.floor(timeout / 3))) }).catch(() => {});
      const selectorMatches = await carrier.count();
      const visibleTexts = [];
      for (let index = 0; index < Math.min(selectorMatches, 100); index += 1) {
        const item = carrier.nth(index);
        if (await item.isVisible().catch(() => false)) visibleTexts.push(String(await item.innerText().catch(() => "")));
      }
      const normalize = (value) => String(value || "").replace(/\s+/gu, " ").trim();
      const visibleText = normalize(visibleTexts.join("\n"));
      const expectedText = normalize(config.expected_text);
      const expectedTextPresent = Boolean(expectedText && visibleText.includes(expectedText));
      const carrierPath = path.join(outputDirectory, `${config.attempt || "initial"}-carrier.png`);
      await page.screenshot({ path: carrierPath, fullPage: true });
      const pageEvidence = {
        configured: true,
        checked_url: page.url(),
        selector,
        selector_matches: selectorMatches,
        visible_matches: visibleTexts.filter((value) => normalize(value)).length,
        expected_text_present: expectedTextPresent,
        visible_text_sha256: digest(Buffer.from(visibleText, "utf8")),
      };
      result = {
        ok: true,
        status_code: chatNavigationResponse ? chatNavigationResponse.status() : "browser",
        response: "",
        raw: JSON.stringify({
          url: page.url(),
          title: failureDiagnostics.page_title,
          selector_matches: selectorMatches,
          visible_matches: pageEvidence.visible_matches,
          expected_text_present: expectedTextPresent,
          visible_text_sha256: pageEvidence.visible_text_sha256,
          persistent_session: Boolean(config.user_data_directory),
          navigation_transport: navigationTransport,
        }),
        network_exchanges: [],
        scope_enforcement: {
          authorized_origin: authorizedOrigin,
          final_origin: originOf(page.url()),
          blocked_requests: blockedRequests,
        },
        completion: { signals: ["page-evidence-captured"], persistent_session: Boolean(config.user_data_directory) },
        page_evidence: pageEvidence,
        captures: [{
          kind: expectedTextPresent ? "carrier-screenshot" : "carrier-context-screenshot",
          path: carrierPath,
          mime_type: "image/png",
        }],
      };
      return result;
    }
    const outcomeRule = config.outcome_rule && config.outcome_rule.enabled ? config.outcome_rule : null;
    let outcomePage = page;
    let outcomeUrl = page.url();
    let baselineOutcome = null;
    if (outcomeRule) {
      capturePhase = "observe-outcome-baseline";
      if (outcomeRule.path) {
        outcomeUrl = new URL(String(outcomeRule.path), `${authorizedOrigin}/`).toString();
        if (originOf(outcomeUrl) !== authorizedOrigin) throw new Error("browser outcome verifier escaped the authorized target origin");
        outcomePage = await context.newPage();
        registerNetworkCapture(outcomePage);
        captureTraffic = true;
        await outcomePage.goto(outcomeUrl, { waitUntil: "domcontentloaded", timeout });
        assertAuthorizedPage(outcomePage, authorizedOrigin);
      }
      baselineOutcome = await visibleOutcomeObservation(outcomePage, outcomeRule);
    }
    capturePhase = "validate-chat-selectors";
    const input = page.locator(config.input_selector || "");
    const submit = page.locator(config.submit_selector || "");
    const response = page.locator(config.response_selector || "");
    const selectorWaitMilliseconds = Math.max(500, Math.min(10000, Math.floor(timeout / 3)));
    const selectorWaitStartedAt = Date.now();
    await Promise.all([
      input.waitFor({ state: "attached", timeout: selectorWaitMilliseconds }),
      submit.waitFor({ state: "attached", timeout: selectorWaitMilliseconds }),
    ]).catch(() => {});
    const inputCount = await input.count();
    const submitCount = await submit.count();
    failureDiagnostics = {
      ...failureDiagnostics,
      input_selector_matches: inputCount,
      submit_selector_matches: submitCount,
      selector_wait_ms: Math.max(0, Date.now() - selectorWaitStartedAt),
    };
    if (inputCount !== 1 || submitCount !== 1) throw new Error(`input and submit selectors must each match exactly one element (input=${inputCount}, submit=${submitCount})`);
    const promptText = String(config.prompt || "");
    const inputMaximumLengthAttribute = await input.getAttribute("maxlength");
    const inputMaximumLength = /^\d+$/.test(String(inputMaximumLengthAttribute || ""))
      ? Number(inputMaximumLengthAttribute)
      : 0;
    failureDiagnostics = {
      ...failureDiagnostics,
      prompt_length: promptText.length,
      input_maxlength: inputMaximumLength,
    };
    if (inputMaximumLength > 0 && promptText.length > inputMaximumLength) {
      throw new Error(`chatbot prompt length ${promptText.length} exceeds target input maxlength ${inputMaximumLength}; request was not submitted`);
    }
    const beforeResponse = await latestResponse(response);
    await input.fill(promptText);
    if (await input.inputValue() !== promptText) {
      throw new Error("chatbot input changed or truncated the prompt before submission; request was not submitted");
    }
    await page.screenshot({ path: beforePath, fullPage: Boolean(config.full_page) });
    const responseStartedAt = Date.now();
    const remainingTimeout = () => Math.max(1, timeout - (Date.now() - responseStartedAt));
    captureTraffic = true;
    capturePhase = "submit-prompt";
    await submit.click();
    let completedResponse;
    capturePhase = "wait-for-response";
    try {
      completedResponse = await waitForInitialResponse(response, beforeResponse, remainingTimeout());
    } catch (error) {
      if (blockedRequests.some((item) => item.captured_after_submit)) {
        throw new Error("scope boundary blocked chatbot traffic outside the authorized target origin");
      }
      throw error;
    }
    const completionSignals = await waitForCompletionSignals(page, config, remainingTimeout());
    completedResponse = await waitForStableResponse(response, completedResponse, stabilityMilliseconds, remainingTimeout(), transientResponsePatterns);
    if (completedResponse.configured_transient_observations) completionSignals.push("configured-transient-response-rejected");
    if (completedResponse.built_in_transient_observations) completionSignals.push("built-in-transient-response-rejected");
    assertAuthorizedPage(page, authorizedOrigin);
    let browserOutcome = {};
    let outcomePath = "";
    if (outcomeRule) {
      capturePhase = "verify-outcome";
      const expected = String(outcomeRule.expected_text || "");
      const requestText = String(config.prompt || "");
      const requestContainsExpected = outcomeRule.case_sensitive
        ? requestText.includes(expected)
        : requestText.toLocaleLowerCase().includes(expected.toLocaleLowerCase());
      const verificationTimeoutMilliseconds = Math.max(0, Math.min(30000, Number(outcomeRule.verification_timeout_ms ?? 5000)));
      const verificationPollMilliseconds = Math.max(100, Math.min(500, verificationTimeoutMilliseconds || 100));
      const verificationStartedAt = Date.now();
      const verificationDeadline = verificationStartedAt + Math.min(verificationTimeoutMilliseconds, remainingTimeout());
      const verificationObservations = [];
      let observedOutcome = baselineOutcome;
      const mayObserveTransition = Boolean(!requestContainsExpected && !baselineOutcome?.expected_text_present);
      do {
        if (outcomePage !== page) {
          await outcomePage.goto(outcomeUrl, { waitUntil: "domcontentloaded", timeout: remainingTimeout() });
          assertAuthorizedPage(outcomePage, authorizedOrigin);
        }
        observedOutcome = await visibleOutcomeObservation(outcomePage, outcomeRule);
        verificationObservations.push({
          elapsed_ms: Math.max(0, Date.now() - verificationStartedAt),
          ...observedOutcome,
        });
        if (observedOutcome.expected_text_present || !mayObserveTransition || Date.now() >= verificationDeadline) break;
        await sleep(Math.min(verificationPollMilliseconds, Math.max(1, verificationDeadline - Date.now())));
      } while (Date.now() <= verificationDeadline);
      const verificationDurationMilliseconds = Math.max(0, Date.now() - verificationStartedAt);
      browserOutcome = {
        configured: true,
        rule: outcomeRule,
        baseline: baselineOutcome,
        observed: observedOutcome,
        request_contains_expected: requestContainsExpected,
        transition_observed: Boolean(!requestContainsExpected && !baselineOutcome?.expected_text_present && observedOutcome.expected_text_present),
        conclusive: Boolean((baselineOutcome?.selector_matches || 0) > 0 && observedOutcome.selector_matches > 0),
        verification: {
          timeout_ms: verificationTimeoutMilliseconds,
          poll_interval_ms: verificationPollMilliseconds,
          attempts: verificationObservations.length,
          duration_ms: verificationDurationMilliseconds,
          timed_out: Boolean(mayObserveTransition && !observedOutcome.expected_text_present && verificationDurationMilliseconds >= verificationTimeoutMilliseconds),
          observations: verificationObservations,
        },
      };
      if (outcomePage !== page) {
        outcomePath = path.join(outputDirectory, `${config.attempt || "initial"}-outcome.png`);
        await outcomePage.screenshot({ path: outcomePath, fullPage: Boolean(config.full_page) });
      }
    }
    capturePhase = "write-evidence";
    await Promise.allSettled(pendingNetwork);
    await page.screenshot({ path: afterPath, fullPage: Boolean(config.full_page) });
    const captures = [
      { kind: "request-screenshot", path: beforePath, mime_type: "image/png" },
      { kind: "response-screenshot", path: afterPath, mime_type: "image/png" },
    ];
    if (outcomePath) captures.push({ kind: "outcome-screenshot", path: outcomePath, mime_type: "image/png" });
    const pageTitle = await page.title().catch(() => "");
    capturePhase = "build-result";
    result = {
      ok: true,
      status_code: "browser",
      response: completedResponse.text,
      raw: JSON.stringify({
        url: page.url(), title: pageTitle, response: completedResponse.text,
        response_count: completedResponse.count,
        completion_signals: [...completionSignals, `stable-${stabilityMilliseconds}ms`],
        completion_duration_ms: Date.now() - responseStartedAt,
        transient_response_patterns_configured: transientResponsePatterns.length,
        transient_response_observations: completedResponse.transient_observations || 0,
        configured_transient_response_observations: completedResponse.configured_transient_observations || 0,
        built_in_transient_response_observations: completedResponse.built_in_transient_observations || 0,
        matched_transient_pattern_indexes: completedResponse.matched_transient_pattern_indexes || [],
        matched_built_in_transient_pattern_ids: completedResponse.matched_built_in_transient_pattern_ids || [],
        persistent_session: Boolean(config.user_data_directory),
        navigation_transport: navigationTransport,
        http2_disabled: navigationTransport === "http1",
        network_exchange_count: networkExchanges.length,
        blocked_request_count: blockedRequests.length,
        browser_outcome: browserOutcome,
      }),
      network_exchanges: networkExchanges,
      scope_enforcement: {
        authorized_origin: authorizedOrigin,
        final_origin: originOf(page.url()),
        blocked_requests: blockedRequests,
      },
      completion: {
        response_count: completedResponse.count,
        signals: [...completionSignals, `stable-${stabilityMilliseconds}ms`],
        duration_ms: Date.now() - responseStartedAt,
        transient_response_patterns_configured: transientResponsePatterns.length,
        transient_response_observations: completedResponse.transient_observations || 0,
        configured_transient_response_observations: completedResponse.configured_transient_observations || 0,
        built_in_transient_response_observations: completedResponse.built_in_transient_observations || 0,
        matched_transient_pattern_indexes: completedResponse.matched_transient_pattern_indexes || [],
        matched_built_in_transient_pattern_ids: completedResponse.matched_built_in_transient_pattern_ids || [],
        persistent_session: Boolean(config.user_data_directory),
        navigation_transport: navigationTransport,
        http2_disabled: navigationTransport === "http1",
      },
      browser_outcome: browserOutcome,
      captures,
    };
    return result;
  } finally {
    const phaseBeforeCleanup = capturePhase;
    capturePhase = "cleanup";
    const cleanupWarnings = [];
    try {
      await context.close();
    } catch {
      cleanupWarnings.push("browser context cleanup reported an error after capture");
    }
    if (browser) {
      try {
        await browser.close();
      } catch {
        cleanupWarnings.push("browser process cleanup reported an error after capture");
      }
    }
    if (result && cleanupWarnings.length) result.cleanup_warnings = cleanupWarnings;
    capturePhase = phaseBeforeCleanup;
  }
}

function emitStructuredResult(value) {
  const serialized = JSON.stringify(value);
  if (resultOutputPath) {
    try {
      const temporaryPath = `${resultOutputPath}.${process.pid}.tmp`;
      fs.writeFileSync(temporaryPath, serialized, "utf8");
      fs.renameSync(temporaryPath, resultOutputPath);
    } catch {
      // Stdout remains the primary transport. The result file is a durable
      // fallback for platforms that drop a large final pipe write.
    }
  }
  process.stdout.write(serialized);
}

main().then((result) => {
  emitStructuredResult(result);
}).catch((error) => {
  emitStructuredResult({ ok: false, error: `${capturePhase}: ${errorDetail(error)}`, phase: capturePhase, diagnostics: failureDiagnostics });
  process.exitCode = 1;
});
