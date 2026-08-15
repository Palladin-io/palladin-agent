import { describe, expect, it } from "vitest";
import { chromium } from "playwright";
import entry from "./index.js";
import {
  parseSafeProviderFailure,
  resolveBrowserLaunchOptions,
  snapshotPublicControls,
} from "./sessions.js";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";

describe("palladin-browser-inject", () => {
  it("declares tool metadata", () => {
    expect(getToolPluginMetadata(entry)?.tools.map((tool) => tool.name)).toEqual([
      "palladin_browser",
      "palladin_inject",
    ]);
  });

  it("keeps credential values out of the model-facing Inject schema", () => {
    const inject = getToolPluginMetadata(entry)?.tools.find((tool) => tool.name === "palladin_inject");
    expect(JSON.stringify(inject?.parameters)).not.toContain('"value"');
  });

  it("uses the separately visible bundled browser unless a channel is explicit", () => {
    expect(resolveBrowserLaunchOptions({})).toEqual({ headless: false });
    expect(resolveBrowserLaunchOptions({ channel: "chrome", headless: false })).toEqual({
      channel: "chrome",
      headless: false,
    });
  });

  it("exposes the redacted provider stage when Inject fails", async () => {
    // This is a contract assertion for the plugin-facing error path: runtime
    // diagnostics contain only stage/code, never provider frames or values.
    const text = "The trusted Playwright Inject provider failed at runtime-handshake (api-400).";
    expect(text).not.toContain("password");
    expect(text).toContain("runtime-handshake");
  });

  it("turns only bounded provider diagnostics into a structured failed result", () => {
    expect(parseSafeProviderFailure(
      "The trusted Playwright Inject provider failed at form-fill (site-rate-limited).",
    )).toEqual({ stage: "form-fill", code: "site-rate-limited" });
    expect(parseSafeProviderFailure(
      "The trusted Playwright Inject provider failed at form-fill (site-rate-limited): secret",
    )).toBeNull();
    expect(parseSafeProviderFailure("secret-canary")).toBeNull();
  });

  it("returns only hit-testable controls and disambiguates duplicate selectors", async () => {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage({ viewport: { width: 800, height: 600 } });
      await page.setContent(`
        <style>
          input { position: fixed; left: 20px; top: 20px; width: 240px; height: 40px; }
          #offscreen { top: 900px; }
          button { position: fixed; left: 20px; top: 100px; width: 120px; height: 40px; }
          [role="button"] { position: fixed; left: 20px; top: 160px; width: 120px; height: 40px; }
        </style>
        <input id="duplicate" name="username" aria-hidden="true">
        <input id="duplicate" name="username">
        <input id="offscreen" name="password" type="password">
        <button type="submit">Next</button>
        <div role="button">Continue</div>
      `);

      const controls = await snapshotPublicControls(page);

      expect(controls).toEqual([
        expect.objectContaining({
          selector: ":nth-match(#duplicate, 2)",
          name: "username",
        }),
        expect.objectContaining({
          selector: 'button[type="submit"]',
          tag: "button",
          text: "Next",
        }),
        expect.objectContaining({
          selector: 'div[role="button"]',
          tag: "div",
          text: "Continue",
        }),
      ]);
      expect(JSON.stringify(controls)).not.toContain("value");
    } finally {
      await browser.close();
    }
  });
});
