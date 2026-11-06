// Run with the same external Playwright setup as central-keys-qa.mjs.
// The default starts the project's Vite server; TERMINAL_QA_URL reuses an existing one.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "vite";
const { captures } = JSON.parse(await readFile(new URL("./fixtures/ubuntu-vim-startup.json", import.meta.url), "utf8"));
const cases = [
  { name: "alternate", text: "Vim 中文", chunks: ["\x1b[?1049h\x1b[H\x1b[2JVim 中文\r\n~"] },
  { name: "clear", text: "$ clear 中文", chunks: ["\x1b[3J\x1b[H\x1b[2J$ clear 中文"] },
  ...captures.map((capture) => ({ ...capture, name: capture.editor, text: "繁體中文 Vim 畫面測試", chunks: capture.chunks.map((chunk) => [...Buffer.from(chunk, "base64")]) })),
];
const playwright = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const server = process.env.TERMINAL_QA_URL ? null : await createServer({ server: { host: "127.0.0.1", port: 0, strictPort: false } });
await server?.listen();
const url = process.env.TERMINAL_QA_URL ?? server.resolvedUrls.local[0];
try {
  for (const engine of (process.env.TERMINAL_QA_BROWSERS ?? "chromium,webkit").split(",")) {
    const browser = await playwright[engine].launch({ headless: true, ...(engine === "chromium" && process.env.QA_CHROMIUM_PATH ? { executablePath: process.env.QA_CHROMIUM_PATH } : {}) });
    try {
      for (const scenario of cases) {
        const { name: mode } = scenario;
        const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
        const errors = [];
        page.on("pageerror", (error) => errors.push(error.message));
        await page.goto(`${url.replace(/\/$/, "")}/tests/browser/terminal.html`, { waitUntil: "domcontentloaded" });
        await page.waitForFunction(() => window.__terminalTest);
        const frame = () => page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        const write = (text) => page.evaluate((text) => window.__terminalTest.write(text), text);
        const snapshot = () => page.evaluate(() => window.__terminalTest.snapshot());
        if (scenario.cols) await page.evaluate(({ cols, rows }) => window.__terminalTest.resize(cols, rows), scenario);
        await write("shell 中文\r\n".repeat(300));
        await frame();
        assert.ok((await snapshot()).history > 100, "setup must have deep scrollback");
        // Focusing after output pins the hidden input to a history-relative position (#245).
        await page.evaluate(() => window.__terminalTest.focus());
        const before = await snapshot();
        for (const chunk of scenario.chunks) {
          if (typeof chunk === "string") await write(chunk);
          else await page.evaluate((bytes) => window.__terminalTest.writeBytes(bytes), chunk);
          await frame();
        }
        await frame();
        const screen = await snapshot();
        assert.equal(screen.history, 0);
        assert.ok(screen.text.includes(scenario.text));
        assert.equal(screen.scrollTop, 0, `${engine} ${mode}: viewport must stay on the live screen`);
        assert.equal(screen.rowVisible, true, "live text must be inside the viewport");
        await page.keyboard.type("i");
        assert.ok((await snapshot()).input.includes("i"), "keyboard input must still reach the host");
        if (mode !== "clear") {
          await write("\x1b[?1049l");
          await frame();
          const restored = await snapshot();
          assert.equal(restored.alternate, false);
          assert.equal(restored.history, before.history);
          assert.ok(restored.text.includes("shell 中文"));
        }
        assert.deepEqual(errors, []);
        console.log(`PASS ${engine}: focused scrollback → ${mode} → visible Chinese text and keyboard input`);
        await page.close();
      }
    } finally { await browser.close(); }
  }
} finally { await server?.close(); }
