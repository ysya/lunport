// Run with a local Vite server. Supply PLAYWRIGHT_MODULE when using a bundled tool runtime.
// Synthetic IPC only; never launches the desktop app or reads real credentials.
import assert from "node:assert/strict";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE ?? "playwright"
);
const browser = await chromium.launch({ headless: true });
const base = process.env.REPLACEMENT_QA_URL ?? "http://127.0.0.1:1420";
const page = await browser.newPage({ viewport: { width: 900, height: 1100 } });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
const command = (name) => `central_replacement_${name}`;
const call = async (method, ...args) =>
  page.evaluate(
    ({ method, args }) => window.__replacementTest[method](...args),
    { method, args },
  );
const count = async (name) =>
  page.evaluate(
    (cmd) =>
      window.__replacementTest.model.calls.filter((c) => c.command === cmd)
        .length,
    command(name),
  );
const wait = async (name, n = 1) =>
  page.waitForFunction(
    ({ cmd, n }) =>
      window.__replacementTest.model.calls.filter((c) => c.command === cmd)
        .length >= n,
    { cmd: command(name), n },
  );
const clean = async () => {
  const caches = await call("caches");
  assert.equal(caches.mutations, 0);
  assert(!JSON.stringify(caches).includes("SECRET_TEST_ONLY"));
  assert(!JSON.stringify(caches).includes("INPUT_RECOVERY_SECRET"));
};
const reset = async () => {
  await page.goto(`${base}/tests/browser/central-replacement.html`);
  await page
    .getByRole("button", { name: "Replace this device", exact: true })
    .waitFor();
};
const startKit = async () => {
  await page.getByLabel("An offline recovery kit", { exact: true }).check();
  await page
    .getByLabel("Recovery kit for device replacement", { exact: true })
    .fill("INPUT_RECOVERY_SECRET");
  await page
    .getByRole("button", { name: "Replace this device", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .waitFor();
};
try {
  await reset();
  await call("defer", command("reserve"));
  await page
    .getByRole("button", { name: "Replace this device", exact: true })
    .click();
  await wait("reserve");
  await call("mount", false);
  await page.waitForFunction(
    () => !document.querySelector('[aria-label="Replace this device"]'),
  );
  await call("mount", true);
  await page
    .getByRole("button", { name: "Replace this device", exact: true })
    .click();
  assert.equal(await count("reserve"), 1);
  await call("resolve", command("reserve"));
  await wait("reserve", 2);
  await wait("start");
  const starts = await page.evaluate(() =>
    window.__replacementTest.model.calls.filter(
      (c) => c.command === "central_replacement_start",
    ),
  );
  assert.equal(starts.length, 1);
  assert.equal(starts[0].args.invocation.generation, "2".padStart(32, "0"));
  await wait("cancel");
  await clean();
  console.log(
    "PASS pending reservation, unmount and newer reservation ordering",
  );

  await reset();
  await startKit();
  await call("defer", command("reveal_kit"));
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await wait("reveal_kit");
  await call("hide", true);
  await call("resolve", command("reveal_kit"));
  await page.waitForTimeout(150);
  assert.equal(
    await page
      .getByLabel("New replacement recovery kit", { exact: true })
      .count(),
    0,
  );
  await clean();
  console.log("PASS hidden late reveal and metadata-only caches");

  await reset();
  await startKit();
  await call("defer", command("reveal_kit"));
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await wait("reveal_kit");
  await call("status", {
    device_id: "9".repeat(32),
    root_fingerprint: "8".repeat(64),
  });
  await call("resolve", command("reveal_kit"));
  await page.waitForTimeout(150);
  assert.equal(
    await page
      .getByLabel("New replacement recovery kit", { exact: true })
      .count(),
    0,
  );
  await clean();
  console.log("PASS scope change rejects late secret response");

  await reset();
  await startKit();
  const confirm = page.getByRole("button", {
    name: "Confirm recovery and replace device",
    exact: true,
  });
  assert(await confirm.isDisabled());
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await page
    .getByLabel("New replacement recovery kit", { exact: true })
    .waitFor();
  const saved = page.getByRole("checkbox");
  await saved.check();
  assert(await confirm.isEnabled());
  await page
    .getByRole("button", { name: "Hide recovery kit", exact: true })
    .click();
  assert(await confirm.isDisabled());
  assert.equal(await saved.isChecked(), false);
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await page
    .getByLabel("New replacement recovery kit", { exact: true })
    .waitFor();
  await saved.check();
  await call("defer", command("continue"));
  await confirm.click();
  await wait("continue");
  await page
    .getByRole("button", { name: "Pause replacement", exact: true })
    .click();
  await wait("cancel");
  await call("resolve", command("continue"), {
    phase: "complete",
    operation: "c".repeat(32),
    route: "recovery_kit",
    verified: 33,
    total: 33,
    root_fingerprint: "1".repeat(64),
    backup_confirmed: true,
    unresolved_archives: 0,
  });
  await page.waitForTimeout(150);
  assert.equal(
    await page
      .getByText("This device now uses its new account identity.", {
        exact: true,
      })
      .count(),
    0,
  );
  assert.equal(
    await page
      .getByLabel("New replacement recovery kit", { exact: true })
      .count(),
    0,
  );
  await clean();
  console.log(
    "PASS backup acknowledgement, hide reset, pause and late completion",
  );

  await reset();
  await startKit();
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await page
    .getByLabel("New replacement recovery kit", { exact: true })
    .waitFor();
  await call("disable", true);
  await page.waitForFunction(
    () =>
      !document.querySelector('[aria-label="New replacement recovery kit"]'),
  );
  await clean();
  console.log("PASS disabled/sign-out boundary clears shown secret");
  await reset();
  await startKit();
  await page
    .getByRole("button", { name: "Show new recovery kit", exact: true })
    .click();
  await page
    .getByLabel("New replacement recovery kit", { exact: true })
    .waitFor();
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", {
      name: "Confirm recovery and replace device",
      exact: true,
    })
    .click();
  await page
    .getByText("This device now uses its new account identity.", {
      exact: true,
    })
    .waitFor();
  await page.waitForFunction(
    () => window.__replacementTest.model.status.device_id === "d".repeat(32),
  );
  assert.equal(
    await page
      .getByLabel("New replacement recovery kit", { exact: true })
      .count(),
    0,
  );
  await clean();
  console.log(
    "PASS automatic verification reaches completion and clears secrets",
  );
  assert.deepEqual(errors, []);
  console.log("6 browser lifecycle scenarios passed");
} finally {
  await browser.close();
}
