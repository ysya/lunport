// Local Vite + synthetic IPC only. Supply bundled PLAYWRIGHT_MODULE/QA_CHROMIUM_PATH if needed.
import assert from "node:assert/strict";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE ?? "playwright"
);
const browser = await chromium.launch({
  headless: true,
  ...(process.env.QA_CHROMIUM_PATH
    ? { executablePath: process.env.QA_CHROMIUM_PATH }
    : {}),
});
const page = await browser.newPage({ viewport: { width: 1100, height: 920 } });
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
const call = (method, value) =>
  page.evaluate(
    ({ method, value }) => window.__centralKeysTest[method](value),
    { method, value },
  );
try {
  await page.goto(
    `${process.env.CENTRAL_KEYS_QA_URL ?? "http://127.0.0.1:1420"}/tests/browser/central-keys.html`,
  );
  await page.locator("[data-key-id]").click();
  await page.getByRole("button", { name: "Sync key", exact: true }).click();
  await page
    .getByRole("button", { name: "Confirm sync", exact: true })
    .waitFor();
  await call("central", true);
  await page.locator('main[data-central="true"]').waitFor();
  await page.locator('[data-key-id][aria-pressed="false"]').click();
  await page.getByText("Automatic encrypted sync", { exact: true }).waitFor();
  for (const name of [
    "Sync key",
    "Stop syncing",
    "Download synced key",
    "Confirm sync",
  ])
    assert.equal(
      await page.getByRole("button", { name, exact: true }).count(),
      0,
    );
  console.log(
    "PASS central cutover removes legacy actions and an open sharing confirmation",
  );
  await call("status", "needs_material");
  await page
    .getByText(
      "This key will become available automatically after encrypted sync completes.",
      { exact: true },
    )
    .waitFor();
  assert.equal(
    await page
      .getByRole("button", { name: "Download synced key", exact: true })
      .count(),
    0,
  );
  console.log(
    "PASS pending material uses automatic sync with no download action",
  );
  await call("storage", "hardware");
  await page
    .getByText(
      "Connect this key’s hardware device to use it on this computer.",
      { exact: true },
    )
    .waitFor();
  await call("storage", "external_agent");
  await page
    .getByText(
      "Connect the SSH agent that holds this key to use it on this computer.",
      { exact: true },
    )
    .waitFor();
  await call("storage", "managed");
  console.log(
    "PASS hardware and agent references require their local provider without private transfer",
  );
  await call("status", "conflict");
  await page
    .getByText("Review this key’s identity conflict before connecting.", {
      exact: true,
    })
    .waitFor();
  await page
    .getByRole("button", { name: "Close details", exact: true })
    .click();
  await page.getByRole("button", { name: "Generate key", exact: true }).click();
  await page
    .getByText("Create an Ed25519 key in your encrypted account vault.", {
      exact: true,
    })
    .waitFor();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "detached" });
  console.log(
    "PASS conflict and key creation copy follow central account policy",
  );
  await page
    .getByRole("button", { name: "Import private key", exact: true })
    .click();
  await page.getByRole("tab", { name: "Paste key", exact: true }).click();
  await page.getByLabel("Key name", { exact: true }).fill("old_key");
  await page
    .getByLabel("Private key", { exact: true })
    .fill("PRIVATE synthetic old draft");
  await call("defer", true);
  await page.getByRole("button", { name: "Import key", exact: true }).click();
  await call("root", "c");
  await page.getByRole("dialog").waitFor({ state: "detached" });
  await page
    .getByRole("button", { name: "Import private key", exact: true })
    .click();
  await page.getByRole("tab", { name: "Paste key", exact: true }).click();
  assert.equal(
    await page.getByLabel("Private key", { exact: true }).inputValue(),
    "",
  );
  await page.getByLabel("Key name", { exact: true }).fill("new_key");
  await page
    .getByLabel("Private key", { exact: true })
    .fill("PRIVATE synthetic new draft");
  await call("root", "a");
  await page.getByRole("dialog").waitFor({ state: "detached" });
  await page
    .getByRole("button", { name: "Import private key", exact: true })
    .click();
  await page.getByRole("tab", { name: "Paste key", exact: true }).click();
  await page.getByLabel("Key name", { exact: true }).fill("current_key");
  await page
    .getByLabel("Private key", { exact: true })
    .fill("PRIVATE synthetic current draft");
  await call("reply");
  assert.equal(
    await page.getByLabel("Private key", { exact: true }).inputValue(),
    "PRIVATE synthetic current draft",
  );
  assert.notEqual(
    await page.evaluate(() => window.__centralKeysTest.cachedDestination()),
    null,
  );
  assert.equal(
    await page.evaluate(() => window.__centralKeysTest.cachedError()),
    null,
  );
  await call("root", "d");
  await page.getByRole("dialog").waitFor({ state: "detached" });
  assert.deepEqual(await page.evaluate(() => window.__centralKeysTest.model.calls), ["records_key_import"]);
  await call("clearCalls");
  console.log(
    "PASS account/device context changes clear secrets and ignore a late reply even after returning to the original root",
  );
  await call("status", "needs_material");
  await page.locator("[data-key-id]").click();
  await page.getByText("Automatic encrypted sync", { exact: true }).waitFor();
  await page
    .locator('[aria-label="Key details"][data-state="open"]')
    .evaluate(async (element) => {
      await Promise.all(
        element
          .getAnimations({ subtree: true })
          .map((animation) => animation.finished.catch(() => {})),
      );
    });
  await page.screenshot({
    path:
      process.env.CENTRAL_KEYS_QA_SCREENSHOT ??
      "/private/tmp/lunport-central-key-actions.png",
    fullPage: true,
  });
  assert.deepEqual(
    await page.evaluate(() => window.__centralKeysTest.model.calls),
    [],
  );
  assert.deepEqual(errors, []);
  console.log("PASS only expected synthetic invocation and no browser errors");
} finally {
  await browser.close();
}
