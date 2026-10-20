import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import control from "../selfhost/central/control";
import { REGISTRY_WITNESS } from "../src/security/floor";
type Configuration = Parameters<typeof control.test>[1];
const installation = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
let settings: Configuration;
beforeEach(() => {
  settings = {
    ...env,
    SECURITY_INSTALLATION: installation(),
    SELFHOST_CONTROL_MODE: "inspect",
  };
  vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());
const floor = () =>
  env.SECURITY_FLOOR.getByName("floor:" + settings.SECURITY_INSTALLATION);
const registry = () =>
  env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString();
const fresh = () => ({
  ...settings,
  SELFHOST_CONTROL_MODE: "provision-new",
  SELFHOST_EXPECTED_REGISTRY: registry(),
  SELFHOST_CONFIRM_NEW_INSTALLATION: settings.SECURITY_INSTALLATION,
});
describe("private selfhost operator actions", () => {
  it("inspection does not initialize absent floor state", async () => {
    await control.test({}, settings);
    expect(
      await runInDurableObject(floor(), (_instance, state) =>
        state.storage.get("floor"),
      ),
    ).toBeUndefined();
  });
  it("requires exact registry and fresh-install confirmation and rejects existing-state reinitialization", async () => {
    await expect(
      control.test({}, { ...fresh(), SELFHOST_CONFIRM_NEW_INSTALLATION: "" }),
    ).rejects.toThrow();
    await expect(
      control.test(
        {},
        { ...fresh(), SELFHOST_EXPECTED_REGISTRY: "0".repeat(64) },
      ),
    ).rejects.toThrow();
    expect(
      (await floor().authorize(settings.SECURITY_INSTALLATION)).status,
    ).toBe(503);
    await control.test({}, fresh());
    expect(
      await floor().authorize(settings.SECURITY_INSTALLATION),
    ).toMatchObject({ status: 200, minimum: 2 });
    await expect(control.test({}, fresh())).rejects.toThrow();
  });
  it("only raises an existing floor and never repairs absent or corrupt state", async () => {
    const raised = {
      ...settings,
      SELFHOST_CONTROL_MODE: "raise-floor",
      SELFHOST_EXPECTED_REGISTRY: registry(),
      SELFHOST_MINIMUM_FLOOR: "3",
    };
    await expect(control.test({}, raised)).rejects.toThrow();
    await control.test({}, fresh());
    await control.test({}, raised);
    await expect(
      control.test({}, { ...raised, SELFHOST_MINIMUM_FLOOR: "1" }),
    ).rejects.toThrow();
    expect(
      await floor().authorize(settings.SECURITY_INSTALLATION),
    ).toMatchObject({ status: 200, minimum: 3 });
    await runInDurableObject(floor(), (_instance, state) =>
      state.storage.put("floor", { corrupt: true }),
    );
    await expect(control.test({}, fresh())).rejects.toThrow();
    expect(
      await runInDurableObject(floor(), (_instance, state) =>
        state.storage.get("floor"),
      ),
    ).toEqual({ corrupt: true });
  });
});
