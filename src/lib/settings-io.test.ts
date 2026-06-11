import { describe, expect, it } from "vitest";

import { parseSettingsEnvelope, SETTINGS_VERSION } from "./settings-io";

describe("parseSettingsEnvelope", () => {
  it("accepts a persist envelope with state and version", () => {
    const env = parseSettingsEnvelope(
      JSON.stringify({ state: { theme: "dark", fontSize: 15 }, version: 0 }),
    );
    expect(env.state).toEqual({ theme: "dark", fontSize: 15 });
    expect(env.version).toBe(0);
  });

  it("accepts a missing version (treated as current)", () => {
    const env = parseSettingsEnvelope(JSON.stringify({ state: {} }));
    expect(env.version).toBeUndefined();
  });

  it("rejects non-JSON input", () => {
    expect(() => parseSettingsEnvelope("Host web\n  HostName example.com")).toThrow(
      /not valid JSON/,
    );
  });

  it("rejects JSON that is not an object envelope", () => {
    expect(() => parseSettingsEnvelope("[1,2,3]")).toThrow(/not an SSHelter settings export/);
    expect(() => parseSettingsEnvelope('"hello"')).toThrow(/not an SSHelter settings export/);
    expect(() => parseSettingsEnvelope("null")).toThrow(/not an SSHelter settings export/);
  });

  it("rejects envelopes without a state object", () => {
    expect(() => parseSettingsEnvelope("{}")).toThrow(/missing settings data/);
    expect(() => parseSettingsEnvelope('{"state": "dark"}')).toThrow(/missing settings data/);
    expect(() => parseSettingsEnvelope('{"state": [1]}')).toThrow(/missing settings data/);
  });

  it("rejects envelopes from a newer settings schema", () => {
    expect(() =>
      parseSettingsEnvelope(JSON.stringify({ state: {}, version: SETTINGS_VERSION + 1 })),
    ).toThrow(/newer SSHelter/);
  });

  it("rejects a non-numeric version", () => {
    expect(() => parseSettingsEnvelope('{"state": {}, "version": "two"}')).toThrow(
      /invalid settings version/,
    );
  });
});
