import { describe, expect, it } from "vitest";
import { searchSettings, settingsDestinations } from "./settings-navigation";

describe("settings mode boundaries and navigation", () => {
  it("offers Records workspace tools once, with no empty Sync category", () => {
    const destinations = settingsDestinations("records");
    expect(destinations.some((item) => item.id === "sync")).toBe(false);
    expect(destinations.find((item) => item.id === "files")?.label).toBe("Local data");
    expect(destinations.find((item) => item.id === "advanced")?.label).toBe("Diagnostics");
    expect(searchSettings("sync", "records").map((item) => item.category)).toEqual(["files"]);
  });
  it("does not expose OpenSSH-only settings in Records search", () => {
    for (const query of ["retention", "tailscale", "drift", "lint"]) expect(searchSettings(query, "records")).toEqual([]);
    expect(searchSettings("retention", "legacy")[0].category).toBe("files");
    expect(searchSettings("drift", "legacy")[0].category).toBe("advanced");
  });
  it("finds real preference sections using all query words and supports blank search", () => {
    expect(searchSettings(" FONT  size ", "records")[0].target).toBe("settings-display");
    expect(searchSettings("export JSON", "legacy")[0].target).toBe("settings-preferences-transfer");
    expect(searchSettings("Auto-log", "legacy")).toEqual([]);
    expect(searchSettings("Auto-log", "records")[0].category).toBe("ai");
    expect(searchSettings(" ", "records")).toEqual([]);
    expect(searchSettings("no-such-preference", "legacy")).toEqual([]);
  });
});
