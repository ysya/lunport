import { describe, expect, it } from "vitest";
import { searchSettings, settingsDestinations } from "./settings-navigation";

describe("settings navigation", () => {
  it("offers the workspace tools once, with no empty Sync category", () => {
    const destinations = settingsDestinations();
    expect(destinations.some((item) => item.id === "sync")).toBe(false);
    expect(destinations.find((item) => item.id === "files")?.label).toBe("Local data");
    expect(destinations.find((item) => item.id === "advanced")?.label).toBe("Diagnostics");
    expect(searchSettings("sync").map((item) => item.category)).toEqual(["files"]);
  });
  it("no longer knows the OpenSSH-only settings of the retired Legacy workspace", () => {
    for (const query of ["retention", "tailscale", "drift", "lint", "ssh_config"]) expect(searchSettings(query)).toEqual([]);
  });
  it("finds real preference sections using all query words and supports blank search", () => {
    expect(searchSettings("catppuccin")[0].target).toBe("settings-color-theme");
    expect(searchSettings(" FONT  size ")[0].target).toBe("settings-display");
    expect(searchSettings("export JSON")[0].target).toBe("settings-preferences-transfer");
    expect(searchSettings("Auto-log")[0].category).toBe("ai");
    expect(searchSettings(" ")).toEqual([]);
    expect(searchSettings("no-such-preference")).toEqual([]);
  });
});
