import { describe, expect, it } from "vitest";
import { initialAddHostTarget } from "@/lib/add-host-target";

const FILES = ["/a/config", "/a/config.d/work", "/a/config.d/home"];

describe("initialAddHostTarget", () => {
  it("uses the requested file when it is a loaded file", () => {
    expect(initialAddHostTarget("/a/config.d/work", null, FILES)).toBe("/a/config.d/work");
  });

  it("prefers the requested file over the current scope", () => {
    expect(initialAddHostTarget("/a/config.d/work", "/a/config.d/home", FILES)).toBe(
      "/a/config.d/work",
    );
  });

  it("falls back to scope when nothing is requested", () => {
    expect(initialAddHostTarget(null, "/a/config.d/home", FILES)).toBe("/a/config.d/home");
  });

  it("ignores a requested file that is not loaded", () => {
    expect(initialAddHostTarget("/a/ghost", "/a/config.d/home", FILES)).toBe(
      "/a/config.d/home",
    );
  });

  it("returns empty string when neither requested nor scope is a loaded file", () => {
    expect(initialAddHostTarget("/a/ghost", "/a/gone", FILES)).toBe("");
    expect(initialAddHostTarget(null, null, FILES)).toBe("");
  });
});
