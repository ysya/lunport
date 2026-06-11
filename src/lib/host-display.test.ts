import { describe, it, expect } from "vitest";
import type { HostSummary } from "@/bindings/HostSummary";
import { isWildcardOnly, secondaryLine, shortLabels } from "@/lib/host-display";

/** Build a HostSummary with sensible defaults; override what each test needs. */
function host(over: Partial<HostSummary> = {}): HostSummary {
  return {
    alias: "web",
    patterns: ["web"],
    source_file: "/Users/me/.ssh/config",
    tags: [],
    hostname: null,
    user: null,
    ...over,
  };
}

describe("secondaryLine", () => {
  it("combines user and hostname as user@hostname", () => {
    expect(secondaryLine(host({ user: "root", hostname: "10.0.0.5" }))).toBe(
      "root@10.0.0.5",
    );
  });

  it("falls back to hostname alone", () => {
    expect(secondaryLine(host({ hostname: "example.com" }))).toBe("example.com");
  });

  it("falls back to user alone", () => {
    expect(secondaryLine(host({ user: "deploy" }))).toBe("deploy");
  });

  it("uses extra wildcard patterns when no user/hostname", () => {
    expect(
      secondaryLine(host({ alias: "web", patterns: ["web", "*.web"] })),
    ).toBe("*.web");
  });

  it("returns null when nothing distinct from the alias exists", () => {
    expect(secondaryLine(host({ alias: "web", patterns: ["web"] }))).toBeNull();
  });

  it("trims whitespace and treats blank values as absent", () => {
    expect(secondaryLine(host({ user: "  ", hostname: "  host  " }))).toBe("host");
  });
});

describe("shortLabels", () => {
  it("uses the bare basename when basenames are unique", () => {
    const m = shortLabels(["/etc/ssh/ssh_config", "/Users/me/.ssh/work"]);
    expect(m.get("/etc/ssh/ssh_config")).toBe("ssh_config");
    expect(m.get("/Users/me/.ssh/work")).toBe("work");
  });

  it("labels a colliding file by its nearest distinctive ancestor", () => {
    // The OrbStack case: `ssh/config` is meaningless to a human; `orbstack` is the identity.
    const m = shortLabels([
      "/Users/me/.ssh/config",
      "/Users/me/.orbstack/ssh/config",
    ]);
    expect(m.get("/Users/me/.ssh/config")).toBe("config");
    expect(m.get("/Users/me/.orbstack/ssh/config")).toBe("orbstack");
  });

  it("falls back to a trailing path when every ancestor is generic", () => {
    const m = shortLabels(["/Users/me/.ssh/config", "/etc/ssh/config"]);
    // /etc/ssh are both generic segments — no distinctive anchor exists.
    expect(m.get("/Users/me/.ssh/config")).toBe("config");
    expect(m.get("/etc/ssh/config")).toBe("ssh/config");
  });

  it("is case-insensitive when detecting collisions", () => {
    const m = shortLabels(["/a/CONFIG", "/b/config"]);
    expect(m.get("/a/CONFIG")).toBe("CONFIG");
    expect(m.get("/b/config")).toBe("b");
  });

  it("falls back to trailing paths when anchors also collide", () => {
    const m = shortLabels([
      "/base/config",
      "/x/work/ssh/config",
      "/y/work/ssh/config",
    ]);
    expect(m.get("/base/config")).toBe("config");
    expect(m.get("/x/work/ssh/config")).toBe("work");
    // `work` is taken too — extend with the trailing path until unique.
    expect(m.get("/y/work/ssh/config")).toBe("ssh/config");
  });
});

describe("isWildcardOnly", () => {
  it("treats a bare * block as wildcard-only", () => {
    expect(isWildcardOnly(host({ alias: "*", patterns: ["*"] }))).toBe(true);
  });

  it("treats *.web as wildcard-only", () => {
    expect(isWildcardOnly(host({ alias: "*.web", patterns: ["*.web"] }))).toBe(true);
  });

  it("is false when ANY pattern is a concrete host", () => {
    expect(isWildcardOnly(host({ alias: "web", patterns: ["web", "*.web"] }))).toBe(
      false,
    );
  });

  it("counts ? as a wildcard", () => {
    expect(isWildcardOnly(host({ alias: "web?", patterns: ["web?"] }))).toBe(true);
  });

  it("is false for a plain alias", () => {
    expect(isWildcardOnly(host({ alias: "web", patterns: ["web"] }))).toBe(false);
  });
});
