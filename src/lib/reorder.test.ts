import { describe, it, expect } from "vitest";
import { applyOrderToHosts, buildNewOrder, type ReorderableHost } from "@/lib/reorder";

/** Concrete host block: alias == single pattern. */
function h(alias: string): ReorderableHost {
  return { alias, patterns: [alias] };
}

/** Wildcard-only DEFAULTS block (`Host *`, `Host *.web`, …). */
function wild(pattern: string): ReorderableHost {
  return { alias: pattern, patterns: [pattern] };
}

describe("buildNewOrder", () => {
  const abc = [h("a"), h("b"), h("c")];

  it("moves the first host to the end (gap past the last row)", () => {
    expect(buildNewOrder(abc, 0, 3)).toEqual(["b", "c", "a"]);
  });

  it("moves the last host to the front", () => {
    expect(buildNewOrder(abc, 2, 0)).toEqual(["c", "a", "b"]);
  });

  it("swaps adjacent hosts (drag down past the next row)", () => {
    expect(buildNewOrder(abc, 0, 2)).toEqual(["b", "a", "c"]);
  });

  it("swaps adjacent hosts (drag up above the previous row)", () => {
    expect(buildNewOrder(abc, 2, 1)).toEqual(["a", "c", "b"]);
  });

  it("treats the gaps hugging the source as no-ops", () => {
    expect(buildNewOrder(abc, 1, 1)).toEqual(["a", "b", "c"]);
    expect(buildNewOrder(abc, 1, 2)).toEqual(["a", "b", "c"]);
  });

  it("keeps interleaved wildcard blocks pinned to their absolute slots", () => {
    // File: Host * | a | b | Host *.web | c — concrete subsequence is [a, b, c].
    const file = [wild("*"), h("a"), h("b"), wild("*.web"), h("c")];
    // Drag `a` (concrete idx 0) below `c` (gap 3).
    expect(buildNewOrder(file, 0, 3)).toEqual(["*", "b", "c", "*.web", "a"]);
    // Drag `c` (concrete idx 2) to the very top (gap 0) — `*.web` keeps its
    // absolute slot, so the remaining concrete hosts flow around it.
    expect(buildNewOrder(file, 2, 0)).toEqual(["*", "c", "a", "*.web", "b"]);
  });

  it("always returns the EXHAUSTIVE alias order (wildcards included)", () => {
    const file = [wild("*"), h("a"), h("b")];
    const order = buildNewOrder(file, 0, 2);
    expect(order).toHaveLength(file.length);
    expect(order).toContain("*");
  });

  it("clamps an out-of-range gap to the list bounds", () => {
    expect(buildNewOrder(abc, 0, 99)).toEqual(["b", "c", "a"]);
    expect(buildNewOrder(abc, 2, -5)).toEqual(["c", "a", "b"]);
  });

  it("returns the current order unchanged for an out-of-range source index", () => {
    expect(buildNewOrder(abc, 7, 0)).toEqual(["a", "b", "c"]);
    expect(buildNewOrder(abc, -1, 0)).toEqual(["a", "b", "c"]);
  });
});

describe("applyOrderToHosts", () => {
  const FILE = "/me/.ssh/config";
  const OTHER = "/etc/ssh/ssh_config";
  const host = (alias: string, source_file: string) => ({
    alias,
    patterns: [alias],
    source_file,
  });

  it("reorders only the target file's hosts, in their existing global slots", () => {
    const hosts = [
      host("a", FILE),
      host("x", OTHER),
      host("b", FILE),
      host("c", FILE),
    ];
    const out = applyOrderToHosts(hosts, FILE, ["c", "a", "b"]);
    expect(out.map((h2) => h2.alias)).toEqual(["c", "x", "a", "b"]);
    // Other files' hosts are the SAME objects, untouched.
    expect(out[1]).toBe(hosts[1]);
  });

  it("mirrors the backend: aliases missing from order sink AFTER the named ones", () => {
    const hosts = [host("a", FILE), host("b", FILE), host("c", FILE)];
    const out = applyOrderToHosts(hosts, FILE, ["c"]);
    expect(out.map((h2) => h2.alias)).toEqual(["c", "a", "b"]);
  });

  it("matches an alias against ANY pattern of a block", () => {
    const multi = { alias: "web", patterns: ["web", "www"], source_file: FILE };
    const hosts = [host("a", FILE), multi];
    const out = applyOrderToHosts(hosts, FILE, ["www", "a"]);
    expect(out.map((h2) => h2.alias)).toEqual(["web", "a"]);
  });

  it("ignores aliases that match nothing", () => {
    const hosts = [host("a", FILE), host("b", FILE)];
    const out = applyOrderToHosts(hosts, FILE, ["ghost", "b", "a"]);
    expect(out.map((h2) => h2.alias)).toEqual(["b", "a"]);
  });
});
