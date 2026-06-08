import { describe, it, expect } from "vitest";
import type { HostOption } from "@/bindings/HostOption";
import { computeChanges, FIRST_CLASS_KEYS, FIELD_DEFS } from "@/lib/hostFields";

/** Helper: build a HostOption (enabled defaults to true). */
function opt(keyword: string, value: string, enabled = true): HostOption {
  return { keyword, value, enabled };
}

describe("FIRST_CLASS_KEYS", () => {
  it("contains every FIELD_DEFS keyword, lowercased", () => {
    for (const def of FIELD_DEFS) {
      expect(FIRST_CLASS_KEYS.has(def.keyword.toLowerCase())).toBe(true);
    }
    expect(FIRST_CLASS_KEYS.size).toBe(FIELD_DEFS.length);
  });
});

describe("computeChanges", () => {
  it("emits a set when a value changes", () => {
    const original = [opt("HostName", "old.example.com")];
    const desired = [{ keyword: "HostName", value: "new.example.com" }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "HostName", value: "new.example.com", remove: false },
    ]);
  });

  it("emits a set for a new field not present in original", () => {
    const original: HostOption[] = [];
    const desired = [{ keyword: "Port", value: "2222" }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "Port", value: "2222", remove: false },
    ]);
  });

  it("emits a remove when a previously-set field is cleared", () => {
    const original = [opt("User", "alice")];
    const desired = [{ keyword: "User", value: "" }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "User", value: "", remove: true },
    ]);
  });

  it("emits a remove when a previously-set field is dropped entirely from desired", () => {
    const original = [opt("ForwardAgent", "yes")];
    const desired: { keyword: string; value: string }[] = [];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "ForwardAgent", value: "", remove: true },
    ]);
  });

  it("omits unchanged fields", () => {
    const original = [opt("HostName", "host.example.com"), opt("Port", "22")];
    const desired = [
      { keyword: "HostName", value: "host.example.com" },
      { keyword: "Port", value: "22" },
    ];
    expect(computeChanges(original, desired)).toEqual([]);
  });

  it("matches keywords case-insensitively (unchanged → omitted)", () => {
    const original = [opt("HostName", "host.example.com")];
    // Form re-uses canonical casing but original could be lowercased on disk.
    const original2 = [opt("hostname", "host.example.com")];
    const desired = [{ keyword: "HostName", value: "host.example.com" }];
    expect(computeChanges(original, desired)).toEqual([]);
    expect(computeChanges(original2, desired)).toEqual([]);
  });

  it("matches keywords case-insensitively (changed → set, preserves desired casing)", () => {
    const original = [opt("hostname", "old")];
    const desired = [{ keyword: "HostName", value: "new" }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "HostName", value: "new", remove: false },
    ]);
  });

  it("matches keywords case-insensitively (cleared → remove, preserves original casing)", () => {
    const original = [opt("ForwardAgent", "yes")];
    const desired = [{ keyword: "forwardagent", value: "" }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "ForwardAgent", value: "", remove: true },
    ]);
  });

  it("omits an empty desired value that has no original entry (no spurious remove)", () => {
    const original: HostOption[] = [];
    const desired = [{ keyword: "Port", value: "" }];
    expect(computeChanges(original, desired)).toEqual([]);
  });

  it("omits an empty desired value when original was also empty", () => {
    const original = [opt("Port", "")];
    const desired = [{ keyword: "Port", value: "" }];
    expect(computeChanges(original, desired)).toEqual([]);
  });

  it("treats whitespace-only values as empty (trim semantics)", () => {
    const original = [opt("User", "alice")];
    const desired = [{ keyword: "User", value: "   " }];
    expect(computeChanges(original, desired)).toEqual([
      { keyword: "User", value: "", remove: true },
    ]);
  });

  it("uses first-occurrence-wins on both sides", () => {
    // Backend first-match semantics: only the first HostName matters.
    const original = [opt("HostName", "first"), opt("HostName", "second")];
    const desired = [
      { keyword: "HostName", value: "first" }, // matches first orig → unchanged
      { keyword: "HostName", value: "ignored" },
    ];
    expect(computeChanges(original, desired)).toEqual([]);
  });

  it("handles a mixed change set (set + new + remove + unchanged)", () => {
    const original = [
      opt("HostName", "old.example.com"),
      opt("User", "alice"),
      opt("Port", "22"),
    ];
    const desired = [
      { keyword: "HostName", value: "new.example.com" }, // changed → set
      { keyword: "User", value: "" }, // cleared → remove
      { keyword: "Port", value: "22" }, // unchanged → omit
      { keyword: "Compression", value: "yes" }, // new → set
    ];
    const result = computeChanges(original, desired);
    expect(result).toEqual(
      expect.arrayContaining([
        { keyword: "HostName", value: "new.example.com", remove: false },
        { keyword: "Compression", value: "yes", remove: false },
        { keyword: "User", value: "", remove: true },
      ]),
    );
    expect(result).toHaveLength(3);
  });
});
