import { describe, expect, it } from "vitest";
import type { HostSummary } from "@/bindings/HostSummary";
import { hostMatches, parseQuery } from "./host-filter";

function host(over: Partial<HostSummary> = {}): HostSummary {
  return {
    alias: "web-1",
    patterns: ["web-1"],
    source_file: "/home/f/.ssh/config",
    tags: ["prod", "web"],
    hostname: "10.0.0.9",
    user: "deploy",
    ...over,
  };
}

const match = (q: string, h: HostSummary = host()) =>
  hostMatches(h, parseQuery(q));

describe("free-text matching", () => {
  it("matches everything on an empty query", () => {
    expect(match("")).toBe(true);
    expect(match("   ")).toBe(true);
  });

  it("matches alias, patterns, tags and source file", () => {
    expect(match("web-1")).toBe(true);
    expect(match("prod")).toBe(true);
    expect(match("config")).toBe(true);
  });

  it("matches hostname and user in free text (previous gap)", () => {
    expect(match("10.0.0.9")).toBe(true);
    expect(match("deploy")).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(match("WEB-1")).toBe(true);
    expect(match("Deploy")).toBe(true);
  });

  it("rejects non-matching text", () => {
    expect(match("nas")).toBe(false);
  });
});

describe("#tag prefix", () => {
  it("matches a tag substring, case-insensitively", () => {
    expect(match("#prod")).toBe(true);
    expect(match("#PRO")).toBe(true);
  });

  it("does not match tag terms against other fields", () => {
    // "deploy" is the user, not a tag.
    expect(match("#deploy")).toBe(false);
  });

  it("treats a bare # as incomplete input, not a filter", () => {
    expect(match("#")).toBe(true);
  });
});

describe("@user prefix", () => {
  it("matches the user, case-insensitively", () => {
    expect(match("@deploy")).toBe(true);
    expect(match("@DEP")).toBe(true);
  });

  it("does not match user terms against other fields", () => {
    // "prod" is a tag, not the user.
    expect(match("@prod")).toBe(false);
  });

  it("never matches hosts without a user", () => {
    expect(match("@deploy", host({ user: null }))).toBe(false);
  });

  it("treats a bare @ as incomplete input, not a filter", () => {
    expect(match("@")).toBe(true);
  });
});

describe("combined terms (AND)", () => {
  it("requires every term to match", () => {
    expect(match("#prod @deploy web")).toBe(true);
    expect(match("#prod @deploy nas")).toBe(false);
    expect(match("#staging @deploy")).toBe(false);
  });
});
