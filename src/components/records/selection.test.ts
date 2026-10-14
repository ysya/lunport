import { describe, expect, it } from "vitest";
import { decideHostSelection } from "./selection";

describe("host draft navigation", () => {
  it("keeps the current editor mounted while its operation is in flight", () => {
    expect(
      decideHostSelection(
        { kind: "new", nonce: 1 },
        { kind: "host", id: "saved" },
        false,
        true,
      ),
    ).toBe("keep");
  });
  it("requires discarding a dirty draft before replacing it", () => {
    expect(
      decideHostSelection(
        { kind: "host", id: "a" },
        { kind: "host", id: "b" },
        true,
        false,
      ),
    ).toBe("confirm");
    expect(
      decideHostSelection(
        { kind: "new", nonce: 1 },
        { kind: "new", nonce: 2 },
        true,
        false,
      ),
    ).toBe("confirm");
  });
  it("returns to the same saved host without discarding its draft", () => {
    expect(
      decideHostSelection(
        { kind: "host", id: "a" },
        { kind: "host", id: "a" },
        true,
        false,
      ),
    ).toBe("keep");
  });
  it("selects a different host when no draft would be lost", () => {
    expect(
      decideHostSelection(
        { kind: "none" },
        { kind: "host", id: "a" },
        false,
        false,
      ),
    ).toBe("select");
  });
});
