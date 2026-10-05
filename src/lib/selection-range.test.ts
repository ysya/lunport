import { describe, expect, it } from "vitest";
import { rangeBetween, rowClickKind } from "./selection-range";

const visible = ["a", "b", "c", "d", "e"];

describe("rangeBetween", () => {
  it("selects forward from anchor to target, inclusive", () => {
    expect(rangeBetween(visible, "b", "d")).toEqual(["b", "c", "d"]);
  });

  it("selects backward when the target sits above the anchor", () => {
    expect(rangeBetween(visible, "d", "b")).toEqual(["b", "c", "d"]);
  });

  it("degrades to the target alone when the anchor is null", () => {
    expect(rangeBetween(visible, null, "c")).toEqual(["c"]);
  });

  it("degrades to the target alone when the anchor is no longer visible", () => {
    expect(rangeBetween(visible, "gone", "c")).toEqual(["c"]);
  });

  it("returns just the row when anchor and target are the same", () => {
    expect(rangeBetween(visible, "c", "c")).toEqual(["c"]);
  });

  it("returns nothing when the target is not visible", () => {
    expect(rangeBetween(visible, "a", "zzz")).toEqual([]);
  });
});

describe("rowClickKind", () => {
  const keys = (held: Partial<{ metaKey: boolean; ctrlKey: boolean; shiftKey: boolean }> = {}) => ({
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    ...held,
  });

  it("toggles the row on ⌘/Ctrl-click, ranges on Shift-click, and selects on a plain click", () => {
    expect(rowClickKind(keys({ metaKey: true }), true)).toBe("toggle");
    expect(rowClickKind(keys({ ctrlKey: true }), true)).toBe("toggle");
    expect(rowClickKind(keys({ shiftKey: true }), true)).toBe("range");
    expect(rowClickKind(keys(), true)).toBe("select");
  });

  it("lets ⌘/Ctrl win over Shift, as the click always did", () => {
    expect(rowClickKind(keys({ metaKey: true, shiftKey: true }), true)).toBe("toggle");
    expect(rowClickKind(keys({ ctrlKey: true, shiftKey: true }), true)).toBe("toggle");
  });

  it("leaves the checked rows alone when a row that cannot be checked is ⌘/Ctrl- or Shift-clicked: it neither joins them nor clears them", () => {
    expect(rowClickKind(keys({ metaKey: true }), false)).toBe("keep");
    expect(rowClickKind(keys({ ctrlKey: true }), false)).toBe("keep");
    expect(rowClickKind(keys({ shiftKey: true }), false)).toBe("keep");
    expect(rowClickKind(keys({ metaKey: true, shiftKey: true }), false)).toBe("keep");
  });

  it("still clears the checked rows on a plain click, whether or not the row can be checked", () => {
    expect(rowClickKind(keys(), false)).toBe("select");
  });
});
