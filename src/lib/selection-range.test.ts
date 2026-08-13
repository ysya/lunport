import { describe, expect, it } from "vitest";
import { rangeBetween } from "./selection-range";

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
