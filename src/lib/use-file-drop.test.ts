import { describe, expect, it } from "vitest";
import { droppedPath } from "./use-file-drop";

describe("a dropped key file", () => {
  it("is the one path of a single-file drop", () => {
    expect(droppedPath({ type: "drop", paths: ["/home/f/Downloads/id_work"] })).toBe("/home/f/Downloads/id_work");
    expect(droppedPath({ type: "drop", paths: ["/a", "/b"] })).toBeNull();
    expect(droppedPath({ type: "enter", paths: ["/a"] })).toBeNull();
    expect(droppedPath({ type: "leave" })).toBeNull();
  });
});
