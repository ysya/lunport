import { describe, expect, it } from "vitest";

import { isImeKey } from "./ime";

const key = (isComposing: boolean, keyCode: number) => ({ nativeEvent: { isComposing }, keyCode });

describe("isImeKey", () => {
  it("is true while a composition is running (the browser says so)", () => {
    expect(isImeKey(key(true, 13))).toBe(true);
  });

  it("is true for the Enter that commits one in WebKit: no isComposing any more, but key code 229", () => {
    expect(isImeKey(key(false, 229))).toBe(true);
  });

  it("is false for a plain Enter", () => {
    expect(isImeKey(key(false, 13))).toBe(false);
  });
});
