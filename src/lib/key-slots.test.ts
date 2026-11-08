import { describe, expect, it } from "vitest";

import { isValidSlotName } from "./key-slots";

describe("slot names", () => {
  it("accepts the slot names the backend accepts", () => {
    for (const ok of ["id_ed25519", "work", "a", "Key.2026_v-1", "k".repeat(64)]) expect(isValidSlotName(ok)).toBe(true);
    for (const bad of ["", "-x", ".x", "a b", "a/b", "id.pub", "ID.PUB", "k".repeat(65), "鍵"]) expect(isValidSlotName(bad)).toBe(false);
  });
});
