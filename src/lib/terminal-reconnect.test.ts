import { readFileSync } from "node:fs";
import { GhosttyCore } from "@wterm/ghostty";
import { describe, expect, it } from "vitest";
import { RECONNECT_TERMINAL_OUTPUT } from "./terminal-reconnect";

const wasmPath = "data:application/wasm;base64," + readFileSync("node_modules/@wterm/ghostty/wasm/ghostty-vt.wasm").toString("base64");
function retainedText(core: GhosttyCore) {
  const lines = [];
  for (let row = 0; row < core.getScrollbackCount(); row++) {
    lines.push(Array.from({ length: core.getCols() }, (_, col) => String.fromCodePoint(core.getScrollbackCell(row, col).char || 32)).join(""));
  }
  for (let row = 0; row < core.getRows(); row++) {
    lines.push(Array.from({ length: core.getCols() }, (_, col) => String.fromCodePoint(core.getCell(row, col).char || 32)).join(""));
  }
  return lines.join("\n");
}
describe("reconnecting the actual Ghostty VT", () => {
  it.each(["", "\x1b[", "\x1b]0;partial title", "\x1bPpartial DCS", new Uint8Array([0xe4, 0xb8])])("preserves output while recovering from a partial %j sequence", async (partial) => {
    const core = await GhosttyCore.load({ wasmPath, scrollbackLimit: 8 * 1024 * 1024, imageStorageLimit: 0 });
    try {
      core.init(80, 24);
      for (let row = 0; row < 50; row++) core.writeString(`RETAIN-${row}\r\n`);
      core.writeString("\x1b[?1049h\x1b[?2004h\x1b[?1003h\x1b[?1004h\x1b[?1006h\x1b[>31u\x1b[31m");
      if (typeof partial === "string") core.writeString(partial); else core.writeRaw(partial);
      core.writeString(RECONNECT_TERMINAL_OUTPUT); core.writeString("NEW-SHELL");
      expect(core.usingAltScreen()).toBe(false); expect(core.bracketedPaste()).toBe(false);
      expect(core.mouseTracking()).toBe(0); expect(core.focusEvents()).toBe(false); expect(core.kittyKeyboardFlags()).toBe(0);
      const text = retainedText(core);
      expect(text).toContain("RETAIN-0"); expect(text).toContain("RETAIN-49");
      expect(text).toContain("── Reconnecting ──"); expect(text).toContain("NEW-SHELL");
    } finally { core.dispose(); }
  });
});
