// Real terminal engine and renderer; no SSH connections or native commands.
import { WTerm } from "@wterm/dom";
import { GhosttyCore } from "@wterm/ghostty";
import ghosttyWasm from "@wterm/ghostty/ghostty-vt.wasm?url";
import "@/index.css";
import "@wterm/dom/css";
import "@/components/records/terminal.css";

const host = document.getElementById("terminal")!;
const core = await GhosttyCore.load({ wasmPath: ghosttyWasm, scrollbackLimit: 8 * 1024 * 1024, imageStorageLimit: 0 });
const input: string[] = [];
const term = new WTerm(host, { core, cols: 80, rows: 24, autoResize: true, onData: (data) => input.push(data) });
await term.init();
await document.fonts.ready;
term.fit();
Object.assign(window, {
  __terminalTest: {
    write: (text: string) => term.write(new TextEncoder().encode(text)),
    focus: () => term.focus(),
    resize: (cols: number, rows: number) => term.resize(cols, rows),
    writeBytes: (bytes: number[]) => term.write(new Uint8Array(bytes)),
    snapshot: () => {
      const row = host.querySelector(".term-row:not(.term-scrollback-row)")!;
      const bounds = host.getBoundingClientRect();
      const first = row.getBoundingClientRect();
      return {
        scrollTop: host.scrollTop,
        history: core.getScrollbackCount(),
        alternate: core.usingAltScreen(),
        rowVisible: first.top >= bounds.top && first.bottom <= bounds.bottom,
        text: host.querySelector(".term-grid")!.textContent,
        input: [...input],
      };
    },
  },
});
