import { Channel } from "@tauri-apps/api/core";
import { tauriInvoke } from "./ipc";

export type TerminalHost = { id: string } | { alias: string };

export type TerminalEvent =
  | { type: "opened"; session_id: string }
  | { type: "event"; event: "connected" | "disconnected" | "error" | "banner"; kind?: string; text?: string; reason?: string }
  | { type: "question"; text: string }
  | { type: "exited"; code: number | null; signal: string | null }
  | { type: "closed" }
  | { type: "bridge_error"; text: string };

/** One native broker session. Output stays binary, outside React state. */
export class EmbeddedTerminal {
  readonly id = crypto.randomUUID();
  private disposed = false;
  private opened = false;
  private pending = 0;
  private sent = Promise.resolve();
  private received = 0;
  private acknowledged = 0;
  private acking = false;
  private opening: Promise<void> | null = null;
  private closing: Promise<void> | null = null;
  private output = new Channel<ArrayBuffer>();
  private dimensions: { cols: number; rows: number } | null = null;

  constructor(private writeOutput: (bytes: Uint8Array) => void, private event: (event: TerminalEvent) => void) {
    this.output.onmessage = (buffer) => {
      if (this.disposed) return;
      const packet = new Uint8Array(buffer);
      try {
        if (packet[0] === 0) {
          this.writeOutput(packet.subarray(1));
          this.received += packet.length - 1;
          void this.acknowledge();
        } else if (packet[0] === 1) {
          const event = JSON.parse(new TextDecoder().decode(packet.subarray(1))) as TerminalEvent;
          if (event.type === "opened") {
            this.opened = true;
            // The pane/font can change while native authentication is pending.
            if (this.dimensions) this.resize(this.dimensions.cols, this.dimensions.rows);
          }
          if (event.type === "closed" || event.type === "exited" || event.type === "bridge_error") this.opened = false;
          if (event.type === "event" && (event.event === "error" || event.event === "disconnected")) this.opened = false;
          this.event(event);
        } else throw new Error("Unknown terminal packet");
      } catch (error) { this.fail(error); }
    };
  }
  async start(host: TerminalHost, cols: number, rows: number) {
    if (this.disposed) return;
    this.dimensions = { cols, rows };
    this.opening = tauriInvoke("terminal_open", { id: this.id, host, cols, rows, output: this.output });
    try {
      await this.opening;
    } catch (error) { this.fail(error); }
    finally { this.opening = null; }
  }
  private async acknowledge() {
    if (this.acking || this.disposed) return;
    this.acking = true;
    try {
      while (!this.disposed && this.acknowledged < this.received) {
        const total = this.received;
        await tauriInvoke("terminal_ack", { id: this.id, total });
        this.acknowledged = total;
      }
    } catch { /* A final packet can race the broker's normal EOF cleanup. */ }
    finally { this.acking = false; }
  }
  input(data: Uint8Array) {
    if (!this.opened || this.disposed) return;
    if (this.pending + data.length > 512 * 1024) { this.fail("Too much pending terminal input. Reconnect before continuing."); return; }
    for (let offset = 0; offset < data.length; offset += 16 * 1024) {
      const bytes = data.slice(offset, offset + 16 * 1024);
      this.pending += bytes.length;
      this.sent = this.sent.then(async () => {
        try { if (!this.disposed && this.opened) await tauriInvoke("terminal_write", { id: this.id, data: Array.from(bytes) }); }
        finally { this.pending -= bytes.length; bytes.fill(0); }
      }).catch((error) => this.fail(error));
    }
  }
  resize(cols: number, rows: number) {
    if (this.disposed || cols < 1 || rows < 1) return;
    this.dimensions = { cols, rows };
    if (!this.opened) return;
    this.sent = this.sent.then(async () => {
      if (!this.disposed && this.opened) await tauriInvoke("terminal_resize", { id: this.id, cols, rows });
    }).catch((error) => this.fail(error));
  }
  private fail(error: unknown) {
    if (this.disposed) return;
    this.event({ type: "bridge_error", text: String(error) });
    this.close();
  }
  close() {
    if (this.closing) return this.closing;
    this.disposed = true;
    this.opened = false;
    const opening = this.opening;
    const stop = () => tauriInvoke<void>("terminal_close", { id: this.id }).catch(() => {});
    this.closing = (async () => {
      await stop();
      // An open still registering on the native worker must finish and be closed
      // before a replacement consumes the same workspace's session budget.
      if (opening) { await opening.catch(() => {}); await stop(); }
    })();
    return this.closing;
  }
}
