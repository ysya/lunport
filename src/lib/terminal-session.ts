import { EmbeddedTerminal, type TerminalEvent, type TerminalHost } from "./embedded-terminal";
import type { TerminalState } from "@/stores/terminals";

export type TerminalStatus = { kind: TerminalState; text: string; retry?: number; question?: boolean; autoReconnect: boolean };
const RETRY_DELAYS = [2000, 5000, 10000, 20000, 30000];
const STABLE_CONNECTION_MS = 10000;

/** A tab owns one renderer and replaces only its SSH transport. Nothing typed on
 * a lost connection is buffered or replayed into the replacement shell. */
export class TerminalSession {
  private transport: EmbeddedTerminal | null = null;
  private closing = Promise.resolve();
  private disposed = false;
  private generation = 0;
  private attempted = false;
  private recovery = false;
  private waitingForNetwork = false;
  private retries = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private cols = 80;
  private rows = 24;
  private status: TerminalStatus = { kind: "connecting", text: "Connecting…", autoReconnect: true };

  constructor(
    private host: TerminalHost,
    private output: (bytes: Uint8Array) => void,
    private changed: (status: TerminalStatus) => void,
    private beforeReconnect: () => void,
  ) {}

  start(cols: number, rows: number) {
    this.cols = cols; this.rows = rows;
    return this.connect(false);
  }

  reconnect() {
    this.retries = 0;
    return this.connect(false);
  }

  private update(status: Omit<TerminalStatus, "autoReconnect">) {
    if (this.disposed) return;
    this.status = { ...status, autoReconnect: this.status.autoReconnect };
    this.changed(this.status);
  }

  private clearRetry() {
    clearTimeout(this.timer);
    this.timer = undefined;
  }

  private async connect(automatic: boolean) {
    if (this.disposed) return;
    this.clearRetry();
    this.waitingForNetwork = false;
    const generation = ++this.generation;
    this.recovery = automatic;
    if (this.transport) this.closing = this.transport.close();
    this.transport = null;
    this.update({ kind: "connecting", text: automatic ? `Reconnecting… (${this.retries}/${RETRY_DELAYS.length})` : "Connecting…" });
    await this.closing;
    if (this.disposed || generation !== this.generation) return;
    try { if (this.attempted) this.beforeReconnect(); }
    catch (error) { this.update({ kind: "error", text: String(error) }); return; }
    this.attempted = true;
    let openedAt: number | undefined;
    let retryable = false;
    let exited = false;
    let finished = false;
    const transport = new EmbeddedTerminal(
      (bytes) => { if (!this.disposed && generation === this.generation) this.output(bytes); },
      (event: TerminalEvent) => {
        if (this.disposed || generation !== this.generation || finished) return;
        if (event.type === "opened") {
          openedAt = Date.now();
          this.recovery = false;
          this.update({ kind: "open", text: "Connected" });
        } else if (event.type === "question") {
          this.update({ kind: "connecting", text: event.text, question: true });
        } else if (event.type === "event" && (event.event === "error" || event.event === "disconnected")) {
          retryable = event.event === "disconnected" || event.kind === "connect" || event.kind === "input";
          this.update({ kind: "error", text: event.text ?? event.reason ?? "Connection failed" });
        } else if (event.type === "bridge_error") {
          finished = true;
          this.recovery = false;
          this.update({ kind: "error", text: event.text });
        } else if (event.type === "exited") {
          exited = true;
          if (event.code !== null || event.signal !== null) retryable = false;
          if (this.status.kind !== "error") this.update({ kind: "ended", text: event.signal ? `Ended (${event.signal})` : event.code === null ? "Disconnected" : `Shell exited (${event.code})` });
        } else if (event.type === "closed") {
          finished = true;
          if (!exited && this.status.kind !== "error") {
            retryable = true;
            this.update({ kind: "ended", text: "Disconnected" });
          }
          if (openedAt !== undefined && Date.now() - openedAt >= STABLE_CONNECTION_MS) this.retries = 0;
          if (retryable && this.status.autoReconnect && (openedAt !== undefined || this.recovery)) {
            const delay = RETRY_DELAYS[this.retries];
            if (delay !== undefined) {
              const retry = ++this.retries;
              this.recovery = true;
              this.update({ kind: "connecting", text: `Waiting to reconnect (${retry}/${RETRY_DELAYS.length})`, retry });
              this.timer = setTimeout(() => { this.timer = undefined; void this.connect(true); }, delay);
              return;
            }
            this.update({ kind: "error", text: "Automatic reconnect paused after 5 attempts. Try again when the connection is available." });
            this.waitingForNetwork = true;
          }
          this.recovery = false;
        }
      },
    );
    this.transport = transport;
    await transport.start(this.host, this.cols, this.rows);
  }

  input(data: Uint8Array) { if (this.status.kind === "open") this.transport?.input(data); }
  resize(cols: number, rows: number) { this.cols = cols; this.rows = rows; this.transport?.resize(cols, rows); }

  networkRestored() {
    if (!this.status.autoReconnect || this.disposed || !this.timer && !this.waitingForNetwork) return;
    this.retries = 0;
    void this.connect(true);
  }

  setAutoReconnect(enabled: boolean) {
    this.status = { ...this.status, autoReconnect: enabled };
    if (!enabled && this.recovery) this.disconnect();
    else this.changed(this.status);
  }

  disconnect() {
    this.clearRetry();
    this.generation++;
    this.recovery = false;
    this.waitingForNetwork = false;
    if (this.transport) this.closing = this.transport.close();
    this.transport = null;
    this.update({ kind: "ended", text: "Disconnected" });
  }

  dispose() {
    this.disposed = true;
    this.disconnect();
  }
}
