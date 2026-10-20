import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TerminalEvent } from "./embedded-terminal";

const mocks = vi.hoisted(() => ({ transports: [] as {
  output: (bytes: Uint8Array) => void;
  event: (event: TerminalEvent) => void;
  start: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  input: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
}[] }));
vi.mock("./embedded-terminal", () => ({ EmbeddedTerminal: class {
  start = vi.fn().mockResolvedValue(undefined);
  close = vi.fn().mockResolvedValue(undefined);
  input = vi.fn(); resize = vi.fn();
  constructor(public output: (bytes: Uint8Array) => void, public event: (event: TerminalEvent) => void) { mocks.transports.push(this); }
} }));
import { TerminalSession, type TerminalStatus } from "./terminal-session";

let session: TerminalSession;
let statuses: TerminalStatus[];
let output: ReturnType<typeof vi.fn<(bytes: Uint8Array) => void>>;
let prepare: ReturnType<typeof vi.fn<() => void>>;
const current = () => mocks.transports[mocks.transports.length - 1];
const status = () => statuses[statuses.length - 1];
const open = () => current().event({ type: "opened", session_id: "ssh" });
const end = (code: number | null = null, signal: string | null = null) => {
  current().event({ type: "exited", code, signal }); current().event({ type: "closed" });
};
const lost = () => { current().event({ type: "event", event: "disconnected", reason: "Connection reset by peer" }); end(); };
const failed = (kind = "connect") => { current().event({ type: "event", event: "error", kind, text: `${kind} failed` }); end(); };
beforeEach(() => {
  vi.useFakeTimers(); mocks.transports.length = 0; statuses = [];
  output = vi.fn(); prepare = vi.fn();
  session = new TerminalSession({ id: "saved-host" }, output, (state) => statuses.push(state), prepare);
});
afterEach(() => { session.dispose(); vi.clearAllTimers(); vi.useRealTimers(); });

describe("terminal reconnect lifecycle", () => {
  it("retains a missing-key error through EOF without retrying, and clears its cause on manual retry", async () => {
    await session.start(80, 24);
    const text = "simple needs key fc3f11fff708a1229b4e877f447dbf7f material on this device.";
    current().event({ type: "event", event: "error", kind: "host", text });
    end();
    expect(status()).toMatchObject({ kind: "error", failureKind: "host", text });
    session.networkRestored();
    await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(1);
    await session.reconnect();
    expect(status().failureKind).toBeUndefined();
    open();
    expect(status()).toMatchObject({ kind: "open", text: "Connected" });
  });
  it("replaces the transport in the same renderer, retaining output and ignoring old callbacks", async () => {
    await session.start(100, 40); open();
    const old = current(); old.output(Uint8Array.of(65));
    await session.reconnect(); open(); current().output(Uint8Array.of(66));
    old.output(Uint8Array.of(67)); old.event({ type: "closed" });
    expect(output.mock.calls.map(([bytes]) => [...bytes])).toEqual([[65], [66]]);
    expect(old.close).toHaveBeenCalledOnce(); expect(prepare).toHaveBeenCalledOnce();
    expect(current().start).toHaveBeenCalledWith({ id: "saved-host" }, 100, 40);
    expect(status().kind).toBe("open");
  });

  it("serializes rapid reconnects behind pending cleanup and starts with the latest size", async () => {
    await session.start(80, 24); open(); const old = current();
    let release!: () => void;
    old.close.mockReturnValue(new Promise<void>((resolve) => { release = resolve; }));
    const first = session.reconnect(); const second = session.reconnect();
    session.resize(120, 45); session.input(Uint8Array.of(13));
    expect(mocks.transports).toHaveLength(1); expect(old.input).not.toHaveBeenCalled();
    release(); await Promise.all([first, second]);
    expect(mocks.transports).toHaveLength(2); expect(prepare).toHaveBeenCalledOnce();
    expect(current().start).toHaveBeenCalledWith({ id: "saved-host" }, 120, 45);
  });

  it("retries a lost connection automatically with backoff, then pauses until an online event", async () => {
    await session.start(80, 24); open(); lost();
    expect(status()).toMatchObject({ kind: "connecting", retry: 1 });
    await vi.advanceTimersByTimeAsync(1999); expect(mocks.transports).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); expect(mocks.transports).toHaveLength(2);
    for (const delay of [5000, 10000, 20000, 30000]) {
      failed(); await vi.advanceTimersByTimeAsync(delay);
    }
    expect(mocks.transports).toHaveLength(6);
    failed(); expect(status().text).toContain("paused after 5 attempts");
    await vi.advanceTimersByTimeAsync(120000); expect(mocks.transports).toHaveLength(6);
    session.networkRestored(); await Promise.resolve();
    expect(mocks.transports).toHaveLength(7);
  });

  it("an online event expedites one pending retry without duplicating it", async () => {
    await session.start(80, 24); open(); lost();
    session.networkRestored(); session.networkRestored(); await Promise.resolve();
    expect(mocks.transports).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(30000); expect(mocks.transports).toHaveLength(2);
  });

  it.each(["auth", "host_key", "host", "shell", "protocol", "unsupported"])("stops automatic retry after a %s error", async (kind) => {
    await session.start(80, 24); open(); lost(); await vi.advanceTimersByTimeAsync(2000);
    current().event({ type: "question", text: "Authentication required" });
    await vi.advanceTimersByTimeAsync(60000); expect(mocks.transports).toHaveLength(2);
    expect(status().question).toBe(true);
    failed(kind); session.networkRestored(); await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(2); expect(status().kind).toBe("error");
  });

  it.each([[0, null], [7, null], [null, "TERM"]] as const)("respects an explicit shell exit (%s, %s)", async (code, signal) => {
    await session.start(80, 24); open(); end(code, signal);
    session.networkRestored(); await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(1); expect(status().kind).toBe("ended");
  });

  it("keeps a first failed login user-controlled and never replays disconnected input", async () => {
    await session.start(80, 24); session.input(Uint8Array.of(65)); failed();
    session.input(Uint8Array.of(66)); await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(1); expect(current().input).not.toHaveBeenCalled();
    await session.reconnect(); open(); session.input(Uint8Array.of(67));
    expect(current().input).toHaveBeenCalledExactlyOnceWith(Uint8Array.of(67));
  });

  it("manual disconnect and tab disposal cancel all pending retries", async () => {
    await session.start(80, 24); open(); lost(); session.disconnect();
    session.networkRestored(); await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(1); expect(status().kind).toBe("ended");
    await session.reconnect(); open(); lost(); session.dispose();
    await vi.advanceTimersByTimeAsync(120000); expect(mocks.transports).toHaveLength(2);
  });

  it("does not resurrect a tab disposed while cleanup is pending", async () => {
    await session.start(80, 24); open();
    let release!: () => void;
    current().close.mockReturnValue(new Promise<void>((resolve) => { release = resolve; }));
    const connecting = session.reconnect(); session.dispose(); release(); await connecting;
    expect(mocks.transports).toHaveLength(1);
  });

  it("the per-tab automatic reconnect choice survives manual reconnects", async () => {
    await session.start(80, 24); open(); session.setAutoReconnect(false);
    expect(status()).toMatchObject({ kind: "open", autoReconnect: false });
    lost(); await vi.advanceTimersByTimeAsync(30000); expect(mocks.transports).toHaveLength(1);
    await session.reconnect(); open(); expect(status().autoReconnect).toBe(false);
    session.setAutoReconnect(true); lost(); session.setAutoReconnect(false);
    await vi.advanceTimersByTimeAsync(30000); expect(mocks.transports).toHaveLength(2);
  });

  it("bounds flapping connections, and replenishes retries only after a stable connection", async () => {
    await session.start(80, 24); open(); lost(); await vi.advanceTimersByTimeAsync(2000);
    open(); lost(); expect(status().retry).toBe(2);
    await vi.advanceTimersByTimeAsync(5000); open(); await vi.advanceTimersByTimeAsync(10000);
    lost(); expect(status().retry).toBe(1);
  });

  it("does not auto-retry client-side bridge/input failures", async () => {
    await session.start(80, 24); open();
    current().event({ type: "bridge_error", text: "Too much pending terminal input" });
    current().event({ type: "closed" });
    await vi.advanceTimersByTimeAsync(120000);
    expect(mocks.transports).toHaveLength(1); expect(status().text).toContain("Too much pending");
  });
});
