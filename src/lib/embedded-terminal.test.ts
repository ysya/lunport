import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), channels: [] as { onmessage: (value: ArrayBuffer) => void }[] }));
vi.mock("./ipc", () => ({ tauriInvoke: mocks.invoke }));
vi.mock("@tauri-apps/api/core", () => ({ Channel: class { onmessage = () => {}; constructor() { mocks.channels.push(this); } } }));
import { EmbeddedTerminal } from "./embedded-terminal";
const packet = (type: number, bytes: Uint8Array) => mocks.channels[0].onmessage(Uint8Array.from([type, ...bytes]).buffer);
const event = (value: unknown) => packet(1, new TextEncoder().encode(JSON.stringify(value)));
const open = () => event({ type: "opened", session_id: "broker-session" });
beforeEach(() => { mocks.invoke.mockReset().mockResolvedValue(undefined); mocks.channels.length = 0; });

describe("embedded SSH transport", () => {
  it("sends the latest pane size after authentication, including font changes while waiting", async () => {
    const terminal = new EmbeddedTerminal(vi.fn(), vi.fn());
    await terminal.start("host", 80, 24);
    terminal.resize(100, 40); terminal.resize(110, 35);
    expect(mocks.invoke.mock.calls.some(([name]) => name === "terminal_resize")).toBe(false);
    open();
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("terminal_resize", { id: terminal.id, cols: 110, rows: 35 }));
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "terminal_resize")).toHaveLength(1);
    terminal.close();
  });
  it("preserves split UTF-8, escape and binary bytes without decoding", async () => {
    const output = vi.fn(); const terminal = new EmbeddedTerminal(output, vi.fn());
    await terminal.start("host", 100, 40); open();
    packet(0, Uint8Array.of(0x1b, 0x5b, 0xe4)); packet(0, Uint8Array.of(0xb8, 0xad, 0xff));
    expect(output.mock.calls.map(([bytes]) => Array.from(bytes))).toEqual([[0x1b, 0x5b, 0xe4], [0xb8, 0xad, 0xff]]);
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("terminal_ack", { id: terminal.id, total: 6 }));
    terminal.close();
  });
  it("sends input in order, in bounded chunks, then resizes", async () => {
    const terminal = new EmbeddedTerminal(vi.fn(), vi.fn()); await terminal.start("host", 80, 24); open();
    terminal.input(new Uint8Array(20_000).fill(65)); terminal.input(Uint8Array.of(13)); terminal.resize(120, 45);
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("terminal_resize", { id: terminal.id, cols: 120, rows: 45 }));
    const writes = mocks.invoke.mock.calls.filter(([name]) => name === "terminal_write");
    expect(writes.map(([, args]) => args.data.length)).toEqual([16_384, 3616, 1]);
    expect(writes[2][1].data).toEqual([13]); terminal.close();
  });
  it("closes again after a pending open completes, without leaking a session", async () => {
    let resolve!: () => void;
    mocks.invoke.mockImplementation((name) => name === "terminal_open" ? new Promise<void>((done) => { resolve = done; }) : Promise.resolve());
    const output = vi.fn(); const terminal = new EmbeddedTerminal(output, vi.fn());
    const opening = terminal.start("host", 80, 24); terminal.close(); resolve(); await opening;
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "terminal_close")).toHaveLength(2);
    packet(0, Uint8Array.of(65)); expect(output).not.toHaveBeenCalled();
  });
  it("does not echo or send keystrokes before PTY open or after exit", async () => {
    const output = vi.fn(); const terminal = new EmbeddedTerminal(output, vi.fn());
    await terminal.start("host", 80, 24); terminal.input(Uint8Array.of(65));
    open(); event({ type: "exited", code: 0, signal: null }); terminal.input(Uint8Array.of(66));
    await Promise.resolve(); expect(output).not.toHaveBeenCalled();
    expect(mocks.invoke.mock.calls.some(([name]) => name === "terminal_write")).toBe(false); terminal.close();
  });
  it("stops instead of silently dropping an oversized paste", async () => {
    const events = vi.fn(); const terminal = new EmbeddedTerminal(vi.fn(), events);
    await terminal.start("host", 80, 24); open(); terminal.input(new Uint8Array(512 * 1024 + 1));
    expect(events).toHaveBeenLastCalledWith(expect.objectContaining({ type: "bridge_error" }));
    expect(mocks.invoke).toHaveBeenCalledWith("terminal_close", { id: terminal.id });
    expect(mocks.invoke.mock.calls.some(([name]) => name === "terminal_write")).toBe(false);
  });
  it("ends the session if a write fails, without replaying partial input", async () => {
    mocks.invoke.mockImplementation((name) => name === "terminal_write" ? Promise.reject("timeout") : Promise.resolve());
    const terminal = new EmbeddedTerminal(vi.fn(), vi.fn()); await terminal.start("host", 80, 24); open();
    terminal.input(Uint8Array.of(65)); terminal.input(Uint8Array.of(66));
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("terminal_close", { id: terminal.id }));
    expect(mocks.invoke.mock.calls.filter(([name]) => name === "terminal_write")).toHaveLength(1);
  });
});
