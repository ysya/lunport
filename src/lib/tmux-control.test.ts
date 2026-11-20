import { describe, expect, it } from "vitest";
import { TmuxControl } from "./tmux-control";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function setup() {
  const writes: string[] = [];
  const output: Array<[string, number[]]> = [];
  const exits: Array<[string, string]> = [];
  let topologyChanges = 0;
  const tmux = new TmuxControl({
    write: (bytes) => { writes.push(decoder.decode(bytes)); },
    onOutput: (paneId, bytes) => { output.push([paneId, [...bytes]]); },
    onTopologyChanged: () => { topologyChanges += 1; },
    onExit: (reason, source) => { exits.push([reason, source]); },
  });
  const feed = (data: string) => tmux.feed(encoder.encode(data));
  const start = () => feed("%begin 4 7 0\n%end 4 7 0\n%session-changed $3 workspace\n");
  const reply = (number: number, data: string, error = false) => {
    feed(`%begin 5 ${number} 1\n${data}%${error ? "error" : "end"} 5 ${number} 1\n`);
  };
  return { tmux, writes, output, exits, feed, start, reply, topologyChanges: () => topologyChanges };
}

describe("tmux control client", () => {
  it("decodes fragmented output byte-for-byte, keeping pane streams distinct", () => {
    const { tmux, output, feed, start, topologyChanges } = setup();
    start();
    const first = encoder.encode("%output %4  \\000\\033[?5h\\134中");
    for (const byte of first) tmux.feed(Uint8Array.of(byte));
    tmux.feed(Uint8Array.of(0xff, 0x0a));
    feed("%extended-output %12 2 future-field : \\012tail\n%layout-change @2 encoded-layout\n");

    expect(output).toEqual([
      ["%4", [32, 0, 27, 91, 63, 53, 104, 92, 228, 184, 173, 255]],
      ["%12", [10, 116, 97, 105, 108]],
    ]);
    expect(topologyChanges()).toBe(2);
  });

  it("waits for attachment and pairs requested replies across unrelated guards", async () => {
    const { tmux, writes, start, feed, reply } = setup();
    const resize = tmux.resize(120, 40);
    const select = tmux.selectPane("%4");
    const rejected = expect(select).rejects.toThrow("pane disappeared");
    expect(writes).toEqual([]);

    start();
    feed("%begin 4 8 0\n%end 4 8 0\n");
    reply(9, "");
    reply(10, "pane disappeared\n", true);
    await resize;
    await rejected;
    expect(writes).toEqual(["refresh-client -C 120x40\n", "select-pane -t %4\n"]);
  });

  it("keeps output inside a reply as data unless its closing guard matches", async () => {
    const { tmux, output, start, reply } = setup();
    start();
    const failed = expect(tmux.selectPane("%4")).rejects.toThrow("%output %7 unrelated\n%end 5 99 1");
    reply(15, "%output %7 unrelated\n%end 5 99 1\n", true);
    await failed;
    expect(output).toEqual([]);
  });

  it("reports the startup reply if attachment exits without a reason", () => {
    const { feed, exits } = setup();
    feed("%begin 4 7 0\n%end 4 7 0\n%begin 4 8 0\nSession changed.\n%end 4 8 0\n%exit\n");
    expect(exits).toEqual([["Session changed.", "tmux"]]);
  });

  it("stops pending input when tmux moves the client to another session", async () => {
    const { tmux, feed, start, exits, writes } = setup();
    start();
    const rejected = expect(tmux.sendInput("%4", "echo")).rejects.toThrow(/session/i);
    feed("%session-changed $5 other\n%exit\n");
    await rejected;
    await expect(tmux.selectPane("%4")).rejects.toThrow(/session/i);
    expect(exits).toEqual([["The attached tmux session changed or ended.", "protocol"]]);
    expect(writes).toHaveLength(1);
  });

  it("rejects pending commands and reports one exit on disconnect", async () => {
    const { tmux, feed, start, exits } = setup();
    start();
    const pending = expect(tmux.selectPane("%4")).rejects.toThrow("too far behind");
    feed("%exit too far behind\n%exit\n");
    await pending;
    expect(exits).toEqual([["too far behind", "tmux"]]);
  });

  it("rejects commands and closes on an oversized unterminated line", async () => {
    const { tmux, start, exits } = setup();
    start();
    const pending = expect(tmux.selectPane("%4")).rejects.toThrow(/line.*large/i);
    tmux.feed(new Uint8Array(2 * 1024 * 1024));
    await pending;
    expect(exits).toEqual([["A tmux control line is too large.", "protocol"]]);
  });

  it("bounds pending command work and rejects queued requests on dispose", async () => {
    const { tmux, writes } = setup();
    const pending = Array.from({ length: 128 }, () => expect(tmux.resize(80, 24)).rejects.toThrow("Closed"));
    await expect(tmux.resize(90, 25)).rejects.toThrow(/too many/i);
    tmux.dispose("Closed");
    await Promise.all(pending);
    expect(writes).toEqual([]);
  });

  it("keeps input bytes and tmux target syntax separate", async () => {
    const { tmux, writes, start, reply } = setup();
    start();
    const input = tmux.sendInput("%4", "中\u001b[A;\n\\\u0000");
    await expect(tmux.selectPane("%4; kill-server")).rejects.toThrow(/invalid.*pane/i);
    await expect(tmux.killWindow("@4\nkill-server")).rejects.toThrow(/invalid.*window/i);
    await expect(tmux.resize(80.5, 24)).rejects.toThrow(/invalid.*size/i);
    expect(writes).toEqual(["send-keys -H -t %4 e4 b8 ad 1b 5b 41 3b 0a 5c 00\n"]);
    reply(9, "");
    await input;
  });

  it("reads session identity, window names and zoomed pane geometry from one snapshot", async () => {
    const { tmux, start, reply } = setup();
    start();
    const snapshot = tmux.snapshot();
    reply(9,
      "$3|165|32768:160|@3|0|0|80|24|1|%4|0|0|39|24|0|off|code|main\n" +
      "$3|165|32768:160|@3|0|0|80|24|1|%5|0|0|80|24|1|off|code|main\n" +
      "$3|165|32768:160|@3|1|1|80|24|1|%4|0|0|39|24|0|off|code|main\n" +
      "$3|165|32768:160|@3|1|1|80|24|1|%5|0|0|80|24|1|off|code|main\n" +
      "$3|165|32768:160|@9|2|0|120|38|0|%7|0|0|120|38|1|0|shell\n");
    expect(await snapshot).toEqual({
      sessionId: "$3",
      sessionCreated: "165",
      sessionName: "workspace",
      server: "32768:160",
      destroyUnattached: false,
      activeWindowId: "@3",
      windows: [
        { id: "@3", index: 1, name: "code|main", activePaneId: "%5", width: 80, height: 24, panes: [
          { id: "%4", left: 0, top: 0, width: 39, height: 24, active: false, visible: false },
          { id: "%5", left: 0, top: 0, width: 80, height: 24, active: true, visible: true },
        ] },
        { id: "@9", index: 2, name: "shell", activePaneId: "%7", width: 120, height: 38, panes: [
          { id: "%7", left: 0, top: 0, width: 120, height: 38, active: true, visible: true },
        ] },
      ],
    });
  });

  it("updates the attached session name and ignores another session's rename", async () => {
    const { tmux, feed, start, reply } = setup();
    start();
    feed("%session-renamed $3 new name\n%session-renamed $31 unrelated\n");
    const renamed = tmux.snapshot();
    reply(9, "$3|165|32768:160|@3|1|1|80|24|0|%4|0|0|80|24|1|off|shell\n");
    await expect(renamed).resolves.toHaveProperty("sessionName", "new name");
  });

  it("rejects a snapshot whose geometry cannot fit a supported viewport", async () => {
    const { tmux, start, reply } = setup();
    start();
    const rejected = expect(tmux.snapshot()).rejects.toThrow(/size/i);
    reply(9, "$3|165|32768:160|@3|1|1|9000|9000|0|%4|0|0|9000|9000|1|off|shell\n");
    await rejected;
  });

  it("returns the newly created window and resizes only the requested pane axis", async () => {
    const { tmux, start, reply, writes } = setup();
    start();
    const created = tmux.newWindow();
    const resized = tmux.resizePane("%4", { rows: 12 });
    await expect(tmux.resizePane("%4", { cols: 0 })).rejects.toThrow(/invalid.*size/i);
    expect(writes).toEqual([
      "new-window -P -F '#{window_id}' -t '$3:'\n",
      "resize-pane -t %4 -y 12\n",
    ]);
    reply(9, "@17\n");
    reply(10, "");
    expect(await created).toBe("@17");
    await resized;
  });

  it("restores styled capture data and the cursor before dispatching later live output", async () => {
    const { tmux, output, start, reply, feed } = setup();
    start();
    const capture = tmux.capturePane("%4", (result) => {
      expect(output).toEqual([["%4", [97]]]);
      expect(result.cursorX).toBe(2);
    });
    feed("%output %4 a\n");
    reply(9, "2|1|0|0|0|0|1|1|1|0|0|0|1|0|0|0|0\n");
    reply(10, "\n");
    reply(11, "\\033[31mline\\\\\nfolded  \n");
    feed("%begin 5 12 1\n\\033[\n%end 5 12 1\n%output %4 b\n");
    expect(output).toEqual([["%4", [97]], ["%4", [98]]]);
    const result = await capture;
    expect(result.alternateScreen).toBe(false);
    expect(result.bracketedPasteKnown).toBe(true);
    expect(result.cursorY).toBe(1);
    expect(decoder.decode(result.bytes)).toContain("\u001b[31mline\\\r\nfolded  ");
    expect(decoder.decode(result.bytes)).toContain("\u001b[2;3H");
    expect(decoder.decode(result.bytes)).toContain("\u001b[?2004h");
    expect(decoder.decode(result.bytes)).toMatch(/\u001b\[$/);
  });

  it("distinguishes a missing paste mode from an explicitly disabled mode", async () => {
    const { tmux, start, reply } = setup();
    start();
    const capture = async (offset: number, paste: string) => {
      const result = tmux.capturePane("%4");
      reply(offset, `0|0|0|0|0|1|0|0|${paste}|0|0|0|0|0|0|1\n`);
      reply(offset + 1, "");
      reply(offset + 2, "\n");
      reply(offset + 3, "");
      return (await result).bracketedPasteKnown;
    };
    expect(await capture(9, "")).toBe(false);
    expect(await capture(13, "0")).toBe(true);
  });

  it("continues with the next request after an unsuccessful capture batch", async () => {
    const { tmux, start, reply } = setup();
    start();
    const capture = expect(tmux.capturePane("%4")).rejects.toThrow("no pane");
    const resize = tmux.resize(80, 24);
    reply(9, "no pane\n", true);
    reply(10, "");
    await capture;
    await resize;
  });
});
