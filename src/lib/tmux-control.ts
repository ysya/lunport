export interface TmuxPane {
  id: string;
  left: number;
  top: number;
  width: number;
  height: number;
  active: boolean;
  visible: boolean;
}

export interface TmuxWindow {
  id: string;
  index: number;
  name: string;
  activePaneId: string;
  width: number;
  height: number;
  panes: TmuxPane[];
}

export interface TmuxSnapshot {
  sessionId: string;
  sessionName: string;
  sessionCreated: string;
  server: string;
  destroyUnattached: boolean;
  activeWindowId: string;
  windows: TmuxWindow[];
}

export interface TmuxPaneCapture {
  bytes: Uint8Array;
  cursorX: number;
  cursorY: number;
  alternateScreen: boolean;
  bracketedPasteKnown: boolean;
}

interface TmuxControlOptions {
  write: (bytes: Uint8Array) => void | Promise<void>;
  onOutput: (paneId: string, bytes: Uint8Array) => void;
  onTopologyChanged: () => void;
  onExit: (reason: string, source: "tmux" | "protocol") => void;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SESSION_ID = /^\$\d{1,10}$/;
const WINDOW_ID = /^@\d{1,10}$/;
const PANE_ID = /^%\d{1,10}$/;
const MAX_LINE = 1024 * 1024;
const MAX_REPLY = 8 * 1024 * 1024;
const MAX_REPLY_LINES = 32_768;
const MAX_PENDING = 128;
const MAX_PENDING_INPUT = 400 * 1024;
const MAX_INPUT_BYTES = 128 * 1024;
const INPUT_CHUNK = 1024;
const CAPTURE_HISTORY_LINES = 300;
const COMMAND_TIMEOUT = 30_000;
const MAX_SIDE = 4096;
const MAX_CELLS = 2_097_152;
const HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));

const SNAPSHOT_FORMAT = [
  "#{session_id}", "#{session_created}", "#{pid}:#{start_time}", "#{window_id}", "#{window_index}",
  "#{window_active}", "#{window_width}", "#{window_height}", "#{window_zoomed_flag}", "#{pane_id}",
  "#{pane_left}", "#{pane_top}", "#{pane_width}", "#{pane_height}", "#{pane_active}", "#{destroy-unattached}",
  "#{window_name}",
].join("|");

const CAPTURE_FORMAT = [
  "cursor_x", "cursor_y", "alternate_saved_x", "alternate_saved_y", "alternate_on", "cursor_flag",
  "keypad_cursor_flag", "keypad_flag", "bracket_paste_flag", "mouse_any_flag", "mouse_button_flag",
  "mouse_standard_flag", "mouse_sgr_flag", "mouse_utf8_flag", "origin_flag", "insert_flag", "wrap_flag",
].map((key) => `#{${key}}`).join("|");

const TOPOLOGY_EVENTS = new Set([
  "%layout-change", "%session-window-changed", "%sessions-changed", "%window-add",
  "%window-close", "%window-pane-changed", "%window-renamed", "%unlinked-window-close",
]);

interface Request {
  commands: (sessionId: string) => string[];
  inputSize: number;
  expected: number;
  replies: Uint8Array[][];
  resolve: (replies: Uint8Array[][]) => void;
  reject: (error: Error) => void;
}

interface Reply {
  guard: string;
  requested: boolean;
  startup: boolean;
  lines: Uint8Array[];
  size: number;
  overflow: boolean;
}

function octal(byte: number) {
  return byte >= 48 && byte <= 55;
}

function unescape(bytes: Uint8Array, capture = false) {
  const result = new Uint8Array(bytes.length);
  let length = 0;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === 92 && capture && bytes[i + 1] === 92) {
      result[length++] = 92;
      i++;
    } else if (byte === 92 && bytes[i + 1] >= 48 && bytes[i + 1] <= 51
      && octal(bytes[i + 2]) && octal(bytes[i + 3])) {
      result[length++] = ((bytes[i + 1] - 48) << 6) | ((bytes[i + 2] - 48) << 3) | (bytes[i + 3] - 48);
      i += 3;
    } else {
      result[length++] = byte;
    }
  }
  return result.subarray(0, length);
}

function joinBytes(parts: Uint8Array[]) {
  const bytes = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}

function readNumber(value: string, minimum = 0) {
  const number = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(number) || number < minimum) {
    throw new Error("Invalid number in tmux response.");
  }
  return number;
}

function isValidSide(size: number) {
  return Number.isInteger(size) && size >= 1 && size <= MAX_SIDE;
}

function readSize(rawWidth: string, rawHeight: string) {
  const width = readNumber(rawWidth, 1);
  const height = readNumber(rawHeight, 1);
  if (!isValidSide(width) || !isValidSide(height) || width * height > MAX_CELLS) {
    throw new Error("The tmux viewport size is too large.");
  }
  return { width, height };
}

function parseSnapshot(lines: Uint8Array[], session: { id: string; name: string }): TmuxSnapshot {
  const windows = new Map<string, TmuxWindow>();
  const paneWindows = new Map<string, string>();
  let activeWindowId = "";
  let sessionCreated = "";
  let server = "";
  let destroyUnattached = false;
  for (const bytes of lines) {
    const line = decoder.decode(bytes);
    const fields = line.split("|", 16);
    const [
      sessionId, created, identity, windowId, index, windowActive, windowWidth, windowHeight, zoomed,
      paneId, left, top, paneWidth, paneHeight, paneActive, destroy,
    ] = fields;
    if (fields.length !== 16 || sessionId !== session.id || !WINDOW_ID.test(windowId)
      || !PANE_ID.test(paneId) || !/^\d+$/.test(created) || !/^\d+:\d+$/.test(identity)) {
      throw new Error("Invalid tmux workspace snapshot.");
    }
    sessionCreated = created;
    server = identity;
    destroyUnattached = destroy !== "" && destroy !== "off" && destroy !== "0";
    let window = windows.get(windowId);
    if (!window) {
      window = {
        id: windowId,
        index: readNumber(index),
        name: line.slice(fields.join("|").length + 1),
        ...readSize(windowWidth, windowHeight),
        activePaneId: "",
        panes: [],
      };
      windows.set(windowId, window);
    }
    if (windowActive === "1") {
      activeWindowId = windowId;
      // The same window can be linked at several indexes within a session.
      window.index = readNumber(index);
    }
    const knownWindow = paneWindows.get(paneId);
    if (knownWindow === windowId) continue;
    if (knownWindow !== undefined) throw new Error("Invalid tmux pane membership.");
    paneWindows.set(paneId, windowId);
    if (paneActive === "1") window.activePaneId = paneId;
    const leftEdge = readNumber(left);
    const topEdge = readNumber(top);
    const size = readSize(paneWidth, paneHeight);
    const visible = zoomed !== "1" || paneActive === "1";
    if (visible && (leftEdge + size.width > window.width || topEdge + size.height > window.height)) {
      throw new Error("A tmux pane is outside its window viewport.");
    }
    window.panes.push({
      id: paneId,
      left: leftEdge,
      top: topEdge,
      ...size,
      active: paneActive === "1",
      visible,
    });
  }
  const orderedWindows = [...windows.values()].sort((a, b) => a.index - b.index);
  if (!activeWindowId || orderedWindows.some((window) => !window.activePaneId)) {
    throw new Error("The tmux session has no active window or pane.");
  }
  return {
    sessionId: session.id, sessionName: session.name, sessionCreated, server, destroyUnattached,
    activeWindowId, windows: orderedWindows,
  };
}

function captureRows(rows: Uint8Array[], parts: Uint8Array[]) {
  const nextRow = encoder.encode("\r\n");
  for (let index = 0; index < rows.length; index++) {
    if (index > 0) parts.push(nextRow);
    parts.push(unescape(rows[index], true));
  }
}

function cursor(x: number, y: number) {
  return `\x1b[${y + 1};${x + 1}H`;
}

function parseCapture([metadata, saved, screen, pending]: Uint8Array[][]): TmuxPaneCapture {
  const [
    x, y, savedX, savedY, alternate, showCursor, applicationCursor, applicationKeypad, paste,
    mouseAny, mouseButton, mouseStandard, mouseSgr, mouseUtf8, origin, insert, wrap,
  ] = decoder.decode(metadata[0]).split("|");
  const cursorX = readNumber(x);
  const cursorY = readNumber(y);
  const alternateScreen = alternate === "1";
  const bytes: Uint8Array[] = [];
  if (alternateScreen) {
    captureRows(saved, bytes);
    const restoreX = readNumber(savedX);
    const restoreY = readNumber(savedY);
    const savedCursor = restoreX < 65_536 && restoreY < 65_536 ? cursor(restoreX, restoreY) : cursor(0, 0);
    bytes.push(encoder.encode(`${savedCursor}\x1b[?1049h`));
  }
  captureRows(screen, bytes);
  let modes = "";
  if (origin === "1") modes += "\x1b[?6h";
  modes += cursor(cursorX, cursorY);
  if (showCursor === "0") modes += "\x1b[?25l";
  if (applicationCursor === "1") modes += "\x1b[?1h";
  if (applicationKeypad === "1") modes += "\x1b=";
  // tmux 3.2 leaves the bracketed-paste format empty.
  if (paste === "1") modes += "\x1b[?2004h";
  if (mouseAny === "1") modes += "\x1b[?1003h";
  else if (mouseButton === "1") modes += "\x1b[?1002h";
  else if (mouseStandard === "1") modes += "\x1b[?1000h";
  if (mouseSgr === "1") modes += "\x1b[?1006h";
  else if (mouseUtf8 === "1") modes += "\x1b[?1005h";
  if (insert === "1") modes += "\x1b[4h";
  if (wrap === "0") modes += "\x1b[?7l";
  bytes.push(encoder.encode(modes));
  if (pending.length > 0) bytes.push(unescape(pending[0], true));
  return { bytes: joinBytes(bytes), cursorX, cursorY, alternateScreen, bracketedPasteKnown: paste === "0" || paste === "1" };
}

/** Streaming control of a single tmux -C client over SSH exec. */
export class TmuxControl {
  private readonly waiting: Request[] = [];
  private readonly sent: Request[] = [];
  private writing = false;
  private queuedInput = 0;
  private session: { id: string; name: string } | undefined;
  private line = new Uint8Array(4096);
  private lineUsed = 0;
  private reply: Reply | undefined;
  private closed: Error | undefined;
  private deadline: ReturnType<typeof setTimeout> | undefined;
  private startupMessage = "";

  constructor(private readonly options: TmuxControlOptions) {}

  feed(bytes: Uint8Array) {
    let start = 0;
    while (start < bytes.length && !this.closed) {
      const end = bytes.indexOf(10, start);
      const fragment = bytes.subarray(start, end < 0 ? bytes.length : end);
      if (this.lineUsed + fragment.length > MAX_LINE) {
        this.exit("A tmux control line is too large.");
        return;
      }
      if (this.lineUsed === 0 && end >= 0) {
        this.acceptLine(fragment);
      } else {
        if (this.lineUsed + fragment.length > this.line.length) {
          const expanded = new Uint8Array(Math.min(MAX_LINE, Math.max(this.line.length * 2, this.lineUsed + fragment.length)));
          expanded.set(this.line.subarray(0, this.lineUsed));
          this.line = expanded;
        }
        this.line.set(fragment, this.lineUsed);
        this.lineUsed += fragment.length;
        if (end >= 0) {
          const line = this.line.subarray(0, this.lineUsed);
          this.lineUsed = 0;
          this.acceptLine(line);
        }
      }
      start = end < 0 ? bytes.length : end + 1;
    }
  }

  dispose(reason = "The tmux client disconnected.") {
    if (this.closed) return;
    this.closed = new Error(reason);
    this.reply = undefined;
    this.line = new Uint8Array(0);
    this.lineUsed = 0;
    this.queuedInput = 0;
    this.updateDeadline();
    for (const request of this.sent.splice(0)) request.reject(this.closed);
    for (const request of this.waiting.splice(0)) request.reject(this.closed);
  }

  snapshot() {
    return this.request(
      (sessionId) => [`list-panes -s -t '${sessionId}:' -F '${SNAPSHOT_FORMAT}'`],
      ([lines]) => parseSnapshot(lines, this.session!),
    );
  }

  async capturePane(paneId: string, onCaptured?: (capture: TmuxPaneCapture) => void) {
    this.validatePane(paneId);
    return this.request(
      () => [
        `display-message -p -t ${paneId} '${CAPTURE_FORMAT}'`,
        `capture-pane -p -a -q -e -C -N -t ${paneId}`,
        `capture-pane -p -e -C -N -S -${CAPTURE_HISTORY_LINES} -t ${paneId}`,
        `capture-pane -p -P -C -t ${paneId}`,
      ],
      (replies) => {
        const capture = parseCapture(replies);
        onCaptured?.(capture);
        return capture;
      },
    );
  }

  async sendInput(paneId: string, input: string | Uint8Array) {
    this.validatePane(paneId);
    if (input.length > MAX_INPUT_BYTES) throw new Error("The tmux input is too large.");
    const bytes = typeof input === "string" ? encoder.encode(input) : input;
    if (bytes.length > MAX_INPUT_BYTES) throw new Error("The tmux input is too large.");
    const commands: string[] = [];
    for (let offset = 0; offset < bytes.length; offset += INPUT_CHUNK) {
      const hex = Array.from(bytes.subarray(offset, offset + INPUT_CHUNK), (byte) => HEX[byte]).join(" ");
      commands.push(`send-keys -H -t ${paneId} ${hex}`);
    }
    if (commands.length === 0) return;
    const size = commands.reduce((length, command) => length + command.length + 3, 0);
    return this.request(() => commands, () => {}, size);
  }

  async resize(cols: number, rows: number) {
    if (!isValidSide(cols) || !isValidSide(rows) || cols * rows > MAX_CELLS) {
      throw new Error("Invalid tmux client size.");
    }
    return this.action(() => `refresh-client -C ${cols}x${rows}`);
  }

  async resizePane(paneId: string, { cols, rows }: { cols?: number; rows?: number }) {
    this.validatePane(paneId);
    if ((cols === undefined && rows === undefined)
      || (cols !== undefined && !isValidSide(cols))
      || (rows !== undefined && !isValidSide(rows))) {
      throw new Error("Invalid tmux pane size.");
    }
    const width = cols === undefined ? "" : ` -x ${cols}`;
    const height = rows === undefined ? "" : ` -y ${rows}`;
    return this.action(() => `resize-pane -t ${paneId}${width}${height}`);
  }

  async selectWindow(windowId: string) {
    this.validateWindow(windowId);
    return this.action((sessionId) => `select-window -t '${sessionId}:${windowId}'`);
  }

  async selectPane(paneId: string) {
    this.validatePane(paneId);
    return this.action(() => `select-pane -t ${paneId}`);
  }

  async splitPane(paneId: string, direction: "horizontal" | "vertical") {
    this.validatePane(paneId);
    if (direction !== "horizontal" && direction !== "vertical") throw new Error("Invalid tmux split direction.");
    return this.action(() => `split-window -${direction === "horizontal" ? "h" : "v"} -t ${paneId}`);
  }

  newWindow() {
    return this.request(
      (sessionId) => [`new-window -P -F '#{window_id}' -t '${sessionId}:'`],
      ([lines]) => {
        const id = decoder.decode(lines[0]);
        this.validateWindow(id);
        return id;
      },
    );
  }

  async killWindow(windowId: string) {
    this.validateWindow(windowId);
    return this.action((sessionId) => `kill-window -t '${sessionId}:${windowId}'`);
  }

  killSession() {
    return this.action((sessionId) => `kill-session -t '${sessionId}'`);
  }

  private validatePane(paneId: string) {
    if (!PANE_ID.test(paneId)) throw new Error("Invalid tmux pane ID.");
  }

  private validateWindow(windowId: string) {
    if (!WINDOW_ID.test(windowId)) throw new Error("Invalid tmux window ID.");
  }

  private action(command: (sessionId: string) => string) {
    return this.request((sessionId) => [command(sessionId)], () => {});
  }

  private request<T>(
    commands: Request["commands"],
    read: (replies: Uint8Array[][]) => T,
    inputSize = 0,
  ): Promise<T> {
    if (this.closed) return Promise.reject(this.closed);
    if (this.waiting.length + this.sent.length >= MAX_PENDING || this.queuedInput + inputSize > MAX_PENDING_INPUT) {
      return Promise.reject(new Error("Too many pending tmux commands."));
    }
    return new Promise<T>((resolve, reject) => {
      this.waiting.push({
        commands, expected: 0, inputSize, replies: [], reject,
        resolve(replies) {
          try { resolve(read(replies)); }
          catch (error) { reject(error); }
        },
      });
      this.queuedInput += inputSize;
      this.updateDeadline();
      this.flush();
    });
  }

  private flush() {
    if (!this.session || this.writing || this.closed) return;
    this.writing = true;
    try {
      while (this.waiting.length > 0 && !this.closed) {
        const request = this.waiting.shift()!;
        this.sent.push(request);
        const commands = request.commands(this.session.id);
        request.expected = commands.length;
        const bytes = encoder.encode(commands.join(" ; ") + "\n");
        const write = this.options.write(bytes);
        if (write) {
          void write.then(() => {
            this.writing = false;
            this.flush();
          }, (error: unknown) => this.exit(String(error)));
          return;
        }
      }
    } catch (error) {
      this.exit(String(error));
    }
    this.writing = false;
  }

  private updateDeadline(reset = false) {
    if (this.deadline !== undefined && (reset || this.closed || this.waiting.length + this.sent.length === 0)) {
      clearTimeout(this.deadline);
      this.deadline = undefined;
    }
    if (!this.closed && this.deadline === undefined && this.waiting.length + this.sent.length > 0) {
      this.deadline = setTimeout(() => this.exit("The tmux client stopped responding."), COMMAND_TIMEOUT);
    }
  }

  private exit(reason: string, source: "tmux" | "protocol" = "protocol") {
    if (this.closed) return;
    this.dispose(reason);
    this.options.onExit(reason, source);
  }

  private finishReply(reply: Reply, failed: boolean) {
    if (reply.startup && reply.lines.length > 0) {
      this.startupMessage = this.replyMessage(reply.lines).slice(0, 1024);
    }
    if (!reply.requested) return;
    const request = this.sent[0];
    if (failed || reply.overflow || request.replies.length + 1 === request.expected) {
      this.sent.shift();
      this.queuedInput -= request.inputSize;
    }
    if (failed) request.reject(new Error(this.replyMessage(reply.lines) || "The tmux command failed."));
    else if (reply.overflow) {
      // The rest of a successful multi-command batch will still produce replies.
      this.exit("A tmux command response is too large.");
      request.reject(this.closed!);
    } else {
      request.replies.push(reply.lines);
      if (request.replies.length === request.expected) request.resolve(request.replies);
    }
    this.updateDeadline(true);
  }

  private replyMessage(lines: Uint8Array[]) {
    return lines.slice(0, 8).map((line) => decoder.decode(line.subarray(0, 1024))).join("\n").trim();
  }

  private acceptLine(line: Uint8Array) {
    // Decode only the protocol prefix. Pane bytes can include invalid UTF-8.
    const prefix = decoder.decode(line.subarray(0, 128));
    const guard = line.length <= 128 && /^%(begin|end|error) (\d+ \d+ (\d+))$/.exec(prefix);
    if (this.reply) {
      const reply = this.reply;
      if (guard && guard[1] !== "begin" && guard[2] === reply.guard) {
        this.reply = undefined;
        this.finishReply(reply, guard[1] === "error");
      } else if (!reply.overflow && (reply.requested || reply.startup)) {
        reply.size += line.length + 1;
        reply.overflow = reply.size > MAX_REPLY || reply.lines.length >= MAX_REPLY_LINES;
        if (reply.overflow) reply.lines = [];
        else reply.lines.push(line.slice());
      }
      return;
    }
    if (guard && guard[1] === "begin") {
      const requested = (Number(guard[3]) & 1) !== 0 && this.sent.length > 0;
      this.reply = { guard: guard[2], requested, startup: !this.session, lines: [], size: 0, overflow: false };
      return;
    }
    if (prefix === "%exit" || prefix.startsWith("%exit ")) {
      this.exit(decoder.decode(line.subarray(6, 1024)) || this.startupMessage || "The tmux client detached.", "tmux");
      return;
    }
    if (prefix.startsWith("%session-changed ")) {
      const change = /^%session-changed (\S+) (.*)$/.exec(decoder.decode(line));
      if (!change || !SESSION_ID.test(change[1])) return;
      if (this.session && this.session.id !== change[1]) {
        this.exit("The attached tmux session changed or ended.");
        return;
      }
      this.session = { id: change[1], name: change[2] };
      this.startupMessage = "";
      this.flush();
      this.options.onTopologyChanged();
      return;
    }
    if (prefix.startsWith("%session-renamed ") && this.session) {
      const rename = /^%session-renamed (\S+) (.*)$/.exec(decoder.decode(line));
      if (rename?.[1] === this.session.id) {
        this.session.name = rename[2];
        this.options.onTopologyChanged();
      }
      return;
    }
    if (prefix.startsWith("%output ") || prefix.startsWith("%extended-output ")) {
      this.acceptOutput(line, prefix.startsWith("%extended-output "));
      return;
    }
    const event = prefix.split(" ", 1)[0];
    if (TOPOLOGY_EVENTS.has(event) && this.session) this.options.onTopologyChanged();
  }

  private acceptOutput(line: Uint8Array, extended: boolean) {
    const paneStart = extended ? 17 : 8;
    const paneEnd = line.indexOf(32, paneStart);
    if (paneEnd < paneStart || paneEnd - paneStart > 11) return;
    const paneId = decoder.decode(line.subarray(paneStart, paneEnd));
    if (!PANE_ID.test(paneId)) return;
    let outputStart = paneEnd + 1;
    if (extended) {
      const ageEnd = line.indexOf(32, outputStart);
      if (ageEnd < 0 || !/^\d+$/.test(decoder.decode(line.subarray(outputStart, ageEnd)))) return;
      for (let offset = ageEnd; offset + 2 < line.length; offset++) {
        if (line[offset] === 32 && line[offset + 1] === 58 && line[offset + 2] === 32) {
          outputStart = offset + 3;
          break;
        }
      }
      if (outputStart === paneEnd + 1) return;
    }
    this.options.onOutput(paneId, unescape(line.subarray(outputStart)));
  }
}
