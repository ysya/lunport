import { afterEach, describe, expect, it, vi } from "vitest";
import type { TmuxSnapshot } from "@/lib/tmux-control";
import { forgetTmuxWorkspace, readTmuxWorkspace, rememberTmuxWorkspace, sameTmuxSession, workspaceWindow } from "@/lib/tmux-workspace-state";

const session = { id: "$1", name: "work", created: "1540000000", server: "431" };

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("remembered tmux workspaces", () => {
  it("identifies the same tmux session across a rename but rejects reused IDs", () => {
    expect(sameTmuxSession(session, { ...session, name: "renamed" })).toBe(true);
    expect(sameTmuxSession(session, { ...session, server: "452" })).toBe(false);
    expect(sameTmuxSession(session, { ...session, created: "1540000001" })).toBe(false);
    expect(sameTmuxSession(session, { ...session, id: "$2" })).toBe(false);
  });

  it("remembers the most recent target and pane separately for each host", () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1740000000000);
    const entries = new Map<string, string>();
    vi.stubGlobal("window", { localStorage: {
      getItem: (key: string) => entries.get(key) ?? null,
      setItem: (key: string, value: string) => entries.set(key, value),
    } });
    const first = { session, windowId: "@2", paneId: "%3" };
    const latest = { ...first, paneId: "%4" };
    rememberTmuxWorkspace("records:host-1", first);
    rememberTmuxWorkspace("records:host-2", first);
    now.mockReturnValue(1740000001000);
    rememberTmuxWorkspace("records:host-1", latest);
    expect(readTmuxWorkspace("records:host-1")).toEqual({ ...latest, updatedAt: 1740000001000 });
    expect(readTmuxWorkspace("records:host-2")).toEqual({ ...first, updatedAt: 1740000000000 });
    entries.set("lunport:tmux-workspace:records:host-2", JSON.stringify(first));
    expect(readTmuxWorkspace("records:host-2")).toEqual(first);
    entries.set([...entries.keys()][0], '{"session":{"id":"$1","created":"1540000000"}}');
    expect(readTmuxWorkspace("records:host-1")).toBeNull();
  });

  it("forgets a missing session without discarding a newer target for the same host", () => {
    const entries = new Map<string, string>();
    vi.stubGlobal("window", { localStorage: {
      getItem: (key: string) => entries.get(key) ?? null,
      setItem: (key: string, value: string) => entries.set(key, value),
      removeItem: (key: string) => entries.delete(key),
    } });
    const newSession = { ...session, server: "452" };
    rememberTmuxWorkspace("records:host-1", { session: newSession, windowId: "@2", paneId: "%3" });
    forgetTmuxWorkspace("records:host-1", session);
    expect(readTmuxWorkspace("records:host-1")?.session).toEqual(newSession);
    forgetTmuxWorkspace("records:host-1", newSession);
    expect(readTmuxWorkspace("records:host-1")).toBeNull();
  });

  it("keeps the locally viewed window while another tmux client switches windows", () => {
    const editor = { id: "@0", index: 0, name: "editor", activePaneId: "%0", width: 80, height: 24, panes: [] };
    const shell = { ...editor, id: "@1", index: 1, name: "shell", activePaneId: "%1" };
    const snapshot: TmuxSnapshot = {
      sessionId: session.id, sessionName: session.name, sessionCreated: session.created,
      server: session.server, destroyUnattached: false, activeWindowId: shell.id, windows: [editor, shell],
    };
    expect(workspaceWindow(snapshot, editor.id)).toBe(editor);
    expect(workspaceWindow({ ...snapshot, windows: [shell] }, editor.id)).toBe(shell);
  });
});
