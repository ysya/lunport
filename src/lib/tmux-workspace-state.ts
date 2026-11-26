import type { TmuxSessionInfo } from "@/lib/embedded-terminal";
import type { TmuxSnapshot } from "@/lib/tmux-control";

export type SessionIdentity = Pick<TmuxSessionInfo, "id" | "name" | "created" | "server">;

export type TmuxWorkspaceLocation = {
  session: SessionIdentity;
  windowId: string;
  paneId: string;
  updatedAt?: number;
};

export function sameTmuxSession(first: SessionIdentity, second: SessionIdentity) {
  return first.id === second.id && first.created === second.created && first.server === second.server;
}

export function workspaceWindow(snapshot: TmuxSnapshot | null, localId: string | null) {
  return snapshot?.windows.find((window) => window.id === localId)
    ?? snapshot?.windows.find((window) => window.id === snapshot.activeWindowId)
    ?? snapshot?.windows[0];
}

const storageKey = (hostKey: string) => `lunport:tmux-workspace:${hostKey}`;

export function readTmuxWorkspace(hostKey: string): TmuxWorkspaceLocation | null {
  try {
    const value = JSON.parse(window.localStorage.getItem(storageKey(hostKey)) ?? "null") as TmuxWorkspaceLocation | null;
    const session = value?.session;
    if (session && typeof session.id === "string" && /^\$\d+$/.test(session.id) && typeof session.name === "string" &&
      typeof session.created === "string" && /^\d+$/.test(session.created) && typeof session.server === "string" && session.server.length > 0 &&
      typeof value.windowId === "string" && /^@\d+$/.test(value.windowId) && typeof value.paneId === "string" && /^%\d+$/.test(value.paneId)) return value;
  } catch { /* Remembering a workspace is optional. */ }
  return null;
}

export function rememberTmuxWorkspace(hostKey: string, location: TmuxWorkspaceLocation) {
  try { window.localStorage.setItem(storageKey(hostKey), JSON.stringify({ ...location, updatedAt: Date.now() })); }
  catch { /* Remembering a workspace is optional. */ }
}

export function forgetTmuxWorkspace(hostKey: string, session: SessionIdentity) {
  const saved = readTmuxWorkspace(hostKey);
  if (!saved || !sameTmuxSession(saved.session, session)) return;
  try { window.localStorage.removeItem(storageKey(hostKey)); }
  catch { /* Remembering a workspace is optional. */ }
}
