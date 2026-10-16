import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AuthRequest } from "@/bindings/AuthRequest";
import { tauriInvoke } from "@/lib/ipc";
import { sampleClock, type ClockSample } from "./mcp-flow";

export type AuthenticationSnapshot = { request: AuthRequest; receivedAt: ClockSample };
export const fetchAuthPending = () => tauriInvoke<AuthRequest[]>("auth_pending");
export const resolveAuthentication = (requestId: string, value: string | null) =>
  tauriInvoke<void>("auth_resolve", { requestId, value });

/** Listener first, then fetch; an event invalidates any older in-flight fetch. */
export function followAuthentication(
  set: (list: AuthenticationSnapshot[]) => void,
  onError: () => void,
): () => void {
  let live = true;
  let revision = 0;
  let unlisten: UnlistenFn | undefined;
  const publish = (list: AuthRequest[]) => {
    if (!live) return;
    const receivedAt = sampleClock();
    set(list.map(request => ({ request, receivedAt })));
  };
  void listen<AuthRequest[]>("authentication://requests", event => {
    revision++;
    publish(event.payload);
  }).then(fn => {
    if (!live) {
      fn();
      return;
    }
    unlisten = fn;
    const fetchRevision = revision;
    void fetchAuthPending()
      .then(list => { if (revision === fetchRevision) publish(list); })
      .catch(() => { if (live) onError(); });
  }).catch(() => { if (live) onError(); });
  return () => {
    live = false;
    unlisten?.();
  };
}
