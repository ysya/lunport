import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { tauriInvoke } from "@/lib/ipc";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * The host key window of SSHelter's own SSH client (own-ssh spec §10, §14): a host key is confirmed here, never in a terminal. The
 * Security semantics follow spec §14. The compact structured presentation was revised in beta 1.0.0-2. Names come from the user's
 * hosts and the server, so they are shown through `revealHidden`.
 */

export const HOSTKEY_EVENT = "hostkey://requests";

export function fetchPending(): Promise<HostKeyRequest[]> {
  return tauriInvoke<HostKeyRequest[]>("hostkey_pending");
}

export function resolveHostKey(
  requestId: string,
  answer: HostKeyAnswer,
): Promise<void> {
  return tauriInvoke<void>("hostkey_resolve", { requestId, answer });
}

export function onHostKeyRequests(
  handler: (pending: HostKeyRequest[]) => void,
): Promise<UnlistenFn> {
  return listen<HostKeyRequest[]>(HOSTKEY_EVENT, (event) =>
    handler(event.payload),
  );
}

/** When the old key was pinned, as the changed-key text says it. */
export function pinnedOn(pinnedAtMs: number): string {
  return new Date(pinnedAtMs).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function hostKeyTitle(r: HostKeyRequest): string {
  return r.changed === null
    ? "Verify server identity"
    : "Server identity changed";
}

export function hostKeyBody(r: HostKeyRequest): string {
  if (r.changed === null) {
    return "This server is new to SSHelter. Compare its fingerprint with a trusted source before connecting.";
  }
  return "This key differs from the saved identity. The connection may be intercepted. Refuse unless you have verified why the server's key changed.";
}

export function hostKeyEndpoint(r: HostKeyRequest): string {
  const host =
    r.hostname.includes(":") && !r.hostname.startsWith("[")
      ? `[${r.hostname}]`
      : r.hostname;
  return `${revealHidden(host)}:${r.port}`;
}

/** The two buttons: the one that refuses, then the one that trusts. */
export function hostKeyButtons(r: HostKeyRequest): {
  refuse: string;
  trust: string;
} {
  return r.changed === null
    ? { refuse: "Cancel", trust: "Trust this key" }
    : { refuse: "Refuse", trust: "Accept new key" };
}

/** The answer for a button: trust carries the fingerprint the window showed, and the broker pins only a key with that fingerprint. */
export function buildHostKeyAnswer(
  r: HostKeyRequest,
  trust: boolean,
): HostKeyAnswer {
  return { trust, fingerprint: r.fingerprint };
}

/**
 * How long the trust button stays off after a card mounts: the next question replaces an answered one within milliseconds, and a quick
 * second click must not trust a key nobody looked at. Refusing never waits.
 */
export const TRUST_ARM_DELAY_MS = 700;

export function armAfterDelay(arm: () => void): () => void {
  const timer = setTimeout(arm, TRUST_ARM_DELAY_MS);
  return () => clearTimeout(timer);
}

/** The console line for an answer the backend rejected: the request id and the error only. */
export function answerRejectedMessage(
  requestId: string,
  error: unknown,
): string {
  return `[hostkey] the answer to ${requestId} was rejected: ${errorMessage(error)}`;
}

/**
 * Gives the window the pending list, now and at every change, until the returned function is called (the window's effect). The listener
 * is registered first and the list fetched after it: a change emitted between a fetch's answer and the listener's registration would be
 * lost, and the window would go on showing a list that is no longer pending.
 */
export function followPending(
  set: (list: HostKeyRequest[]) => void,
): () => void {
  let unlisten: UnlistenFn | undefined;
  let live = true;
  const feed = pendingFeed((list) => {
    if (live) set(list);
  });
  void onHostKeyRequests(feed.fromEvent).then((u) => {
    if (!live) {
      u();
      return;
    }
    unlisten = u;
    // The listener is in place: every change from now on arrives as an event, and the fetch fills in what was pending before it.
    void fetchPending().then(feed.fromFetch);
  });
  return () => {
    live = false;
    unlisten?.();
  };
}

/**
 * The pending list reaches the window two ways: one fetch, started once the listener is registered (`followPending`), and an event for
 * every change. A fetch still in flight may have read an older list, so once an event has arrived the fetch's result is ignored.
 * (After a rejected answer the window fetches the list once more, outside this guard: an event that arrives while that fetch is in
 * flight can be overwritten by the older list until the next change. Plan 1d's rework of the window routes it through the guard.)
 */
export function pendingFeed(set: (list: HostKeyRequest[]) => void): {
  fromFetch: (list: HostKeyRequest[]) => void;
  fromEvent: (list: HostKeyRequest[]) => void;
} {
  let sawEvent = false;
  return {
    fromFetch: (list) => {
      if (!sawEvent) set(list);
    },
    fromEvent: (list) => {
      sawEvent = true;
      set(list);
    },
  };
}
