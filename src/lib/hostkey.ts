import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { tauriInvoke } from "@/lib/ipc";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * The host key window of SSHelter's own SSH client (own-ssh spec §10, §14): a host key is confirmed here, never in a terminal. The
 * texts are spec §14's, word for word. Names come from the user's hosts and the server, so they are shown through `revealHidden`.
 */

export const HOSTKEY_EVENT = "hostkey://requests";

export function fetchPending(): Promise<HostKeyRequest[]> {
  return tauriInvoke<HostKeyRequest[]>("hostkey_pending");
}

export function resolveHostKey(requestId: string, answer: HostKeyAnswer): Promise<void> {
  return tauriInvoke<void>("hostkey_resolve", { requestId, answer });
}

export function onHostKeyRequests(handler: (pending: HostKeyRequest[]) => void): Promise<UnlistenFn> {
  return listen<HostKeyRequest[]>(HOSTKEY_EVENT, (event) => handler(event.payload));
}

/** When the old key was pinned, as the changed-key text says it. */
export function pinnedOn(pinnedAtMs: number): string {
  return new Date(pinnedAtMs).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function hostKeyTitle(r: HostKeyRequest): string {
  const alias = revealHidden(r.alias);
  return r.changed === null ? `Is this ${alias}?` : `${alias}'s host key changed`;
}

export function hostKeyBody(r: HostKeyRequest): string {
  const where = `${revealHidden(r.hostname)}:${r.port}`;
  if (r.changed === null) {
    return `${where} presented the key ${revealHidden(r.algorithm)} ${revealHidden(r.fingerprint)}. SSHelter has not seen it before. Connect only if the fingerprint matches what the server's administrator gave you.`;
  }
  return `The key ${where} presented does not match the one SSHelter pinned on ${pinnedOn(r.changed.pinned_at_ms)}. Someone could be intercepting the connection. Refuse unless you know the server's key was reinstalled.`;
}

/** The two buttons: the one that refuses, then the one that trusts. */
export function hostKeyButtons(r: HostKeyRequest): { refuse: string; trust: string } {
  return r.changed === null ? { refuse: "Cancel", trust: "Trust this key" } : { refuse: "Refuse", trust: "Accept new key" };
}

/** The answer for a button: trust carries the fingerprint the window showed, and the broker pins only a key with that fingerprint. */
export function buildHostKeyAnswer(r: HostKeyRequest, trust: boolean): HostKeyAnswer {
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
export function answerRejectedMessage(requestId: string, error: unknown): string {
  return `[hostkey] the answer to ${requestId} was rejected: ${errorMessage(error)}`;
}

/**
 * The pending list reaches the window two ways: one fetch when it opens, and an event for every change after that. A fetch still in
 * flight may have read an older list, so once an event has arrived the fetch's result is ignored.
 */
export function pendingFeed(set: (list: HostKeyRequest[]) => void): { fromFetch: (list: HostKeyRequest[]) => void; fromEvent: (list: HostKeyRequest[]) => void } {
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
