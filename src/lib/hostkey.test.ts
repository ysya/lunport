import { afterEach, describe, expect, it, vi } from "vitest";

import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import {
  answerRejectedMessage,
  armAfterDelay,
  buildHostKeyAnswer,
  followPending,
  HOSTKEY_EVENT,
  hostKeyBody,
  hostKeyButtons,
  hostKeyTitle,
  pendingFeed,
  pinnedOn,
  TRUST_ARM_DELAY_MS,
} from "@/lib/hostkey";
import { stubEventBus } from "./event-bus-fixture";

function request(over: Partial<HostKeyRequest> = {}): HostKeyRequest {
  return {
    id: "hostkey-1",
    alias: "web",
    hostname: "web.example.com",
    port: 22,
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew",
    changed: null,
    ...over,
  };
}

const changed = request({ changed: { fingerprint: "SHA256:old", pinned_at_ms: 1_700_000_000_000 } });

describe("host key texts (spec §14, word for word)", () => {
  it("asks about a key SSHelter has not seen", () => {
    expect(hostKeyTitle(request())).toBe("Is this web?");
    expect(hostKeyBody(request())).toBe(
      "web.example.com:22 presented the key ssh-ed25519 SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew. SSHelter has not seen it before. Connect only if the fingerprint matches what the server's administrator gave you.",
    );
    expect(hostKeyButtons(request())).toEqual({ refuse: "Cancel", trust: "Trust this key" });
  });

  it("warns about a key that changed", () => {
    expect(hostKeyTitle(changed)).toBe("web's host key changed");
    expect(hostKeyBody(changed)).toBe(
      `The key web.example.com:22 presented does not match the one SSHelter pinned on ${pinnedOn(1_700_000_000_000)}. Someone could be intercepting the connection. Refuse unless you know the server's key was reinstalled.`,
    );
    expect(hostKeyButtons(changed)).toEqual({ refuse: "Refuse", trust: "Accept new key" });
  });

  it("shows hidden characters in names instead of rendering them", () => {
    expect(hostKeyTitle(request({ alias: "we‮b" }))).toBe("Is this we⟨U+202E⟩b?");
    expect(hostKeyBody(request({ hostname: "evil\u0007.example.com" }))).toContain("evil⟨U+0007⟩.example.com:22");
  });
});

describe("host key answers", () => {
  it("carries the fingerprint the window showed", () => {
    expect(buildHostKeyAnswer(request(), true)).toEqual({ trust: true, fingerprint: request().fingerprint });
    expect(buildHostKeyAnswer(changed, false)).toEqual({ trust: false, fingerprint: changed.fingerprint });
  });

  it("says which answer was rejected without saying the answer", () => {
    expect(answerRejectedMessage("hostkey-3", new Error("gone"))).toBe("[hostkey] the answer to hostkey-3 was rejected: gone");
  });
});

describe("arming and the pending list", () => {
  afterEach(() => vi.useRealTimers());

  it("arms the trust button after the delay, and a card that goes away first never arms", () => {
    vi.useFakeTimers();
    const armed: string[] = [];
    armAfterDelay(() => armed.push("first"));
    const cancel = armAfterDelay(() => armed.push("second"));
    vi.advanceTimersByTime(TRUST_ARM_DELAY_MS - 1);
    expect(armed).toEqual([]);
    cancel();
    vi.advanceTimersByTime(1);
    expect(armed).toEqual(["first"]);
  });

  it("ignores a fetch that arrives after an event", () => {
    const lists: HostKeyRequest[][] = [];
    const feed = pendingFeed((list) => lists.push(list));
    feed.fromEvent([request()]);
    feed.fromFetch([]);
    expect(lists).toEqual([[request()]]);
  });
});

describe("following the pending list", () => {
  afterEach(() => vi.unstubAllGlobals());

  // A change emitted between the fetch's answer and the listener's registration would be lost, and the window would show a list
  // that is no longer pending: the listener is registered first, and the fetch comes after it.
  it("registers the listener before it fetches", async () => {
    const bus = stubEventBus({ answer: (cmd) => (cmd === "hostkey_pending" ? [request()] : undefined) });
    const lists: HostKeyRequest[][] = [];
    const stop = followPending((list) => lists.push(list));
    await vi.waitFor(() => expect(lists).toEqual([[request()]]));
    expect(bus.commands).toEqual(["plugin:event|listen", "hostkey_pending"]);
    bus.emit(HOSTKEY_EVENT, []);
    expect(lists).toEqual([[request()], []]);
    stop();
    bus.emit(HOSTKEY_EVENT, [request()]);
    expect(lists, "nothing after it stopped").toEqual([[request()], []]);
  });
});
