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
  hostKeyEndpoint,
  pendingFeed,
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

const changed = request({
  changed: { fingerprint: "SHA256:old", pinned_at_ms: 1_700_000_000_000 },
});

describe("host key presentation", () => {
  it("asks about a key Lunport has not seen", () => {
    expect(hostKeyTitle(request())).toBe("Verify server identity");
    expect(hostKeyBody(request())).toBe(
      "This server is new to Lunport. Compare its fingerprint with a trusted source before connecting.",
    );
    expect(hostKeyButtons(request())).toEqual({
      refuse: "Cancel",
      trust: "Trust this key",
    });
  });

  it("warns about a key that changed", () => {
    expect(hostKeyTitle(changed)).toBe("Server identity changed");
    expect(hostKeyBody(changed)).toBe(
      "This key differs from the saved identity. The connection may be intercepted. Refuse unless you have verified why the server's key changed.",
    );
    expect(hostKeyButtons(changed)).toEqual({
      refuse: "Refuse",
      trust: "Accept new key",
    });
  });

  it("shows hidden characters in names instead of rendering them", () => {
    expect(
      hostKeyEndpoint(request({ hostname: "evil\u0007.example.com" })),
    ).toBe("evil⟨U+0007⟩.example.com:22");
    expect(hostKeyEndpoint(request({ hostname: "2001:db8::1" }))).toBe(
      "[2001:db8::1]:22",
    );
  });
});

describe("host key answers", () => {
  it("carries the fingerprint the window showed", () => {
    expect(buildHostKeyAnswer(request(), true)).toEqual({
      trust: true,
      fingerprint: request().fingerprint,
    });
    expect(buildHostKeyAnswer(changed, false)).toEqual({
      trust: false,
      fingerprint: changed.fingerprint,
    });
  });

  it("says which answer was rejected without saying the answer", () => {
    expect(answerRejectedMessage("hostkey-3", new Error("gone"))).toBe(
      "[hostkey] the answer to hostkey-3 was rejected: gone",
    );
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
    const bus = stubEventBus({
      answer: (cmd) => (cmd === "hostkey_pending" ? [request()] : undefined),
    });
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
