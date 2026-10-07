import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import {
  afterFailedAnswer,
  agentProblemText,
  ALLOW_ARM_DELAY_MS,
  allowDisabled,
  answerRejectedMessage,
  approvalTitle,
  armAfterDelay,
  buildAnswer,
  CONNECT_EXPIRED_EVENT,
  connectExpiredMessage,
  destination,
  isAnswering,
  pendingFeed,
  programChainLine,
  programName,
  rememberLabel,
} from "@/lib/agent";

function request(over: Partial<AgentApprovalRequest> = {}): AgentApprovalRequest {
  return {
    id: "approval-1",
    key_name: "id_mac",
    key_fingerprint: "SHA256:k",
    program_chain: ["claude", "zsh", "ssh"],
    user: "root",
    host: "web",
    host_fingerprint: "SHA256:h",
    rememberable: true,
    remember_minutes: 240,
    needs_passphrase: false,
    passphrase_error: null,
    preapproved: false,
    ...over,
  };
}

describe("approval text", () => {
  it("names the program, the key and the destination", () => {
    expect(approvalTitle(request())).toBe("Allow claude to use id_mac?");
    expect(programChainLine(request())).toBe("claude → zsh → ssh");
    expect(destination(request())).toBe("root@web");
  });

  it("says when the program or the host is unknown", () => {
    expect(programName(request({ program_chain: [] }))).toBe("an unknown program");
    expect(programChainLine(request({ program_chain: ["ssh"] }))).toBeNull();
    expect(destination(request({ host: null }))).toBe("root@an unknown host");
    expect(destination(request({ user: null, host: null }))).toBe("an unknown host");
  });

  it("shows hidden characters from other programs instead of rendering them", () => {
    expect(destination(request({ user: "ro\u202Eot" }))).toBe("ro⟨U+202E⟩ot@web");
    expect(approvalTitle(request({ program_chain: ["cl\u0007aude"] }))).toContain("⟨U+0007⟩");
  });

  it("titles a Connect unlock differently", () => {
    expect(approvalTitle(request({ preapproved: true }))).toBe("Unlock id_mac to connect to root@web");
  });

  it("labels each remember choice", () => {
    expect(rememberLabel(15)).toBe("Remember for 15 minutes");
    expect(rememberLabel(60)).toBe("Remember for 1 hour");
    expect(rememberLabel(240)).toBe("Remember for 4 hours");
    expect(rememberLabel(720)).toBe("Remember for 12 hours");
  });
});

describe("buildAnswer", () => {
  const picked = { remember: true, passphrase: "hunter2", rememberPassphrase: true };

  it("sends everything that was picked when everything applies", () => {
    expect(buildAnswer(request({ needs_passphrase: true }), true, picked)).toEqual({
      allow: true,
      remember: true,
      passphrase: "hunter2",
      remember_passphrase: true,
    });
  });

  it("remembers the approval only when allowed, rememberable and not a Connect unlock", () => {
    expect(buildAnswer(request(), true, picked).remember).toBe(true);
    expect(buildAnswer(request(), true, { ...picked, remember: false }).remember).toBe(false);
    expect(buildAnswer(request({ rememberable: false }), true, picked).remember).toBe(false);
    expect(buildAnswer(request({ preapproved: true }), true, picked).remember).toBe(false);
    expect(buildAnswer(request(), false, picked).remember).toBe(false);
  });

  it("sends the passphrase and its remember choice only when allowed and needed", () => {
    const needs = request({ needs_passphrase: true });
    expect(buildAnswer(needs, true, { ...picked, rememberPassphrase: false })).toMatchObject({ passphrase: "hunter2", remember_passphrase: false });
    expect(buildAnswer(request(), true, picked)).toMatchObject({ passphrase: null, remember_passphrase: false });
    // A Connect unlock still takes the passphrase, and may remember it.
    expect(buildAnswer(request({ preapproved: true, needs_passphrase: true }), true, picked)).toEqual({
      allow: true,
      remember: false,
      passphrase: "hunter2",
      remember_passphrase: true,
    });
  });

  it("carries nothing in a denial", () => {
    for (const r of [request(), request({ needs_passphrase: true }), request({ preapproved: true, needs_passphrase: true })]) {
      expect(buildAnswer(r, false, picked)).toEqual({ allow: false, remember: false, passphrase: null, remember_passphrase: false });
    }
  });
});

describe("allowDisabled", () => {
  it("is on until the card is armed, even for a request that would otherwise be allowed", () => {
    expect(allowDisabled(request(), "", false, false)).toBe(true);
    expect(allowDisabled(request({ needs_passphrase: true }), "hunter2", false, false)).toBe(true);
    expect(allowDisabled(request({ preapproved: true, needs_passphrase: true }), "hunter2", false, false)).toBe(true);
  });

  it("is on while an answer is on its way", () => {
    expect(allowDisabled(request(), "", true, true)).toBe(true);
    expect(allowDisabled(request({ needs_passphrase: true }), "hunter2", true, true)).toBe(true);
  });

  it("waits for a needed passphrase", () => {
    expect(allowDisabled(request({ needs_passphrase: true }), "", false, true)).toBe(true);
    expect(allowDisabled(request({ needs_passphrase: true }), "hunter2", false, true)).toBe(false);
  });

  it("does not wait for a passphrase nobody asked for", () => {
    expect(allowDisabled(request(), "", false, true)).toBe(false);
  });
});

describe("the arming delay", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("is longer than a double click and short enough not to be in the way", () => {
    expect(ALLOW_ARM_DELAY_MS).toBeGreaterThanOrEqual(500);
    expect(ALLOW_ARM_DELAY_MS).toBeLessThanOrEqual(1000);
  });

  it("arms a card only once the delay has passed", () => {
    vi.useFakeTimers();
    const arm = vi.fn();
    armAfterDelay(arm);
    vi.advanceTimersByTime(ALLOW_ARM_DELAY_MS - 1);
    expect(arm).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(arm).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(ALLOW_ARM_DELAY_MS * 2);
    expect(arm).toHaveBeenCalledTimes(1);
  });

  it("never arms a card that went away first", () => {
    vi.useFakeTimers();
    const arm = vi.fn();
    const cancel = armAfterDelay(arm);
    vi.advanceTimersByTime(ALLOW_ARM_DELAY_MS - 1);
    cancel();
    vi.advanceTimersByTime(ALLOW_ARM_DELAY_MS * 2);
    expect(arm).not.toHaveBeenCalled();
  });
});

describe("the window's busy rule", () => {
  const first = request({ id: "approval-1" });
  const second = request({ id: "approval-2" });

  it("is busy only while the card on screen is the request that was answered", () => {
    expect(isAnswering(null, first)).toBe(false);
    expect(isAnswering("approval-1", first)).toBe(true);
  });

  it("is not busy for the next request, which arrives as a card of its own", () => {
    expect(isAnswering("approval-1", second)).toBe(false);
    expect(isAnswering("approval-1", undefined)).toBe(false);
  });

  it("lets a rejected answer be given again", () => {
    expect(afterFailedAnswer("approval-1", "approval-1")).toBeNull();
  });

  it("leaves a newer answer alone when an older one is rejected late", () => {
    expect(afterFailedAnswer("approval-2", "approval-1")).toBe("approval-2");
    expect(afterFailedAnswer(null, "approval-1")).toBeNull();
  });
});

describe("the warning for a rejected answer", () => {
  it("names the request and the reason", () => {
    expect(answerRejectedMessage("approval-3", new Error("that request was already answered or has expired"))).toBe(
      "[agent] the answer to approval-3 was rejected: that request was already answered or has expired",
    );
  });

  it("takes the reason from a rejection that is not an Error (the backend rejects with its message as a string)", () => {
    expect(answerRejectedMessage("approval-3", "that request was already answered or has expired")).toBe(
      "[agent] the answer to approval-3 was rejected: that request was already answered or has expired",
    );
  });

  // The helper is given the request id and the error only, so there is nothing of the answer (a passphrase can be in it) to log.
  it("has no way to carry the answer", () => {
    expect(answerRejectedMessage.length).toBe(2);
  });
});

describe("the pending list feed", () => {
  const older = [request({ id: "approval-1" }), request({ id: "approval-2" })];
  const newer = [request({ id: "approval-2" })];

  function feed() {
    const seen: AgentApprovalRequest[][] = [];
    return { seen, feed: pendingFeed((list) => seen.push(list)) };
  }

  it("takes the fetched list while no event has arrived", () => {
    const { seen, feed: f } = feed();
    f.fromFetch(older);
    expect(seen).toEqual([older]);
  });

  it("ignores a fetch that finishes after an event, so it cannot put an older list back", () => {
    const { seen, feed: f } = feed();
    f.fromEvent(newer);
    f.fromFetch(older);
    expect(seen).toEqual([newer]);
  });

  it("keeps taking events, and drops a fetch whenever it comes once an event has", () => {
    const { seen, feed: f } = feed();
    f.fromFetch(older);
    f.fromEvent(newer);
    f.fromEvent([]);
    f.fromFetch(older);
    expect(seen).toEqual([older, newer, []]);
  });
});

describe("the agent problem line", () => {
  it("says why hosts on vault keys can't connect", () => {
    expect(agentProblemText({ kind: "not_running", reason: "path too long" })).toBe("SSHelter's agent isn't running: path too long");
    expect(agentProblemText({ kind: "include_missing" })).toBe("Hosts that use keys in SSHelter can't reach its agent.");
  });
});

describe("the key channel that ssh asked too late", () => {
  it("listens on the event the backend emits", () => {
    expect(CONNECT_EXPIRED_EVENT).toBe("agent://connect-expired");
  });

  it("names the host and says what happened", () => {
    expect(connectExpiredMessage("web")).toEqual({
      title: "Connect to web again",
      description:
        "SSHelter offers the key for one minute after Connect, and ssh asked for it later (a new host's fingerprint question may have been open).",
    });
  });

  it("shows hidden characters in the host's name instead of rendering them", () => {
    expect(connectExpiredMessage("we\u202Eb").title).toBe("Connect to we⟨U+202E⟩b again");
    expect(connectExpiredMessage("we\u0007b").title).toContain("⟨U+0007⟩");
  });
});
