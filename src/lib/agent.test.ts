import { describe, expect, it } from "vitest";

import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { allowDisabled, approvalTitle, buildAnswer, destination, programChainLine, programName, rememberLabel } from "@/lib/agent";

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
  it("is on while an answer is on its way", () => {
    expect(allowDisabled(request(), "", true)).toBe(true);
    expect(allowDisabled(request({ needs_passphrase: true }), "hunter2", true)).toBe(true);
  });

  it("waits for a needed passphrase", () => {
    expect(allowDisabled(request({ needs_passphrase: true }), "", false)).toBe(true);
    expect(allowDisabled(request({ needs_passphrase: true }), "hunter2", false)).toBe(false);
  });

  it("does not wait for a passphrase nobody asked for", () => {
    expect(allowDisabled(request(), "", false)).toBe(false);
  });
});
