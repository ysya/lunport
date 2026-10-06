import { describe, expect, it } from "vitest";

import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { approvalTitle, destination, programChainLine, programName, rememberLabel } from "@/lib/agent";

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
    expect(destination(request({ user: "ro‮ot" }))).toBe("ro⟨U+202E⟩ot@web");
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
