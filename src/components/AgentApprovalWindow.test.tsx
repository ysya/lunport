import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { ApprovalCard } from "@/components/AgentApprovalWindow";

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

const render = (r: AgentApprovalRequest) => renderToStaticMarkup(<ApprovalCard request={r} busy={false} onAnswer={() => {}} />);

describe("ApprovalCard", () => {
  it("asks with Deny and Allow and offers to remember", () => {
    const html = render(request());
    expect(html).toContain("Allow claude to use id_mac?");
    expect(html).toContain("claude → zsh → ssh");
    expect(html).toContain("root@web");
    expect(html).toContain("Remember for 4 hours");
    expect(html).toContain(">Deny<");
    expect(html).toContain(">Allow<");
    expect(html).not.toContain("Passphrase");
  });

  it("does not offer to remember when the request cannot be remembered", () => {
    expect(render(request({ rememberable: false }))).not.toContain("Remember for");
  });

  it("asks for the passphrase and shows the previous error", () => {
    const html = render(request({ needs_passphrase: true, passphrase_error: "That passphrase didn't work." }));
    expect(html).toContain('aria-label="Passphrase"');
    expect(html).toContain("Remember on this computer");
    expect(html).toContain("That passphrase didn&#x27;t work.");
  });

  it("unlocks for Connect with Cancel and Unlock", () => {
    const html = render(request({ preapproved: true, needs_passphrase: true }));
    expect(html).toContain("Unlock id_mac to connect to root@web");
    expect(html).toContain(">Cancel<");
    expect(html).toContain(">Unlock<");
    expect(html).not.toContain("Remember for");
  });

  it("escapes hidden characters in names", () => {
    expect(render(request({ host: "we\u202Eb" }))).toContain("we⟨U+202E⟩b");
  });
});
