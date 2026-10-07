import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { ApprovalCard, ApprovalCardView } from "@/components/AgentApprovalWindow";

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

/** A card that has been on screen long enough to be armed (or not, with `armed: false`). */
const render = (r: AgentApprovalRequest, over: { busy?: boolean; armed?: boolean } = {}) =>
  renderToStaticMarkup(<ApprovalCardView request={r} busy={over.busy ?? false} armed={over.armed ?? true} onAnswer={() => {}} />);

/** What the user sees the moment a card mounts: effects (and so the arming timer) have not run in a server render. */
const renderFirst = (r: AgentApprovalRequest) => renderToStaticMarkup(<ApprovalCard request={r} busy={false} onAnswer={() => {}} />);

/** Whether the button labelled `label` is disabled (React separates text nodes with comments; the checkboxes are buttons too, with no label). */
function buttonDisabled(html: string, label: string): boolean {
  const found = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)].find((m) => m[2].replace(/<!--.*?-->/g, "").trim() === label);
  if (found === undefined) throw new Error(`no ${label} button in ${html}`);
  return found[1].includes('disabled=""');
}

describe("ApprovalCardView", () => {
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

  it("has Allow and Deny on once it is armed", () => {
    const html = render(request());
    expect(buttonDisabled(html, "Allow")).toBe(false);
    expect(buttonDisabled(html, "Deny")).toBe(false);
  });

  it("has Allow off until it is armed, and Deny on", () => {
    const html = render(request(), { armed: false });
    expect(buttonDisabled(html, "Allow")).toBe(true);
    expect(buttonDisabled(html, "Deny")).toBe(false);
  });

  // A Connect unlock that needs no passphrase isolates the arming: with one, the empty field holds Unlock back as well.
  it("has Unlock off until it is armed, and Cancel on", () => {
    const html = render(request({ preapproved: true }), { armed: false });
    expect(buttonDisabled(html, "Unlock")).toBe(true);
    expect(buttonDisabled(html, "Cancel")).toBe(false);
    expect(buttonDisabled(render(request({ preapproved: true })), "Unlock")).toBe(false);
  });

  it("keeps Allow off for a needed passphrase that is still empty, armed or not", () => {
    const html = render(request({ needs_passphrase: true }));
    expect(buttonDisabled(html, "Allow")).toBe(true);
    expect(buttonDisabled(html, "Deny")).toBe(false);
  });

  it("turns both buttons off while its own answer is on the way", () => {
    const html = render(request(), { busy: true });
    expect(buttonDisabled(html, "Allow")).toBe(true);
    expect(buttonDisabled(html, "Deny")).toBe(true);
  });
});

describe("a card that has just appeared", () => {
  it("has Allow off and Deny on, so a second click of a double click cannot allow it", () => {
    const html = renderFirst(request());
    expect(buttonDisabled(html, "Allow")).toBe(true);
    expect(buttonDisabled(html, "Deny")).toBe(false);
  });

  it("has Unlock off and Cancel on for a Connect unlock", () => {
    const html = renderFirst(request({ preapproved: true }));
    expect(buttonDisabled(html, "Unlock")).toBe(true);
    expect(buttonDisabled(html, "Cancel")).toBe(false);
  });

  it("shows the same request as an armed card does", () => {
    expect(renderFirst(request()).replace(/ disabled=""/g, "")).toBe(render(request()));
  });
});

describe("the approval window", () => {
  const source = readFileSync("src/components/AgentApprovalWindow.tsx", "utf8");

  // No DOM in these tests, so the wiring is pinned in the source. A card per request id is what makes every request start
  // unarmed: if the card were reused across requests, the next one would inherit the armed state of the answered one.
  it("gives every request a card of its own", () => {
    expect(source).toMatch(/<ApprovalCard\s+key=\{request\.id\}/);
  });

  it("holds the passphrase field's Enter back with the same check as the Allow button", () => {
    expect(source).toContain("const cannotAllow = allowDisabled(request, passphrase, busy, armed);");
    expect(source).toContain('if (e.key === "Enter" && !cannotAllow) answer(true);');
    expect(source).toContain("disabled={cannotAllow}");
  });

  it("arms a card from a timer that starts when the card mounts", () => {
    expect(source).toMatch(/useEffect\(\(\) => armAfterDelay\(\(\) => setArmed\(true\)\), \[\]\);/);
  });

  it("is busy by the request it answered, not by the call that answers it", () => {
    expect(source).toContain("busy={isAnswering(answeredId, request)}");
    expect(source).toMatch(/setAnsweredId\(request\.id\);/);
    expect(source).toMatch(/\.catch\(\(\) => setAnsweredId\(\(current\) => afterFailedAnswer\(current, request\.id\)\)\)/);
  });

  it("feeds the list through the feed that drops a fetch that is older than an event", () => {
    expect(source).toContain("void fetchPending().then(feed.fromFetch);");
    expect(source).toContain("void onApprovals(feed.fromEvent)");
  });
});
