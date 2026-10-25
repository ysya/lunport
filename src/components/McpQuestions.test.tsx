import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { McpApprovalCardView } from "./McpApprovalDialog";
import { Dialog } from "./ui/dialog";
import { AuthenticationCardView } from "./AuthenticationWindow";
import type { McpPendingRequest } from "@/bindings/McpPendingRequest";
import type { AuthRequest } from "@/bindings/AuthRequest";

const request: McpPendingRequest = {
  id: "exec1", host_id: "stable-host", route: ["jump-id", "stable-host"],
  requested_by: ["observed-process"], requester_id: "42",
  client_info: { name: "claimed-client", title: null, version: "1" },
  alias: "web", command: "echo <hello>; sleep 3; END-OF-COMMAND",
  hostname: "fixture.invalid", user: "ops", port: "2222", requested_at_ms: 1,
};
const question: AuthRequest = {
  id: "q1", request_id: "exec1",
  hop: { host_id: "jump-id", alias: "jump", hostname: "hop.invalid", user: "hopuser", port: 2222 },
  kind: "interactive", text: "<script>server challenge</script>", echo: false, remaining_ms: 1000, grant: null,
};
const renderAuth = (over: Partial<Parameters<typeof AuthenticationCardView>[0]> = {}) =>
  renderToStaticMarkup(
    <AuthenticationCardView request={question} busy={false} armed={true} remainingMs={1000}
      answer="" onChange={() => {}} onAnswer={() => {}} {...over} />,
  );
const renderReview = (over: Partial<Parameters<typeof McpApprovalCardView>[0]> = {}) =>
  renderToStaticMarkup(
    <Dialog open><McpApprovalCardView request={request} busy={false} armed={true} onAnswer={() => {}} {...over} /></Dialog>,
  );
function disabled(html: string, label: string) {
  const match = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)]
    .find(m => m[2].replace(/<!--.*?-->/g, "").trim() === label);
  if (!match) throw Error(`missing ${label}`);
  return match[1].includes('disabled=""');
}

describe("MCP command review", () => {
  it("keeps full command, effective endpoint, stable host and route with distinct observed and claimed attribution", () => {
    const html = renderReview();
    expect(html).toContain("END-OF-COMMAND");
    expect(html).toContain("ops@fixture.invalid:2222");
    expect(html).toContain("stable-host");
    expect(html).toContain("jump-id");
    expect(html).toContain("Observed requester");
    expect(html).toContain("Self-reported client");
    expect(html).toContain("claimed-client");
    expect(html).toMatch(/<button[^>]*autofocus=""[^>]*>Deny</);
  });

  it("blocks Allow until review is armed or after expiry, while Deny stays available", () => {
    const html = renderReview({ armed: false });
    expect(disabled(html, "Allow once")).toBe(true);
    expect(disabled(html, "Deny")).toBe(false);
    expect(disabled(renderReview({ expired: true }), "Allow once")).toBe(true);
  });

  it("reviews host creation with complete settings, no implicit access, and delayed consent", () => {
    const proposed = { ...request, command: "", host_proposal: { settings: [
      ["Alias", "new-web"], ["Hostname", "127.0.0.1"], ["Port", "2222"],
      ["Storage", "This device's library"], ["Tags", "<untrusted>"],
    ] as [string, string][] } };
    const html = renderReview({ request: proposed });
    expect(html).toContain("Add this SSH host?");
    expect(html).toContain("AI access remains off");
    expect(html).toContain("127.0.0.1");
    expect(html).toContain("2222");
    expect(html).toContain("&lt;untrusted&gt;");
    expect(html).not.toContain("Remote command");
    expect(disabled(html, "Add host")).toBe(false);
    expect(disabled(renderReview({ request: proposed, armed: false }), "Add host")).toBe(true);
    expect(disabled(renderReview({ request: proposed, expired: true }), "Add host")).toBe(true);
    expect(disabled(html, "Deny")).toBe(false);
  });
});

describe("native authentication rendering", () => {
  it("escapes server challenge and separates trusted request/hop context, with Cancel default focus", () => {
    const html = renderAuth();
    expect(html).toContain("&lt;script&gt;server challenge&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("exec1");
    expect(html).toContain("hopuser@hop.invalid:2222");
    expect(html).toContain("jump-id");
    expect(html).toMatch(/<button[^>]*autofocus=""[^>]*>Cancel</);
  });

  it("keeps the response input outside the long-prompt scroll body", () => {
    const html = renderAuth();
    const main = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/)![1];
    expect(main).not.toContain("<input");
    expect(html).toContain('aria-label="Authentication response"');
  });

  it("conceals secrets and honors echo without browser completion", () => {
    expect(renderAuth()).toContain('type="password"');
    expect(renderAuth({ request: { ...question, echo: true } })).toContain('type="text"');
    expect(renderAuth()).toContain('autoComplete="off"');
  });

  it("labels password prompts and explains the one-time answer without offering to save an unverified password", () => {
    const html = renderAuth({ request: { ...question, kind: "password" } });
    expect(html).toContain('aria-label="Password"');
    expect(html).toContain("Used for this connection only");
    expect(html).toContain('aria-label="Show answer"');
    expect(html).not.toContain("Remember password");
  });

  it("removes answer inputs on expiry or abandoned retry and holds Submit until armed", () => {
    expect(renderAuth({ remainingMs: 0 })).not.toContain("<input");
    expect(renderAuth({ abandoned: true, answer: "must not render" })).not.toContain("must not render");
    expect(renderAuth({ abandoned: true })).not.toContain("<input");
    expect(disabled(renderAuth({ armed: false }), "Submit")).toBe(true);
  });
});
