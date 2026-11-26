import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AuthenticationCardView } from "./AuthenticationWindow";
import { encodeGrantAnswer } from "@/lib/mcp-flow";
import type { AuthRequest } from "@/bindings/AuthRequest";

const grant: AuthRequest = {
  id: "g1", request_id: "terminal-7", hop: null, kind: "grant", echo: true, remaining_ms: 300000,
  text: "No active Privileged Access Manager grant for prod-operate on acme-prod-123456.",
  grant: { project: "acme-prod-123456", entitlement: "prod-operate", minutes: 30, justification: "restart app-api", max_minutes: null, suggested: null },
  ai: null,
};
const render = (over: Partial<Parameters<typeof AuthenticationCardView>[0]> = {}) =>
  renderToStaticMarkup(
    <AuthenticationCardView request={grant} busy={false} armed={true} remainingMs={300000}
      answer={encodeGrantAnswer("30", "restart app-api")} onChange={() => {}} onAnswer={() => {}} {...over} />,
  );
function tag(html: string, label: string) {
  const match = [...html.matchAll(/<input\b[^>]*>/g)].map(m => m[0]).find(input => input.includes(`aria-label="${label}"`));
  if (!match) throw Error(`missing input ${label}`);
  return match;
}
function textarea(html: string, label: string) {
  const match = [...html.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g)].find(m => m[1].includes(`aria-label="${label}"`));
  if (!match) throw Error(`missing textarea ${label}`);
  return { attributes: match[1], value: match[2] };
}
function disabled(html: string, label: string) {
  const match = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)]
    .find(m => m[2].replace(/<!--.*?-->/g, "").trim() === label);
  if (!match) throw Error(`missing ${label}`);
  return match[1].includes('disabled=""');
}

describe("the Request-a-grant window", () => {
  it("asks for a grant with its own form, prefilled, and answers both fields", () => {
    const html = render();
    expect(html).toContain("Request a grant");
    expect(html).not.toContain("SSH authentication");
    expect(html).toContain("No active Privileged Access Manager grant for prod-operate on acme-prod-123456.");
    expect(textarea(html, "Justification").value).toBe("restart app-api");
    expect(textarea(html, "Justification").attributes).toContain('autofocus=""');
    expect(tag(html, "Duration (minutes)")).toContain('value="30"');
    expect(html).not.toContain("Server prompt");
    expect(html).not.toContain("Server context");
    expect(html).toMatch(/<button[^>]*>Request</);
    expect(html).not.toMatch(/>Submit</);
    expect(html).not.toMatch(/<button[^>]*autofocus=""[^>]*>Cancel</);
    expect(disabled(html, "Request")).toBe(false);
    expect(disabled(render({ answer: encodeGrantAnswer("30", "   ") }), "Request")).toBe(true);
    expect(disabled(render({ answer: encodeGrantAnswer("0", "restart app-api") }), "Request")).toBe(true);
    expect(disabled(render({ answer: encodeGrantAnswer("481", "restart app-api") }), "Request")).toBe(true);
    expect(disabled(render({ armed: false }), "Request")).toBe(true);
  });

  it("marks what an AI client suggested, offers the remembered justification back, and says how the length is bounded", () => {
    const suggestedGrant = {
      ...grant,
      ai: { client: "claude", unreviewed: null },
      grant: { ...grant.grant!, max_minutes: 60, suggested: { justification: "restart app-api after the deploy", minutes: 60, capped_from: 120 } },
    };
    const html = render({ request: suggestedGrant, answer: encodeGrantAnswer("60", "restart app-api after the deploy") });
    expect(html.match(/Suggested by claude/g)?.length).toBe(2);
    expect(html).toContain("Use my last justification");
    expect(html).toContain("Capped at 60 minutes, the entitlement’s maximum.");
    expect(tag(html, "Duration (minutes)")).toContain('max="60"');
    expect(disabled(render({ request: suggestedGrant, answer: encodeGrantAnswer("61", "restart app-api after the deploy") }), "Request")).toBe(true);
    // Once the person changes a field, it is theirs.
    const edited = render({ request: suggestedGrant, answer: encodeGrantAnswer("45", "restart app-api after the hotfix") });
    expect(edited).not.toContain("Suggested by claude");
    // The remembered justification in the field needs no button to bring it back.
    expect(render({ request: suggestedGrant, answer: encodeGrantAnswer("60", "restart app-api") })).not.toContain("Use my last justification");
    // An unknown maximum is said, and a person's own grant question shows no suggestion.
    const unknown = render({ request: { ...suggestedGrant, grant: { ...suggestedGrant.grant, max_minutes: null, suggested: { justification: "restart app-api after the deploy", minutes: 60, capped_from: null } } } });
    expect(unknown).toContain("The entitlement’s maximum is unknown");
    expect(unknown).not.toContain("Capped at");
    expect(render()).not.toContain("Suggested by");
    expect(render()).toContain("The entitlement’s maximum is unknown");
    expect(render({ request: { ...grant, grant: { ...grant.grant!, max_minutes: 60 } } })).not.toContain("maximum is unknown");
  });

  it("drops the form once the request is over, like any other question", () => {
    expect(render({ remainingMs: 0 })).not.toContain("<input");
    expect(render({ remainingMs: 0 })).not.toContain("<textarea");
    expect(render({ abandoned: true, answer: encodeGrantAnswer("30", "must not render") })).not.toContain("must not render");
  });

  it("still shows a server's question the old way", () => {
    const html = render({ request: { ...grant, kind: "password", grant: null, text: "deploy@web's password: ", echo: false }, answer: "" });
    expect(html).toContain("SSH authentication");
    expect(html).toContain("Server prompt");
    expect(html).toMatch(/>Submit</);
  });
});

describe("a question an AI client's request asks", () => {
  const password = { ...grant, kind: "password", grant: null, text: "deploy@web's password: ", echo: false };
  it("names the AI client on the grant form, and in Auto-log says its commands then run without review", () => {
    const html = render({ request: { ...grant, ai: { client: "claude → node", unreviewed: "command" } } });
    expect(html).toContain("Asked by claude → node, an AI client using Lunport AI access.");
    expect(html).toContain("Auto-log is on: while the grant lasts, the AI client’s commands run without per-command review.");
  });
  it("says a tunnel starts once the grant is active", () => {
    expect(render({ request: { ...grant, ai: { client: "claude", unreviewed: "tunnel" } } })).toContain(
      "Auto-log is on: once the grant is active, the tunnel the AI client asked for starts right away, without review.",
    );
  });
  it("says a database starts once the grant is active", () => {
    expect(render({ request: { ...grant, ai: { client: "claude", unreviewed: "database" } } })).toContain(
      "Auto-log is on: once the grant is active, the database the AI client asked for starts right away, without review.",
    );
  });
  it("says a database starts once a server's question is answered", () => {
    expect(render({ request: { ...password, ai: { client: "claude", unreviewed: "database" } }, answer: "" })).toContain(
      "Auto-log is on: once you answer, the database the AI client asked for starts right away, without review.",
    );
  });
  it("names the AI client on a server's question too, with its Auto-log note", () => {
    const html = render({ request: { ...password, ai: { client: "claude", unreviewed: "command" } }, answer: "" });
    expect(html).toContain("Asked by claude, an AI client using Lunport AI access.");
    expect(html).toContain("Auto-log is on: once you answer, the AI client’s command runs right away, without per-command review.");
  });
  it("names the client without an Auto-log note in Ask mode, and nobody for a person's question", () => {
    const ask = render({ request: { ...password, ai: { client: "claude", unreviewed: null } }, answer: "" });
    expect(ask).toContain("Asked by claude");
    expect(ask).not.toContain("Auto-log");
    expect(render()).not.toContain("Asked by");
  });
});
