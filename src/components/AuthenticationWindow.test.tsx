import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AuthenticationCardView } from "./AuthenticationWindow";
import { encodeGrantAnswer } from "@/lib/mcp-flow";
import type { AuthRequest } from "@/bindings/AuthRequest";

const grant: AuthRequest = {
  id: "g1", request_id: "terminal-7", hop: null, kind: "grant", echo: true, remaining_ms: 300000,
  text: "No active Privileged Access Manager grant for prod-operate on knowknow-prod.",
  grant: { project: "knowknow-prod", entitlement: "prod-operate", minutes: 30, justification: "restart app-api" },
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
    expect(html).toContain("No active Privileged Access Manager grant for prod-operate on knowknow-prod.");
    expect(tag(html, "Justification")).toContain('value="restart app-api"');
    expect(tag(html, "Justification")).toContain('autofocus=""');
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

  it("drops the form once the request is over, like any other question", () => {
    expect(render({ remainingMs: 0 })).not.toContain("<input");
    expect(render({ abandoned: true, answer: encodeGrantAnswer("30", "must not render") })).not.toContain("must not render");
  });

  it("still shows a server's question the old way", () => {
    const html = render({ request: { ...grant, kind: "password", grant: null, text: "deploy@web's password: ", echo: false }, answer: "" });
    expect(html).toContain("SSH authentication");
    expect(html).toContain("Server prompt");
    expect(html).toMatch(/>Submit</);
  });
});
