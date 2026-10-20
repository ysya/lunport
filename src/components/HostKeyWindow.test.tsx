import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { HostKeyCard, HostKeyCardView } from "@/components/HostKeyWindow";

function request(over: Partial<HostKeyRequest> = {}): HostKeyRequest {
  return {
    user: "",
    id: "hostkey-1",
    alias: "web",
    hostname: "web.example.com",
    port: 22,
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:new",
    changed: null,
    ...over,
  };
}

const render = (
  r: HostKeyRequest,
  over: { busy?: boolean; armed?: boolean } = {},
) =>
  renderToStaticMarkup(
    <HostKeyCardView
      request={r}
      busy={over.busy ?? false}
      armed={over.armed ?? true}
      onAnswer={() => {}}
    />,
  );

/** Whether the button labelled `label` is disabled (React separates text nodes with comments). */
function buttonDisabled(html: string, label: string): boolean {
  const found = [
    ...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g),
  ].find((m) => m[2].replace(/<!--.*?-->/g, "").trim() === label);
  if (found === undefined) throw new Error(`no ${label} button in ${html}`);
  return found[1].includes('disabled=""');
}

describe("HostKeyCardView", () => {
  it("shows the resolved username alongside the endpoint before trust", () => {
    expect(render(request({ user: "root" }))).toContain("root@web.example.com:22");
  });
  it("asks about a new key with Cancel and Trust this key", () => {
    const html = render(request());
    expect(html).toContain("Verify server identity");
    expect(html).toContain("web.example.com:22");
    expect(html).toContain("ssh-ed25519");
    expect(html).toContain("SHA256:new");
    expect(buttonDisabled(html, "Cancel")).toBe(false);
    expect(buttonDisabled(html, "Trust this key")).toBe(false);
  });

  it("warns about a changed key with Refuse and Accept new key, and shows the new key", () => {
    const html = render(
      request({
        changed: { fingerprint: "SHA256:old", pinned_at_ms: 1_700_000_000_000 },
      }),
    );
    expect(html).toContain("Server identity changed");
    expect(html).toContain("connection may be intercepted");
    expect(html).toContain("SHA256:new");
    expect(buttonDisabled(html, "Refuse")).toBe(false);
    expect(buttonDisabled(html, "Accept new key")).toBe(false);
  });

  it("shows both fingerprints when a stored server identity changes", () => {
    const html = render(
      request({
        changed: {
          fingerprint: "SHA256:previous",
          pinned_at_ms: 1_700_000_000_000,
        },
      }),
    );
    expect(html).toContain("SHA256:previous");
    expect(html).toContain("SHA256:new");
    expect(html).toContain('aria-label="Copy server fingerprint"');
  });

  it("keeps trust off until armed and both buttons off while an answer is on its way", () => {
    expect(
      buttonDisabled(render(request(), { armed: false }), "Trust this key"),
    ).toBe(true);
    expect(buttonDisabled(render(request(), { armed: false }), "Cancel")).toBe(
      false,
    );
    const busy = render(request(), { busy: true });
    expect(buttonDisabled(busy, "Cancel")).toBe(true);
    expect(buttonDisabled(busy, "Trust this key")).toBe(true);
  });

  it("is not armed the moment a card mounts", () => {
    const first = renderToStaticMarkup(
      <HostKeyCard request={request()} busy={false} onAnswer={() => {}} />,
    );
    expect(buttonDisabled(first, "Trust this key")).toBe(true);
  });
});
