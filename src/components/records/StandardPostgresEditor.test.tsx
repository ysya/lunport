import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import { hostPayload, hostView, recordOverview } from "./fixtures";
import { StandardPostgresEditor } from "./StandardPostgresEditor";
import type { StandardPostgresProfile } from "@/lib/standard-postgres";

const host = hostView({ payload: hostPayload({ alias: "web-1", hostname: "web.example.com" }) });
const profile: StandardPostgresProfile = {
  id: "postgres-a1", name: "Reports", host: "reports.example.com", port: 5432, database: "reports", username: "reader",
  via_host: host.id, has_password: true, revision: "a1", route_unavailable: false, route_revision: null,
};
const overview = recordOverview({ hosts: [host] });

function render(initial: StandardPostgresProfile | null) {
  return renderToStaticMarkup(<StandardPostgresEditor initial={initial} overview={overview} busy={false} error={null}
    onDirty={vi.fn()} onSave={vi.fn()} onCancel={vi.fn()} />);
}

describe("StandardPostgresEditor", () => {
  it("starts direct on port 5432 and leaves remembering the password off", () => {
    const html = render(null);
    expect(html).toMatch(/<input[^>]+type="number"[^>]+value="5432"/);
    expect(html).toMatch(/<button[^>]+aria-checked="true"[^>]*>Direct<\/button>/);
    expect(html).toContain('role="switch" aria-checked="false"');
    expect(html).not.toContain('type="password"');
    expect(html).not.toContain('aria-label="Search route hosts"');
  });

  it("shows the saved SSH route without populating the password field", () => {
    const html = render(profile);
    expect(text(html)).toContain("Selected host: web-1");
    expect(html).toContain('aria-label="Search route hosts"');
    expect(html).toContain('role="switch" aria-checked="true"');
    expect(html).toContain('type="password"');
    expect(html).not.toMatch(/<input[^>]+type="password"[^>]+value=/);
    expect(buttonTag(html, "Save database")).not.toContain(DISABLED);
  });

  it("requires fixing an unavailable route even when a new scope exposes the same host ID", () => {
    const html = render({ ...profile, route_unavailable: true });
    expect(text(html)).toContain("Host unavailable");
    expect(text(html)).not.toContain("Selected host");
    expect(buttonTag(html, "Save database")).toContain(DISABLED);
  });
});
