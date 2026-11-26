import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { routeSummary, type SavedDatabase } from "@/lib/databases";
import { recordOverview } from "../fixtures";
import { ConsoleStatusBar } from "./ConsoleStatusBar";

const ORDERS: SavedDatabase = {
  id: "00000000000000a1",
  name: "Orders",
  engine: "postgres",
  project: "acme-prod-123456",
  region: "asia-east1",
  instance: "orders-pg",
  environment: "prod",
  network: "public",
  account: "frank@example.com",
  default_database: "postgres",
  pam: null,
  local_port: null,
};

function render(props: Partial<Parameters<typeof ConsoleStatusBar>[0]> = {}) {
  return renderToStaticMarkup(
    <ConsoleStatusBar
      environment="prod"
      database={ORDERS}
      route={routeSummary(recordOverview(), ORDERS)}
      iamUser="frank@example.com"
      readOnly="locked"
      grant={null}
      {...props}
    />,
  );
}

describe("ConsoleStatusBar", () => {
  it("shows the lock and environment while leaving connection metadata behind a disclosure", () => {
    const html = render();
    expect(html).toMatch(/<button[^>]*aria-label="Connection details[^"]*"[^>]*>/);
    expect(text(html)).toContain("Read-only (locked)");
    expect(text(html)).toContain("PROD");
    expect(text(html)).not.toContain("frank@example.com");
  });

  it("waits to show a lock state until the session confirms it", () => {
    expect(text(render({ readOnly: null }))).not.toContain("Read-only");
  });

  it("a_not_locked_session_says_so", () => {
    expect(text(render({ readOnly: "not_locked" }))).toContain("Read-only (not locked)");
  });

  it("other_environments_have_their_labels", () => {
    expect(text(render({ environment: "staging" }))).toContain("STAGING");
    expect(text(render({ environment: "dev" }))).toContain("DEV");
  });

  it("the_grant_line_shows_when_there_is_one", () => {
    const words = text(render({ grant: { text: "Grant ends in 4 min", tone: "warning", request: false } }));
    expect(words).toContain("Grant ends in 4 min");
  });
});
