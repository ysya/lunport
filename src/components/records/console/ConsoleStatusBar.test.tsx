import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { routeSummary, type SavedDatabase } from "@/lib/databases";
import { hostPayload, hostView, recordOverview } from "../fixtures";
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
const WEB = "00000000000000b1";

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
  it("a_prod_session_names_its_instance_account_and_lock", () => {
    const html = render();
    const words = text(html);
    expect(html).toContain('data-environment="prod"');
    expect(words).toContain("PROD");
    expect(words).toContain("orders-pg · acme-prod-123456");
    expect(words).toContain("frank@example.com · IAM");
    expect(words).toContain("Read-only (locked)");
    expect(words).toContain("Public IP");
  });

  it("a_not_locked_session_says_so", () => {
    expect(text(render({ readOnly: "not_locked" }))).toContain("Read-only (not locked)");
  });

  it("other_environments_have_their_labels", () => {
    expect(text(render({ environment: "staging" }))).toContain("STAGING");
    expect(text(render({ environment: "dev" }))).toContain("DEV");
  });

  it("a_database_through_a_host_names_the_host", () => {
    const through: SavedDatabase = { ...ORDERS, network: "private", via_host: WEB };
    const overview = recordOverview({ hosts: [hostView({ id: WEB, payload: hostPayload({ alias: "web-1" }) })] });
    const words = text(render({ database: through, route: routeSummary(overview, through) }));
    expect(words).toContain("via web-1");
    expect(words).not.toContain("Public IP");
  });

  it("the_grant_line_shows_when_there_is_one", () => {
    const words = text(render({ grant: { text: "Grant ends in 4 min", tone: "warning", request: false } }));
    expect(words).toContain("Grant ends in 4 min");
  });
});
