import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { databasesQuery, type DatabaseView } from "@/lib/databases";
import { standardPostgresQuery, type StandardPostgresProfile } from "@/lib/standard-postgres";
import { DatabaseWorkspaceExplorer } from "./DatabaseWorkspaceExplorer";

const cloud: DatabaseView = {
  database: {
    id: "cloud-a", name: "Orders", engine: "postgres", project: "acme-dev-654321", region: "asia-east1", instance: "orders",
    environment: "dev", network: "public", account: null, default_database: "orders", pam: null, local_port: null,
  },
  environment: "dev", synced: true, blocked: false, removed: false, changed: false,
  live: { phase: "stopped", port: null, connections: 0, writable_until_ms: null, error: null, step: null, address: null },
};
const postgres: StandardPostgresProfile = {
  id: "postgres-a", name: "Ledger", host: "postgres.example.com", port: 5432, database: "ledger", username: "frank",
  via_host: null, has_password: true, route_unavailable: false, route_revision: null, revision: "rev-a",
};

function render() {
  const client = new QueryClient();
  client.setQueryData(databasesQuery.queryKey, [cloud, { ...cloud, database: { ...cloud.database, id: "cloud-b", name: "Removed" }, removed: true }]);
  client.setQueryData(standardPostgresQuery.queryKey, [postgres]);
  return renderToStaticMarkup(<QueryClientProvider client={client}>
    <DatabaseWorkspaceExplorer activeId={null} sources={new Map()} onBrowse={vi.fn()} onOpenQuery={vi.fn()} />
  </QueryClientProvider>);
}

describe("DatabaseWorkspaceExplorer", () => {
  it("lists saved Cloud SQL and PostgreSQL sources side by side", () => {
    const html = render();
    expect(text(html)).toMatch(/Orders DEV.*Ledger/);
    expect(text(html)).not.toContain("Removed");
    expect(html.match(/aria-expanded="false"/g)).toHaveLength(2);
    expect(html.match(/aria-label="Filter databases and objects"/g)).toHaveLength(1);
  });
});
