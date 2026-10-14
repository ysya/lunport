import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { recordOverview } from "./fixtures";
import { SettingsCategoryPane } from "@/components/SettingsDialog";
import { mcpStatusKey } from "@/lib/mcp";
import { text } from "@/components/keychain/test-markup";

vi.mock("@/lib/queries", async (load) => {
  const original = await load<typeof import("@/lib/queries")>();
  return {
    ...original,
    useHostsQuery: () => {
      throw new Error("Legacy SSH config mounted");
    },
    useLoadConfig: () => {
      throw new Error("Legacy config loader mounted");
    },
    usePlatform: () => ({ data: "macos" }),
    useTerminals: () => ({ data: [] }),
    useIsDevelopment: () => ({ data: true }),
  };
});

describe("records settings compatibility", () => {
  it("renders every settings category without loading the legacy config", () => {
    const client = new QueryClient();
    client.setQueryData(mcpStatusKey, {
      enabled: false,
      bridge_active: true,
      allowed_hosts: [],
      pending: [],
      recent: [],
      executable: "/fixture/sshelter",
      last_client_at_ms: null,
    });
    for (const category of [
      "general",
      "appearance",
      "connection",
      "files",
      "ai",
      "sync",
      "advanced",
    ] as const) {
      const html = renderToStaticMarkup(
        <QueryClientProvider client={client}>
          <SettingsCategoryPane
            category={category}
            recordOverview={recordOverview()}
            onOpenImport={vi.fn()}
          />
        </QueryClientProvider>,
      );
      expect(text(html)).not.toContain("Legacy SSH config mounted");
      if (category === "ai") {
        expect(text(html)).toContain("MCP");
        expect(text(html)).toContain(
          "Remote command execution is not available",
        );
        expect(html).toContain("mcp-host-0000000000000001");
      }
    }
  });
});
