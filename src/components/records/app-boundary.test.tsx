import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { recordsStatusKey } from "@/lib/records";
import { recordsStatus } from "./fixtures";
vi.mock("@/lib/queries", async (load) => {
  const original = await load<typeof import("@/lib/queries")>();
  return {
    ...original,
    useHostsQuery: vi.fn(() => {
      throw new Error("Legacy config hook mounted");
    }),
    usePlatform: () => ({ data: "linux" }),
    useTerminals: () => ({ data: [] }),
  };
});
import App from "@/App";
import { useHostsQuery } from "@/lib/queries";
describe("App records boundary", () => {
  it("does not mount config hooks in records, paused legacy or blocked mode", () => {
    for (const status of [
      recordsStatus(),
      recordsStatus({ format: "legacy", legacy_paused: true, overview: null }),
      recordsStatus({
        format: "blocked",
        blocked_reason: "Invalid state",
        overview: null,
      }),
    ]) {
      const client = new QueryClient();
      client.setQueryData(recordsStatusKey, status);
      const html = renderToStaticMarkup(
        <QueryClientProvider client={client}>
          <App />
        </QueryClientProvider>,
      );
      expect(html).not.toContain("Legacy config hook mounted");
    }
    expect(useHostsQuery).not.toHaveBeenCalled();
  });
});
