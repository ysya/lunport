import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { recordsStatusKey } from "@/lib/records";
import { recordsStatus } from "./fixtures";
vi.mock("@/lib/queries", async (load) => {
  const original = await load<typeof import("@/lib/queries")>();
  return {
    ...original,
    usePlatform: () => ({ data: "linux" }),
    useTerminals: () => ({ data: [] }),
  };
});
import App from "@/App";
describe("App workspace boundary", () => {
  const render = (status: ReturnType<typeof recordsStatus>) => {
    const client = new QueryClient();
    client.setQueryData(recordsStatusKey, status);
    return renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <App />
      </QueryClientProvider>,
    );
  };
  it("opens a saved OpenSSH workspace on the import landing, with no way back into the retired editor", () => {
    const html = render(recordsStatus({ format: "legacy", overview: null }));
    expect(html).toContain("Your existing workspace");
    expect(html).toContain("Preview migration");
    expect(html).not.toContain("Use existing SSH configuration");
  });
  it("shows a blocked workspace's reason instead of any workspace", () => {
    const html = render(recordsStatus({ format: "blocked", blocked_reason: "Invalid state", overview: null }));
    expect(html).toContain("Invalid state");
    expect(html).not.toContain("Your existing workspace");
  });
});
