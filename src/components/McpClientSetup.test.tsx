import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { McpClientSetup, mcpSetupKey, setupAction } from "./McpClientSetup";
import type { SetupOverview } from "@/bindings/SetupOverview";

vi.mock("@/lib/queries", () => ({ usePlatform: () => ({ data: "macos" }) }));
function render(data?: SetupOverview) {
  const query = new QueryClient();
  if (data) query.setQueryData(mcpSetupKey, data);
  return renderToStaticMarkup(<QueryClientProvider client={query}><McpClientSetup /></QueryClientProvider>);
}
const overview: SetupOverview = {
  sandbox: false, executable: "/Applications/Lunport.app/Contents/MacOS/sshelter",
  clients: [
    { client: "codex", state: "configured", config_path: "/fixture/.codex/config.toml", message: null },
    { client: "claude_code", state: "not_added", config_path: "/fixture/.claude.json", message: null },
    { client: "claude_desktop", state: "not_added", config_path: "/fixture/Claude/config.json", message: null },
    { client: "cursor", state: "external", config_path: null, message: null },
    { client: "vscode", state: "external", config_path: null, message: null },
  ],
};
describe("multi-agent MCP setup", () => {
  it("offers Claude and other clients and separates configured from actual client loading", () => {
    const html = render(overview);
    for (const name of ["Codex", "Claude Code", "Claude Desktop", "Cursor", "VS Code", "Other agent"]) expect(html).toContain(name);
    expect(html).toContain("Configured means the settings are saved");
    expect(html).toContain("Start a new chat in Codex");
    expect(html).not.toContain("Connected");
  });
  it("provides portable configuration with separate command and arguments", () => {
    const html = render(overview);
    expect(html).toContain("Manual setup &amp; other agents");
    expect(html).toContain("Copy MCP configuration");
    expect(html).toContain("Export MCP configuration");
    expect(html).toContain("Copy MCP command path");
    expect(html).toContain("Arguments:");
    expect(html).toContain("--mcp");
  });
  it("makes sandbox setup explicit and has a loading state", () => {
    expect(render({ ...overview, sandbox: true })).toContain("Development preview uses sandbox client settings");
    expect(render()).toContain("Checking…");
  });
  it("makes repair and enabling actions explicit instead of claiming connection", () => {
    expect(setupAction("needs_repair", "codex")).toBe("Repair setup");
    expect(setupAction("disabled", "codex")).toBe("Enable in this tool");
    expect(setupAction("configured", "codex")).toBe("Configured");
    expect(setupAction("external", "cursor")).toBe("Add to Cursor");
  });
});
