/** All clients use the same local stdio adapter; only their installation format differs. */
export type McpSetupClient = "codex" | "claude_code" | "claude_desktop" | "cursor" | "vscode" | "other";
export type McpSetupFormat = "json" | "toml" | "vscode";

export const MCP_SERVER_ID = "lunport";
export const mcpSetupClients: ReadonlyArray<{ id: McpSetupClient; name: string; description: string }> = [
  { id: "codex", name: "Codex", description: "Desktop, CLI and IDE extension" },
  { id: "claude_code", name: "Claude Code", description: "Available across your projects" },
  { id: "claude_desktop", name: "Claude Desktop", description: "Claude app on this computer" },
  { id: "cursor", name: "Cursor", description: "Review and add in Cursor" },
  { id: "vscode", name: "VS Code", description: "Copilot and compatible agents" },
  { id: "other", name: "Other agent", description: "Use a local MCP server" },
];

export function mcpStdioServer(executable: string) {
  return { command: executable, args: ["--mcp"] };
}

// TOML basic strings and JSON strings share these escapes; control characters outside
// JSON's short escape set are emitted as TOML-supported \uXXXX sequences by JSON.stringify.
export function mcpSetupConfig(executable: string, format: McpSetupFormat = "json"): string {
  if (format === "toml") {
    return `[mcp_servers.${MCP_SERVER_ID}]\ncommand = ${JSON.stringify(executable).replace(/\u007f/g, "\\u007f")}\nargs = ["--mcp"]\n`;
  }
  const server = mcpStdioServer(executable);
  return JSON.stringify(format === "vscode"
    ? { servers: { [MCP_SERVER_ID]: { type: "stdio", ...server } } }
    : { mcpServers: { [MCP_SERVER_ID]: server } }, null, 2);
}

export function shellQuoteMcp(value: string, platform: string | undefined): string {
  // These are PowerShell commands on Windows, with single quotes preventing $/` expansion.
  return platform === "windows" ? `'${value.replace(/'/g, "''")}'` : `'${value.replace(/'/g, `'\\''`)}'`;
}

export function mcpSetupCommand(executable: string, client: "codex" | "claude_code", platform?: string): string {
  const command = client === "codex" ? "codex mcp add" : "claude mcp add --scope user --transport stdio";
  return `${command} ${MCP_SERVER_ID} -- ${shellQuoteMcp(executable, platform)} --mcp`;
}
