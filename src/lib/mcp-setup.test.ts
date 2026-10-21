import { describe, expect, it } from "vitest";
import { MCP_SERVER_ID, mcpSetupCommand, mcpSetupConfig } from "./mcp-setup";

describe("portable MCP setup", () => {
  const executable = "/Applications/Lunport.app/Contents/MacOS/sshelter";

  it("exports the same adapter for Claude, Cursor and other mcpServers clients", () => {
    expect(JSON.parse(mcpSetupConfig(executable))).toEqual({
      mcpServers: { lunport: { command: executable, args: ["--mcp"] } },
    });
  });

  it("uses VS Code's distinct servers envelope and explicit stdio type", () => {
    expect(JSON.parse(mcpSetupConfig(executable, "vscode"))).toEqual({
      servers: { [MCP_SERVER_ID]: { type: "stdio", command: executable, args: ["--mcp"] } },
    });
  });

  it("keeps Windows paths and quotes literal in JSON and TOML", () => {
    const path = 'C:\\Users\\A "quoted" name\\Lunport\\sshelter.exe';
    expect(JSON.parse(mcpSetupConfig(path)).mcpServers[MCP_SERVER_ID].command).toBe(path);
    expect(mcpSetupConfig(path, "toml")).toContain(`command = ${JSON.stringify(path)}\n`);
  });

  it("uses user scope for Claude Code and the Lunport server name", () => {
    expect(mcpSetupCommand(executable, "claude_code", "macos"))
      .toBe(`claude mcp add --scope user --transport stdio lunport -- '${executable}' --mcp`);
    expect(mcpSetupCommand(executable, "codex", "macos"))
      .toBe(`codex mcp add lunport -- '${executable}' --mcp`);
  });

  it("does not expand PowerShell variables, backticks or apostrophes", () => {
    expect(mcpSetupCommand("C:\\O'Brien $env:HOME `x\\sshelter.exe", "codex", "windows"))
      .toBe("codex mcp add lunport -- 'C:\\O''Brien $env:HOME `x\\sshelter.exe' --mcp");
  });

  it("quotes apostrophes and shell syntax literally for POSIX manual setup", () => {
    expect(mcpSetupCommand("/tmp/O'Brien $(touch ignored)/sshelter", "codex", "macos"))
      .toBe("codex mcp add lunport -- '/tmp/O'\\''Brien $(touch ignored)/sshelter' --mcp");
  });
});
