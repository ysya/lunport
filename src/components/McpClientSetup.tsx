import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, Check, Copy, Download, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import type { SetupOverview } from "@/bindings/SetupOverview";
import type { SetupResult } from "@/bindings/SetupResult";
import type { SetupClient } from "@/bindings/SetupClient";
import { tauriInvoke } from "@/lib/ipc";
import { copyText } from "@/lib/clipboard";
import { usePlatform } from "@/lib/queries";
import { mcpSetupClients, mcpSetupConfig, mcpSetupCommand, type McpSetupClient, type McpSetupFormat } from "@/lib/mcp-setup";
import { Section } from "@/components/settings-primitives";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export const mcpSetupKey = ["mcp", "client-setup"] as const;
const nextStep: Record<McpSetupClient, string> = {
  codex: "Start a new chat in Codex to load Lunport. The desktop app, CLI and IDE extension share this setup.",
  claude_code: "Start a new Claude Code session to load Lunport across your projects.",
  claude_desktop: "Quit and reopen Claude Desktop to load Lunport.",
  cursor: "Review the installation in Cursor, then enable Lunport in your agent’s tools.",
  vscode: "Review the installation in VS Code and confirm that you trust Lunport when asked.",
  other: "Choose a local MCP server in your agent and use the command and arguments below.",
};
export function setupAction(state: string | undefined, client: McpSetupClient): string {
  if (client === "other") return "Manual setup";
  if (state === "configured") return "Configured";
  if (state === "disabled") return "Enable in this tool";
  if (state === "needs_repair") return "Repair setup";
  return `Add to ${mcpSetupClients.find(item => item.id === client)?.name ?? "tool"}`;
}

export function McpClientSetup({ fallbackExecutable, accessControl, connectionNote }: { fallbackExecutable?: string; accessControl?: ReactNode; connectionNote?: string }) {
  const queryClient = useQueryClient();
  const platform = usePlatform();
  const setup = useQuery({ queryKey: mcpSetupKey, queryFn: () => tauriInvoke<SetupOverview>("mcp_setup_overview"), staleTime: 10_000 });
  const [selected, setSelected] = useState<McpSetupClient>("codex");
  const [format, setFormat] = useState<McpSetupFormat>("json");
  const [manual, setManual] = useState(false);
  const [backup, setBackup] = useState<string | null>(null);
  const selectedClient = mcpSetupClients.find(client => client.id === selected)!;
  const state = setup.data?.clients.find(client => client.client === selected);
  const executable = setup.data?.executable ?? fallbackExecutable ?? "";
  const external = selected === "cursor" || selected === "vscode";
  const add = useMutation({
    mutationFn: (client: SetupClient) => tauriInvoke<SetupResult>("mcp_setup_add", { client }),
    onSuccess: result => {
      setBackup(result.backup_path);
      void queryClient.invalidateQueries({ queryKey: mcpSetupKey });
      toast.success(result.external ? `Continue in ${selectedClient.name}` : `${selectedClient.name} setup saved`, { description: nextStep[selected] });
    },
  });
  const exportConfig = useMutation({
    mutationFn: () => tauriInvoke<string | null>("mcp_setup_export", { format }),
    onSuccess: path => { if (path) toast.success("MCP configuration exported"); },
  });
  const copy = async (text: string, label: string) => {
    try { await copyText(text); toast.success(`${label} copied`); }
    catch (error) { toast.error("Could not copy", { description: String(error) }); }
  };
  const statusLabel = (value: string | undefined) => value === "configured" ? "Configured" : value === "needs_repair" ? "Needs repair" : value === "disabled" ? "Disabled" : value === "unavailable" ? "Manual setup" : value === "external" ? "Open in app" : "Not added";
  return <Section title="Connect an AI tool" description="Choose your tool to add Lunport. Then choose which hosts it can use below.">
    {accessControl && <div className="mb-3">{accessControl}</div>}
    {setup.data?.sandbox && <p className="mb-3 rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">Development preview uses sandbox client settings. External app installation is disabled.</p>}
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3" role="group" aria-label="AI tools">
      {mcpSetupClients.map(client => {
        const clientState = setup.data?.clients.find(item => item.client === client.id)?.state;
        return <button key={client.id} type="button" aria-pressed={selected === client.id} disabled={add.isPending}
          onClick={() => { setSelected(client.id); setManual(client.id === "other"); setBackup(null); add.reset(); exportConfig.reset(); }}
          className={cn("min-w-0 rounded-lg border px-3 py-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50", selected === client.id ? "border-primary/60 bg-primary/10" : "hover:bg-muted/50")}>
          <span className="flex items-center justify-between gap-2 text-sm font-medium">{client.name}{clientState === "configured" && <Check className="size-3.5 shrink-0 text-success" />}</span>
          <span className="mt-1 block text-xs text-muted-foreground">{client.id === "other" ? "Any local MCP client" : setup.isPending ? "Checking…" : statusLabel(clientState)}</span>
        </button>;
      })}
    </div>
    <div className="mt-3 space-y-3">
      <p className="text-sm text-muted-foreground">{state?.state === "configured" ? nextStep[selected] : selectedClient.description}</p>
      {state?.message && <p className="break-words text-sm text-muted-foreground">{state.message}</p>}
      {setup.isError && <div role="alert" className="text-sm text-destructive">Client setup could not be checked. Retry, or use manual setup.</div>}
      {add.isError && <p role="alert" className="break-words text-sm text-destructive">{String(add.error instanceof Error ? add.error.message : add.error)}</p>}
      {selected !== "other" && <div className="flex flex-wrap items-center gap-2">
        <Button disabled={!setup.data || add.isPending || state?.state === "configured" || state?.state === "unavailable" || (external && setup.data?.sandbox)} onClick={() => add.mutate(selected as SetupClient)}>
          {state?.state === "configured" ? <Check className="size-4" /> : external ? <ArrowUpRight className="size-4" /> : null}
          {add.isPending ? "Adding…" : setupAction(state?.state, selected)}
        </Button>
        <Button variant="ghost" size="sm" disabled={setup.isFetching || add.isPending} onClick={() => void setup.refetch()}><RefreshCw className={cn("size-3.5", setup.isFetching && "motion-safe:animate-spin")} />Refresh status</Button>
      </div>}
      {backup && <p className="text-xs text-muted-foreground">Original settings backed up. The backup location is available under Manual setup.</p>}
      <p className="text-xs text-muted-foreground">Configured means the settings are saved. Open your AI tool to load Lunport; host access and command review remain controlled here.</p>
      {connectionNote && <p role="status" className="text-xs text-muted-foreground">{connectionNote}</p>}
    </div>
    <details open={manual} onToggle={event => setManual(event.currentTarget.open)} className="mt-4 border-t pt-3">
      <summary className="cursor-pointer text-sm text-muted-foreground">Manual setup & other agents</summary>
      <div className="mt-3 space-y-3">
        <p className="text-xs text-muted-foreground">For agents that support local MCP (stdio) on this computer. No Lunport API key is needed.</p>
        <p className="text-xs text-muted-foreground">New server name: <code>lunport</code>. Existing <code>sshelter</code> registrations and executable paths remain supported.</p>
        <div className="flex items-center gap-2">
          <Select value={format} onValueChange={value => setFormat(value as McpSetupFormat)}><SelectTrigger aria-label="MCP configuration format" className="min-w-0 flex-1"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="json">JSON · Most agents</SelectItem><SelectItem value="toml">TOML · Codex</SelectItem><SelectItem value="vscode">JSON · VS Code</SelectItem></SelectContent></Select>
          <Button variant="outline" size="icon" aria-label="Copy MCP configuration" disabled={!executable} onClick={() => void copy(mcpSetupConfig(executable, format), "Configuration")}><Copy className="size-4" /></Button>
          <Button variant="outline" size="icon" aria-label="Export MCP configuration" disabled={!executable || exportConfig.isPending} onClick={() => exportConfig.mutate()}><Download className="size-4" /></Button>
        </div>
        <pre className="max-h-52 overflow-auto rounded-lg border bg-muted/30 p-3 text-xs"><code>{executable ? mcpSetupConfig(executable, format) : "Loading…"}</code></pre>
        <div className="space-y-1 text-xs"><span className="text-muted-foreground">Command</span><div className="flex items-start gap-2"><code className="min-w-0 flex-1 break-all rounded border bg-muted/30 p-2">{executable || "Loading…"}</code><Button variant="ghost" size="icon" aria-label="Copy MCP command path" disabled={!executable} onClick={() => void copy(executable, "Command path")}><Copy className="size-3.5" /></Button></div><p className="text-muted-foreground">Arguments: <code>--mcp</code></p></div>
        {(selected === "codex" || selected === "claude_code") && <div className="space-y-1"><p className="text-xs text-muted-foreground">Optional terminal setup{platform.data === "windows" ? " · PowerShell" : ""}</p><div className="flex items-start gap-2"><code className="min-w-0 flex-1 break-all rounded border bg-muted/30 p-2 text-xs">{executable ? mcpSetupCommand(executable, selected, platform.data) : "Loading…"}</code><Button variant="ghost" size="icon" aria-label="Copy terminal setup command" disabled={!executable} onClick={() => void copy(mcpSetupCommand(executable, selected, platform.data), "Setup command")}><Copy className="size-3.5" /></Button></div></div>}
        {state?.config_path && <p className="break-all text-xs text-muted-foreground">Settings file: {state.config_path}</p>}
        {backup && <p className="break-all text-xs text-muted-foreground">Backup: {backup}</p>}
        {exportConfig.isError && <p role="alert" className="break-words text-sm text-destructive">{String(exportConfig.error)}</p>}
      </div>
    </details>
  </Section>;
}
