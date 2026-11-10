import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { toast } from "sonner";
import type { McpMigration } from "@/bindings/McpMigration";
import type { McpMigrationFailure } from "@/bindings/McpMigrationFailure";
import type { SetupClient } from "@/bindings/SetupClient";
import { tauriInvoke } from "@/lib/ipc";
import { mcpSetupClients } from "@/lib/mcp-setup";
import { useUiStore } from "@/stores/ui";
import { Button } from "@/components/ui/button";

/** Names in a sentence: "A", "A and B", "A, B and C". */
function listed(names: string[]): string {
  return names.length < 2 ? names.join("") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

function clientName(client: SetupClient): string {
  return mcpSetupClients.find(item => item.id === client)?.name ?? client;
}

/**
 * What the move to the new program did to the user's AI tools, shown after every upgrade until the user dismisses it
 * (`McpMigrationToast`). Lunport updates the settings it wrote itself (`updated`), which its sessions already running ignore until they
 * restart, and names what it could not update, with why (`failed`): a settings file it does not change, which is set up by hand, one
 * it could not read or write, or one that starts an earlier Lunport elsewhere, which it checks again on its next start; or, with no
 * client named, why it could not look at any. Cursor and VS Code installed theirs from a link, and exported configurations are the
 * user's files: those still start the earlier program until Lunport is added again.
 */
export function McpMigrationNotice({ updated = [], failed = [], onDismiss, onOpenSettings }: {
  updated?: SetupClient[];
  failed?: McpMigrationFailure[];
  /** Closes the notice; without it there is no Dismiss button. */
  onDismiss?: () => void;
  /** Opens Settings → AI access; without it there is no button for it. */
  onOpenSettings?: () => void;
}) {
  const names = updated.map(clientName);
  const unchecked = failed.filter(item => item.client === null);
  const clients = failed.flatMap(item => item.client === null ? [] : [{ client: item.client, reason: item.reason }]);
  const title = clients.length > 0 ? "Some AI tools still start the earlier program"
    : unchecked.length > 0 ? "Lunport could not check your AI tools"
    : "Add Lunport to Cursor and VS Code again";
  return <div role="note" className="relative w-[var(--width)] space-y-1.5 rounded-[var(--radius)] border bg-popover p-4 text-xs text-muted-foreground shadow-lg">
    {onDismiss && <Button variant="ghost" size="icon-xs" aria-label="Dismiss" className="absolute top-2 right-2" onClick={onDismiss}><X /></Button>}
    <p className="pr-6 text-sm font-medium text-foreground">{title}</p>
    {names.length > 0 && <p>Lunport updated {listed(names)} to start the new program. Restart {names.length === 1 ? "it" : "them"}: a session that is already running keeps the earlier program until it restarts.</p>}
    {unchecked.map((item, index) => <p key={index} className="break-words">{item.reason}</p>)}
    {clients.length > 0 && <>
      <p>Lunport could not update these:</p>
      <ul className="list-disc space-y-1 pl-4">
        {clients.map(item => <li key={item.client} className="break-words"><span className="font-medium text-foreground">{clientName(item.client)}:</span> {item.reason}</li>)}
      </ul>
    </>}
    {failed.length > 0 && <p>Lunport checks them again the next time it starts.</p>}
    <p>Cursor and VS Code keep the setup they installed from a link, which still starts the earlier program. In Settings → AI access, choose Cursor or VS Code and add Lunport again.</p>
    <p>Export or copy MCP configurations you made earlier again, too.</p>
    {onOpenSettings && <div className="pt-1"><Button variant="outline" size="sm" onClick={onOpenSettings}>Open AI access</Button></div>}
  </div>;
}

export const mcpMigrationKey = ["app", "identity-migration", "mcp-settings"] as const;

const MCP_NOTICE = "identity-migration-mcp-settings";

/** What was failing in a notice, by client (`null`: the whole attempt): what a dismissal remembers. */
type Failing = McpMigrationFailure["client"][];

/**
 * Whether the notice for `moved` is to be shown in a window where the user dismissed it having seen `dismissed` fail (`null`: not
 * dismissed here): only something that newly fails brings it back, as across starts (`identity_migration_mcp_settings`).
 */
export function shouldShowMcpNotice(moved: McpMigration | null | undefined, dismissed: Failing | null): moved is McpMigration {
  if (!moved) return false;
  return dismissed === null || moved.failed.some(item => !dismissed.includes(item.client));
}

/** Settings → AI access, where the user adds Lunport to an AI tool again or sets it up by hand. */
function openAiAccess() {
  const ui = useUiStore.getState();
  ui.setSettingsCategory("ai");
  ui.setSettingsOpen(true);
}

/**
 * Shows the notice for `moved` as a toast (`show`: the toaster's) that stays until the user dismisses it; `onDismiss` then hears, once,
 * what was failing in it. The close button and a swipe or flick both dismiss it: the toaster calls the toast's own `onDismiss` for
 * either, the button's included once the toast is removed. Opening AI access leaves it open, so that what it names stays in view.
 */
export function showMcpMigrationNotice(moved: McpMigration, onDismiss: (seen: Failing) => void, show: typeof toast.custom = toast.custom) {
  let dismissed = false;
  const dismissedOnce = () => {
    if (dismissed) return;
    dismissed = true;
    onDismiss(moved.failed.map(item => item.client));
  };
  const close = (id: string | number) => {
    dismissedOnce();
    toast.dismiss(id);
  };
  show(id => <McpMigrationNotice updated={moved.updated} failed={moved.failed} onDismiss={() => close(id)} onOpenSettings={openAiAccess} />, { id: MCP_NOTICE, duration: Infinity, onDismiss: dismissedOnce });
}

/**
 * The notice in one window. A dismissal is recorded for later starts (`remember`, `identity_migration_dismiss_mcp_settings`) and kept
 * here as well, so that the window coming back does not bring the notice back unless something newly fails, even when the dismissal
 * could not be recorded.
 */
export function mcpNoticeHost(remember: (seen: Failing) => Promise<unknown>, show: typeof toast.custom = toast.custom) {
  let dismissed: Failing | null = null;
  return {
    update(moved: McpMigration | null | undefined) {
      if (!shouldShowMcpNotice(moved, dismissed)) return;
      showMcpMigrationNotice(moved, seen => {
        dismissed = seen;
        remember(seen).catch(error => console.warn("[identity-migration] the notice's dismissal was not recorded:", error));
      }, show);
    },
  };
}

/**
 * The notice of what the move did to the AI tools' MCP settings (`identity_migration_mcp_settings`): after every upgrade until the user
 * dismisses it, then only when something newly fails. Asked again whenever the window comes back, like the migration's status: another
 * start may have moved, or failed to move, what this one could not.
 */
export function McpMigrationToast() {
  const moved = useQuery({ queryKey: mcpMigrationKey, queryFn: () => tauriInvoke<McpMigration | null>("identity_migration_mcp_settings"), staleTime: Infinity, retry: false, refetchOnWindowFocus: "always" });
  const [host] = useState(() => mcpNoticeHost(seen => tauriInvoke<void>("identity_migration_dismiss_mcp_settings", { failed: seen })));
  useEffect(() => host.update(moved.data), [host, moved.data]);
  return null;
}
