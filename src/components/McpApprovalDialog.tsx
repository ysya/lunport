import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useQueryClient } from "@tanstack/react-query";
import { Bot, Server, ShieldAlert } from "lucide-react";

import type { McpPendingRequest } from "@/bindings/McpPendingRequest";
import { mcpStatusKey, useMcpStatus, useResolveMcpRequest } from "@/lib/mcp";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/**
 * Authoritative approval surface for AI-triggered SSH commands. MCP callers
 * cannot dismiss or approve this dialog; only a click in SSHelter resolves it.
 */
export function McpApprovalDialog() {
  const queryClient = useQueryClient();
  const status = useMcpStatus(750);
  const resolve = useResolveMcpRequest();
  const request = status.data?.pending[0] ?? null;

  useEffect(() => {
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    listen<McpPendingRequest>("mcp://approval-requested", () => {
      queryClient.invalidateQueries({ queryKey: mcpStatusKey });
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [queryClient]);

  const decide = (allow: boolean) => {
    if (!request) return;
    resolve.mutate({ requestId: request.id, allow });
  };

  const endpoint = request
    ? [request.user ? `${request.user}@` : "", request.hostname ?? request.alias]
        .join("") + (request.port ? `:${request.port}` : "")
    : "";

  return (
    <Dialog open={request !== null} onOpenChange={() => undefined}>
      <DialogContent
        className="sm:max-w-xl"
        onEscapeKeyDown={(event) => event.preventDefault()}
        onPointerDownOutside={(event) => event.preventDefault()}
      >
        {request && (
          <>
            <DialogHeader>
              <div className="mb-1 flex size-10 items-center justify-center rounded-lg bg-amber-500/12 text-amber-600 dark:text-amber-400">
                <ShieldAlert className="size-5" />
              </div>
              <DialogTitle>Allow this AI SSH command?</DialogTitle>
              <DialogDescription>
                SSHelter will run exactly this command once. The MCP client cannot approve it
                on your behalf.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3">
              <div className="grid grid-cols-[5rem_1fr] gap-x-3 gap-y-1 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                <span className="flex items-center gap-1.5 text-muted-foreground">
                  <Bot className="size-3.5" /> Request
                </span>
                <span>Local MCP client</span>
                <span className="flex items-center gap-1.5 text-muted-foreground">
                  <Server className="size-3.5" /> Host
                </span>
                <span className="font-mono text-xs">{request.alias}</span>
                <span className="text-muted-foreground">Resolved</span>
                <span className="font-mono text-xs">{endpoint}</span>
              </div>
              <div className="space-y-1.5">
                <p className="text-xs font-medium text-muted-foreground">Remote command</p>
                <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-100">
                  {request.command}
                </pre>
              </div>
              <p className="text-xs text-muted-foreground">
                Review the complete command, including pipes, redirects, and nested shell syntax.
              </p>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={resolve.isPending}
                onClick={() => decide(false)}
              >
                Deny
              </Button>
              <Button
                type="button"
                disabled={resolve.isPending}
                onClick={() => decide(true)}
              >
                {resolve.isPending ? "Sending…" : "Allow once"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
