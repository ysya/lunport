import { TaskDialogContent as DialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { useEffect, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";

import type { McpPendingRequest } from "@/bindings/McpPendingRequest";
import { mcpStatusKey, useMcpStatus, useResolveMcpRequest } from "@/lib/mcp";
import { armAfterDelay } from "@/lib/hostkey";
import { revealHidden } from "@/lib/sync-approvals";
import { McpAttribution } from "./McpAttribution";
import { Button } from "@/components/ui/button";
import {
  Dialog,  DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";

export type McpApprovalCardViewProps = {
  request: McpPendingRequest;
  busy: boolean;
  armed: boolean;
  expired?: boolean;
  onAnswer: (allow: boolean) => void;
};

export function McpApprovalCardView({ request, busy, armed, expired = false, onAnswer }: McpApprovalCardViewProps) {
  const deny = useRef<HTMLButtonElement>(null);
  useEffect(() => { deny.current?.focus(); }, [request.id]);
  const endpoint = `${request.user ? `${revealHidden(request.user)}@` : ""}${revealHidden(request.hostname ?? request.alias)}${request.port ? `:${request.port}` : ""}`;
  const proposal = request.host_proposal;

  return (
    <>
      <DialogHeader>
        <ShieldAlert className="size-5 text-amber-600 dark:text-amber-400" />
        <DialogTitle>{proposal ? "Add this SSH host?" : "Allow this AI SSH command?"}</DialogTitle>
        <DialogDescription>
          {proposal
            ? "Review these connection settings before saving. This does not connect, trust a server key or grant AI access. The MCP client cannot approve this request."
            : "Lunport will run this command once. Review the complete command and resolved target; the MCP client cannot approve it."}
        </DialogDescription>
      </DialogHeader>
      <TaskDialogBody className="break-all">
        <div className="space-y-1 rounded-lg border bg-muted/30 px-3 py-2 text-xs">
          <p>Host: {revealHidden(request.alias)} · {proposal ? "New record · AI access remains off" : `ID: ${request.host_id ?? "Legacy alias"}`}</p>
          <p>Resolved: {endpoint}</p>
          {!proposal && <p>Route: {request.route.length ? request.route.map(revealHidden).join(" → ") : "Direct"}</p>}
          <McpAttribution requestedBy={request.requested_by} requesterId={request.requester_id} clientInfo={request.client_info} />
        </div>
        {proposal ? (
          <dl className="space-y-2 rounded-lg border p-3 text-xs">
            {proposal.settings.map(([label, value]) => (
              <div key={label} className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-3">
                <dt className="text-muted-foreground">{revealHidden(label)}</dt>
                <dd className="min-w-0 break-words">{revealHidden(value || "None")}</dd>
              </div>
            ))}
          </dl>
        ) : <div className="space-y-1.5">
          <p className="text-xs font-medium text-muted-foreground">Remote command</p>
          <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground">
            {request.command}
          </pre>
        </div>}
        <p className="text-xs text-muted-foreground">
          {proposal ? "Only public connection information is saved. Passwords and private keys are not accepted. Requests expire after 120 seconds; changed settings require fresh approval." : "Review pipes, redirects and nested shell syntax. Requests expire after 120 seconds; changed targets require fresh approval."}
        </p>
        {expired && <p role="alert" className="text-xs text-destructive">This request expired. Ask the client to start a fresh request.</p>}
      </TaskDialogBody>
      <DialogFooter>
        <Button autoFocus ref={deny} variant="outline" disabled={busy} onClick={() => onAnswer(false)}>Deny</Button>
        <Button disabled={busy || !armed || expired} onClick={() => onAnswer(true)}>{busy ? "Sending…" : proposal ? "Add host" : "Allow once"}</Button>
      </DialogFooter>
    </>
  );
}

/** Mounted with request.id as key: candidate and focus never carry across requests. */
export function McpApprovalCard({ request, busy, onAnswer }: {
  request: McpPendingRequest;
  busy: boolean;
  onAnswer: (requestId: string, allow: boolean) => void;
}) {
  const [reviewed] = useState(request);
  const [armed, setArmed] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, []);
  return (
    <McpApprovalCardView
      request={reviewed}
      busy={busy}
      armed={armed}
      expired={now >= reviewed.requested_at_ms + 120000}
      onAnswer={allow => {
        if (!allow || (armed && Date.now() < reviewed.requested_at_ms + 120000)) onAnswer(reviewed.id, allow);
      }}
    />
  );
}

/** Native app is the only authority; status polling selects a new keyed immutable review. */
export function McpApprovalDialog() {
  const queryClient = useQueryClient();
  const status = useMcpStatus(750);
  const resolve = useResolveMcpRequest();
  const request = status.data?.pending[0] ?? null;
  useEffect(() => {
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    void listen<McpPendingRequest>("mcp://approval-requested", () => {
      void queryClient.invalidateQueries({ queryKey: mcpStatusKey });
    }).then(fn => {
      if (disposed) fn();
      else unlisten = fn;
    }).catch(() => { /* Status polling also recovers missed events. */ });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [queryClient]);

  return (
    <Dialog open={request !== null} onOpenChange={() => undefined}>
      <DialogContent
        key={request?.id ?? "none"}
        showCloseButton={false}
        className="max-h-[calc(100dvh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] sm:max-w-xl"
        onEscapeKeyDown={event => event.preventDefault()}
        onPointerDownOutside={event => event.preventDefault()}
      >
        {request && (
          <McpApprovalCard
            key={request.id}
            request={request}
            busy={resolve.isPending && resolve.variables?.requestId === request.id}
            onAnswer={(requestId, allow) => resolve.mutate({ requestId, allow })}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
