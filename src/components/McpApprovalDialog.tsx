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

/** The window's words for each kind of proposal (design 2026-10-26, AI edits): a new host, a changed host, a transport set or removed. */
const EDIT_DESCRIPTION = "Review what would change before saving. Saving does not connect, trust a server key or change AI access. The MCP client cannot approve this request.";
const PROPOSAL_WORDS: Record<string, { title: string; description: string; button: string; hostLine: (request: McpPendingRequest) => string }> = {
  create_host: {
    title: "Add this SSH host?",
    description: "Review these connection settings before saving. A host in an already allowed Group inherits AI access. Saving does not connect or trust a server key. The MCP client cannot approve this request.",
    button: "Add host",
    hostLine: () => "New record · AI access remains off",
  },
  update_host: { title: "Change this SSH host?", description: EDIT_DESCRIPTION, button: "Save changes", hostLine: (request) => `ID: ${request.host_id ?? "Legacy alias"}` },
  set_transport: { title: "Change this host's transport?", description: EDIT_DESCRIPTION, button: "Save transport", hostLine: (request) => `ID: ${request.host_id ?? "Legacy alias"}` },
  remove_transport: { title: "Remove this host's transport?", description: EDIT_DESCRIPTION, button: "Remove transport", hostLine: (request) => `ID: ${request.host_id ?? "Legacy alias"}` },
};

export function McpApprovalCardView({ request, busy, armed, expired = false, onAnswer }: McpApprovalCardViewProps) {
  const deny = useRef<HTMLButtonElement>(null);
  useEffect(() => { deny.current?.focus(); }, [request.id]);
  const endpoint = `${request.user ? `${revealHidden(request.user)}@` : ""}${revealHidden(request.hostname ?? request.alias)}${request.port ? `:${request.port}` : ""}`;
  const proposal = request.host_proposal;
  const words = proposal ? PROPOSAL_WORDS[proposal.kind] ?? PROPOSAL_WORDS.create_host : null;

  return (
    <>
      <DialogHeader>
        <ShieldAlert className="size-5 text-warning" />
        <DialogTitle>{words ? words.title : "Allow this AI SSH command?"}</DialogTitle>
        <DialogDescription>
          {words
            ? words.description
            : "Lunport will run this command once. Review the complete command and resolved target; the MCP client cannot approve it."}
        </DialogDescription>
      </DialogHeader>
      <TaskDialogBody className="break-all">
        <div className="space-y-1 rounded-lg border bg-muted/30 px-3 py-2 text-xs">
          <p>Host: {revealHidden(request.alias)} · {words ? words.hostLine(request) : `ID: ${request.host_id ?? "Legacy alias"}`}</p>
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
          {words ? "Only public connection information is saved. Passwords and private keys are not accepted. Requests expire after 120 seconds; changed settings require fresh approval." : "Review pipes, redirects and nested shell syntax. Requests expire after 120 seconds; changed targets require fresh approval."}
        </p>
        {expired && <p role="alert" className="text-xs text-destructive">This request expired. Ask the client to start a fresh request.</p>}
      </TaskDialogBody>
      <DialogFooter>
        <Button autoFocus ref={deny} variant="outline" disabled={busy} onClick={() => onAnswer(false)}>Deny</Button>
        <Button disabled={busy || !armed || expired} onClick={() => onAnswer(true)}>{busy ? "Sending…" : words ? words.button : "Allow once"}</Button>
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
