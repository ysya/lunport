import { type QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { ApprovalMode } from "@/bindings/ApprovalMode";
import type { HostScope } from "@/lib/records";
import type { McpActivityLog } from "@/bindings/McpActivityLog";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import type { McpStatus } from "@/bindings/McpStatus";
import { tauriInvoke } from "@/lib/ipc";

export const mcpStatusKey = ["mcp", "status"] as const;
export const mcpActivityKey = ["mcp", "activity"] as const;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function useMcpStatus(refetchInterval: number | false = false) {
  return useQuery<McpStatus>({
    queryKey: mcpStatusKey,
    queryFn: () => tauriInvoke<McpStatus>("mcp_status"),
    refetchInterval,
  });
}

/** The AI entries, newest first, as of `revision` of the log. */
export interface McpActivityData {
  revision: number;
  entries: McpAuditEntry[];
  audit_error: string | null;
}

/** The entries after an answer of `mcp_activity`: the same object when nothing changed, so that nothing renders again. */
export function mergeActivity(previous: McpActivityData | undefined, next: McpActivityLog): McpActivityData {
  if (next.entries !== null) return { revision: next.revision, entries: next.entries, audit_error: next.audit_error };
  if (previous && previous.audit_error === next.audit_error) return previous;
  return { revision: next.revision, entries: previous?.entries ?? [], audit_error: next.audit_error };
}

/** The AI entries, asked for only when the log has changed since the revision the cache holds. */
export async function fetchMcpActivity(queryClient: QueryClient): Promise<McpActivityData> {
  const previous = queryClient.getQueryData<McpActivityData>(mcpActivityKey);
  const answer = await tauriInvoke<McpActivityLog>("mcp_activity", { since: previous?.revision ?? null });
  return mergeActivity(previous, answer);
}

export function useMcpActivity(refetchInterval: number | false = 2_000) {
  const queryClient = useQueryClient();
  return useQuery<McpActivityData>({
    queryKey: mcpActivityKey,
    queryFn: () => fetchMcpActivity(queryClient),
    refetchInterval,
  });
}

export function useSetMcpEnabled() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, boolean>({
    mutationFn: (enabled) => tauriInvoke<McpStatus>("mcp_set_enabled", { enabled }),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) =>
      toast.error("Could not update AI access", { description: errorMessage(error) }),
  });
}

export function useSetMcpHostAllowed() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, { alias: string; allowed: boolean }>({
    mutationFn: ({ alias, allowed }) =>
      tauriInvoke<McpStatus>("mcp_set_host_allowed", { alias, allowed }),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) =>
      toast.error("Could not update host access", { description: errorMessage(error) }),
  });
}

export function useSetMcpDatabaseAllowed() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, { id: string; allowed: boolean }>({
    mutationFn: ({ id, allowed }) => tauriInvoke<McpStatus>("mcp_set_database_allowed", { id, allowed }),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) => toast.error("Could not update database AI access", { description: errorMessage(error) }),
  });
}

export function mcpGroupKey(scope: HostScope, id: string): string {
  return scope.kind === "local" ? `local/${id}` : `space/${scope.space_id}/${id}`;
}

export function useSetMcpGroupAllowed() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, { groupId: string; scope: HostScope; generation: string; allowed: boolean }>({
    mutationFn: (args) => tauriInvoke<McpStatus>("mcp_set_group_allowed", args),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) => toast.error("Could not update Group access", { description: errorMessage(error) }),
  });
}

export function useResolveMcpRequest() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { requestId: string; allow: boolean }>({
    mutationFn: ({ requestId, allow }) =>
      tauriInvoke<void>("mcp_resolve_request", { requestId, allow }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: mcpStatusKey }),
    onError: (error) =>
      toast.error("Could not resolve AI request", { description: errorMessage(error) }),
  });
}

export function useSetMcpApprovalMode() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, { approvalMode: ApprovalMode; riskAcknowledged: boolean }>({
    mutationFn: (args) => tauriInvoke<McpStatus>("mcp_set_approval_mode", args),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) => toast.error("Could not update approval mode", { description: errorMessage(error) }),
  });
}

export function useSetMcpTransferLimit() {
  const queryClient = useQueryClient();
  return useMutation<McpStatus, unknown, number>({
    mutationFn: (maxTransferMib) => tauriInvoke<McpStatus>("mcp_set_transfer_limit", { maxTransferMib }),
    onSuccess: (status) => queryClient.setQueryData(mcpStatusKey, status),
    onError: (error) => toast.error("Could not update file transfer limit", { description: errorMessage(error) }),
  });
}
