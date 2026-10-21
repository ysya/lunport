import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { ApprovalMode } from "@/bindings/ApprovalMode";
import type { HostScope } from "@/lib/records";
import type { McpStatus } from "@/bindings/McpStatus";
import { tauriInvoke } from "@/lib/ipc";

export const mcpStatusKey = ["mcp", "status"] as const;

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
