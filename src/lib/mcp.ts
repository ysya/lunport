import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

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
