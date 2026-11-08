import { useMutation, useQuery, useQueryClient, type UseQueryOptions } from "@tanstack/react-query";
import { toast } from "sonner";

import type { KnownHostEntry } from "@/bindings/KnownHostEntry";
import type { TerminalInfo } from "@/bindings/TerminalInfo";
import { tauriInvoke } from "@/lib/ipc";
import { errorMessage } from "@/lib/utils";

export const queryKeys = {
  knownHosts: ["knownHosts"] as const,
};

export function useIsDevelopment() {
  return useQuery<boolean>({
    queryKey: ["app", "isDevelopment"],
    queryFn: () => tauriInvoke<boolean>("app_is_development"),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });
}

export function usePlatform() {
  return useQuery<string>({
    queryKey: ["app", "platform"],
    queryFn: () => tauriInvoke<string>("app_platform"),
    staleTime: Infinity,
    gcTime: Infinity,
  });
}

/**
 * The current user's home directory, the one the backend's `~/.ssh` is in (Tauri resolves both with its compiled
 * profile). Cached indefinitely. Key paths are written as `~/.ssh/…` only when they are inside its `.ssh` directory
 * (`toTildeSshPath`); until it is known, or if it can't be read, they are written as given.
 */
export function useHomeDir() {
  return useQuery<string>({
    queryKey: ["app", "homeDir"],
    queryFn: () => tauriInvoke<string>("app_home_dir"),
    staleTime: Infinity,
    gcTime: Infinity,
  });
}

/** The external terminals this computer has, for the Connections settings and the connection menu. */
export function useTerminals() {
  return useQuery<TerminalInfo[]>({
    queryKey: ["terminals"],
    queryFn: () => tauriInvoke<TerminalInfo[]>("connect_list_terminals"),
    staleTime: Infinity,
  });
}

export function useKnownHosts(options?: Omit<UseQueryOptions<KnownHostEntry[]>, "queryKey" | "queryFn">) {
  return useQuery<KnownHostEntry[]>({
    queryKey: queryKeys.knownHosts,
    queryFn: () => tauriInvoke<KnownHostEntry[]>("known_hosts_list"),
    enabled: false,
    ...options,
  });
}

/**
 * Remove known_hosts lines by index, guarded by the expected first fields (the backend rejects a
 * stale view with a Conflict). Invalidates the list on success AND on error: a Conflict means
 * the file changed under us, so the dialog must re-show the truth either way.
 */
export function useRemoveKnownHosts() {
  const queryClient = useQueryClient();
  return useMutation<number, unknown, { lineIndices: number[]; expectedHosts: string[]; expectedLineHashes: string[] }>({
    mutationFn: ({ lineIndices, expectedHosts, expectedLineHashes }) =>
      tauriInvoke<number>("known_hosts_remove", { lineIndices, expectedHosts, expectedLineHashes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.knownHosts });
    },
    onError: (e) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.knownHosts });
      toast.error("Failed to remove host key", { description: errorMessage(e) });
    },
  });
}
