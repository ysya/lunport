import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { DuplicateAlias } from "@/bindings/DuplicateAlias";
import type { MigrationReport } from "@/bindings/MigrationReport";
import type { SyncStatus } from "@/bindings/SyncStatus";
import { tauriInvoke } from "@/lib/ipc";

export const syncStatusKey = ["sync", "status"] as const;
export const syncDuplicatesKey = ["sync", "duplicates"] as const;

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** After anything that changes chain membership: refetch status, hosts and duplicates. */
export function refreshSyncViews(queryClient: QueryClient): void {
  void queryClient.invalidateQueries({ queryKey: syncStatusKey });
  void queryClient.invalidateQueries({ queryKey: ["config"] });
  void queryClient.invalidateQueries({ queryKey: syncDuplicatesKey });
}

export function useSyncStatus(refetchInterval: number | false = false) {
  return useQuery<SyncStatus>({
    queryKey: syncStatusKey,
    queryFn: () => tauriInvoke<SyncStatus>("sync_status"),
    refetchInterval,
  });
}

/** Non-secret mutations that return the new status: prime the cache, refresh config views. */
function useStatusMutation<TVars>(cmd: string, failure: string, map: (v: TVars) => Record<string, unknown>) {
  const queryClient = useQueryClient();
  return useMutation<SyncStatus, unknown, TVars>({
    mutationFn: (vars) => tauriInvoke<SyncStatus>(cmd, map(vars)),
    onSuccess: (status) => {
      queryClient.setQueryData(syncStatusKey, status);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (error) => toast.error(failure, { description: errorMessage(error) }),
  });
}

export function useLeaveChain() {
  return useStatusMutation<{ deleteRemote: boolean }>("sync_leave_chain", "Could not leave sync chain", ({ deleteRemote }) => ({ deleteRemote }));
}

export function useSetRelayUrl() {
  return useStatusMutation<{ url: string }>("sync_set_relay_url", "Could not update relay URL", ({ url }) => ({ url }));
}

export function useSetDeviceName() {
  return useStatusMutation<{ name: string }>("sync_set_device_name", "Could not rename this device", ({ name }) => ({ name }));
}

/** Removes a device from the list only — it is NOT revocation (see the pane copy). */
export function useForgetDevice() {
  return useStatusMutation<{ deviceId: string }>("sync_forget_device", "Could not forget device", ({ deviceId }) => ({ deviceId }));
}

export function useSyncNow() {
  return useMutation<void, unknown, void>({
    mutationFn: () => tauriInvoke<void>("sync_now"),
    onError: (error) => toast.error("Could not start sync", { description: errorMessage(error) }),
  });
}

export function useMigrateHosts() {
  const queryClient = useQueryClient();
  return useMutation<MigrationReport, unknown, { aliases: string[]; tagByFile: boolean }>({
    mutationFn: ({ aliases, tagByFile }) => tauriInvoke<MigrationReport>("sync_migrate_hosts", { aliases, tagByFile }),
    onSuccess: () => refreshSyncViews(queryClient),
    onError: (error) => toast.error("Could not move hosts", { description: errorMessage(error) }),
  });
}

export function useDuplicateAliases(enabled: boolean) {
  return useQuery<DuplicateAlias[]>({
    queryKey: syncDuplicatesKey,
    queryFn: () => tauriInvoke<DuplicateAlias[]>("sync_duplicate_aliases"),
    enabled,
  });
}

/** Rename or remove the LOCAL copy of a shadowed alias, addressed by file path (never the synced copy). */
export function useResolveShadowed() {
  const queryClient = useQueryClient();
  return useMutation<DuplicateAlias[], unknown, { alias: string; file: string; action: "rename" | "remove" }>({
    mutationFn: ({ alias, file, action }) => tauriInvoke<DuplicateAlias[]>("sync_resolve_shadowed", { alias, file, action }),
    onSuccess: (remaining) => {
      queryClient.setQueryData(syncDuplicatesKey, remaining);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (error) => toast.error("Could not update the local host", { description: errorMessage(error) }),
  });
}

/*
 * Recovery-phrase calls deliberately bypass TanStack Query: `useMutation` keeps
 * `variables` and `data` in its cache, so the words would linger in memory long
 * after the dialog closed. Callers hold the result in component state only and
 * drop it when the dialog closes.
 */

export function createChain(deviceName: string): Promise<string> {
  return tauriInvoke<string>("sync_create_chain", { deviceName });
}

export function joinChain(words: string, deviceName: string): Promise<SyncStatus> {
  return tauriInvoke<SyncStatus>("sync_join_chain", { words, deviceName });
}

export function showWords(): Promise<string> {
  return tauriInvoke<string>("sync_show_words");
}
