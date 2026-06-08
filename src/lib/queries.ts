import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { toast } from "sonner";
import { tauriInvoke } from "@/lib/ipc";
import type { LoadResult } from "@/bindings/LoadResult";
import type { HostDetail } from "@/bindings/HostDetail";
import type { HostFieldChange } from "@/bindings/HostFieldChange";
import type { DriftInfo } from "@/bindings/DriftInfo";

/**
 * Centralized query keys. The hosts list is the canonical cache: both
 * `useLoadConfig` (mutation) and `useHostsQuery` write/read it so the UI has a
 * single source of truth for the loaded host summaries.
 */
export const queryKeys = {
  hosts: ["config", "hosts"] as const,
  host: (alias: string) => ["config", "host", alias] as const,
  files: ["config", "files"] as const,
  drift: ["config", "drift"] as const,
};

/** Normalize a rejected-promise error (Tauri rejects with a string) to a message. */
function errMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * Hosts-query design choice:
 *
 * `useHostsQuery()` is the primary read path — a single `useQuery` over
 * `config_load` returning the full `LoadResult` (files + hosts). This loads the
 * config once and lets the host list read `data.hosts` while the file list reads
 * `data.files`, all from one cache entry keyed by {@link queryKeys.hosts}.
 *
 * `useLoadConfig()` is the imperative escape hatch (mutation) used to (re)load
 * from an explicit path or to force a refresh; on success it primes the same
 * cache entry so reads and the imperative load never diverge.
 */
export function useHostsQuery(
  options?: Omit<UseQueryOptions<LoadResult>, "queryKey" | "queryFn">,
) {
  return useQuery<LoadResult>({
    queryKey: queryKeys.hosts,
    queryFn: () => tauriInvoke<LoadResult>("config_load"),
    ...options,
  });
}

/**
 * Imperative (re)load. Optionally takes a path. On success it primes the
 * hosts-query cache with the full `LoadResult` and refreshes the files cache.
 */
export function useLoadConfig() {
  const queryClient = useQueryClient();
  return useMutation<LoadResult, unknown, string | undefined>({
    mutationFn: (path) =>
      tauriInvoke<LoadResult>("config_load", path ? { path } : undefined),
    onSuccess: (data) => {
      queryClient.setQueryData<LoadResult>(queryKeys.hosts, data);
      queryClient.setQueryData<string[]>(queryKeys.files, data.files);
    },
    onError: (e) => toast.error("Failed to load config", { description: errMessage(e) }),
  });
}

/** Detail for a single host. Disabled until an alias is provided. */
export function useHostDetail(alias: string | null | undefined) {
  return useQuery<HostDetail | null>({
    queryKey: queryKeys.host(alias ?? ""),
    queryFn: () => tauriInvoke<HostDetail | null>("config_get_host", { alias }),
    enabled: !!alias,
  });
}

/** Save a host's field changes. Surfaces backend errors (incl. Conflict) as a toast. */
export function useSaveHost() {
  const queryClient = useQueryClient();
  return useMutation<
    HostDetail | null,
    unknown,
    { alias: string; changes: HostFieldChange[] }
  >({
    mutationFn: ({ alias, changes }) =>
      tauriInvoke<HostDetail | null>("config_save_host", { alias, changes }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to save host", { description: errMessage(e) }),
  });
}

/** Add a new host into `targetFile`. */
export function useAddHost() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    unknown,
    { targetFile: string; alias: string; fields: HostFieldChange[] }
  >({
    mutationFn: ({ targetFile, alias, fields }) =>
      tauriInvoke<void>("config_add_host", { targetFile, alias, fields }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to add host", { description: errMessage(e) }),
  });
}

/** Remove a host by alias. */
export function useRemoveHost() {
  const queryClient = useQueryClient();
  return useMutation<boolean, unknown, { alias: string }>({
    mutationFn: ({ alias }) => tauriInvoke<boolean>("config_remove_host", { alias }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to remove host", { description: errMessage(e) }),
  });
}

/** Set (or clear, with null) a host's group. */
export function useSetGroup() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string; group: string | null }>({
    mutationFn: ({ alias, group }) =>
      tauriInvoke<void>("config_set_group", { alias, group }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to set group", { description: errMessage(e) }),
  });
}

/** Replace a host's tags. */
export function useSetTags() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string; tags: string[] }>({
    mutationFn: ({ alias, tags }) =>
      tauriInvoke<void>("config_set_tags", { alias, tags }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to set tags", { description: errMessage(e) }),
  });
}

/** Toggle whether a single option line is enabled (commented out vs. active). */
export function useSetOptionEnabled() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    unknown,
    { alias: string; keyword: string; enabled: boolean }
  >({
    mutationFn: ({ alias, keyword, enabled }) =>
      tauriInvoke<void>("config_set_option_enabled", { alias, keyword, enabled }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) =>
      toast.error("Failed to toggle option", { description: errMessage(e) }),
  });
}

/** Reorder hosts within a file. */
export function useReorderHosts() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { file: string; order: string[] }>({
    mutationFn: ({ file, order }) =>
      tauriInvoke<void>("config_reorder_hosts", { file, order }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to reorder hosts", { description: errMessage(e) }),
  });
}

/**
 * Drift check: which files changed on disk since load. Manual/polled — disabled
 * by default; opt in with `{ enabled: true }` or `{ refetchInterval }`.
 */
export function useDrift(
  options?: Omit<UseQueryOptions<DriftInfo[]>, "queryKey" | "queryFn">,
) {
  return useQuery<DriftInfo[]>({
    queryKey: queryKeys.drift,
    queryFn: () => tauriInvoke<DriftInfo[]>("config_check_drift"),
    enabled: false,
    ...options,
  });
}
