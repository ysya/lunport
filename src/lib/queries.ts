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
import type { TerminalInfo } from "@/bindings/TerminalInfo";
import type { KeyHygiene } from "@/bindings/KeyHygiene";
import type { ChainNode } from "@/bindings/ChainNode";
import type { LintIssue } from "@/bindings/LintIssue";
import type { Suggestion } from "@/bindings/Suggestion";
import type { BackupInfo } from "@/bindings/BackupInfo";

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
  lint: ["config", "lint"] as const,
  keyHygiene: (alias: string) => ["config", "keyHygiene", alias] as const,
  effective: (alias: string) => ["config", "effective", alias] as const,
  jumpChain: (alias: string) => ["config", "jumpChain", alias] as const,
  discover: ["discover", "hosts"] as const,
  backups: ["config", "backups"] as const,
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

/**
 * Host platform (`"macos" | "linux" | "windows"`). Cached indefinitely — it
 * never changes during a session. Used to gate macOS-only fields in the editor.
 */
export function usePlatform() {
  return useQuery<string>({
    queryKey: ["app", "platform"],
    queryFn: () => tauriInvoke<string>("app_platform"),
    staleTime: Infinity,
    gcTime: Infinity,
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
 * The terminal emulators we can launch a connection into. Detected once per
 * session (the installed set doesn't change while the app runs) → cached
 * indefinitely. The toolbar picker reads this; an empty list means "system
 * default only".
 */
export function useTerminals() {
  return useQuery<TerminalInfo[]>({
    queryKey: ["terminals"],
    queryFn: () => tauriInvoke<TerminalInfo[]>("connect_list_terminals"),
    staleTime: Infinity,
  });
}

/**
 * Launch an SSH connection to a host in a terminal. `terminalOverride` is the
 * preferred terminal id (or `null` for the system default / first detected).
 * Backend rejects unknown aliases — surfaced as an error toast.
 */
export function useConnect() {
  return useMutation<
    void,
    unknown,
    { alias: string; terminalOverride?: string | null }
  >({
    mutationFn: ({ alias, terminalOverride }) =>
      tauriInvoke<void>("connect_launch", {
        alias,
        terminalOverride: terminalOverride ?? null,
      }),
    onSuccess: (_data, { alias }) => toast.success(`Launching ${alias}…`),
    onError: (e) => toast.error("Could not connect", { description: errMessage(e) }),
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

/**
 * Key hygiene for a host: its resolved IdentityFile set (with existence checks)
 * plus the `IdentitiesOnly` / explicit-IdentityFile flags. Keyed per-alias and
 * disabled until an alias is provided. Read-only insight panel.
 */
export function useKeyHygiene(alias: string | null | undefined) {
  return useQuery<KeyHygiene>({
    queryKey: queryKeys.keyHygiene(alias ?? ""),
    queryFn: () => tauriInvoke<KeyHygiene>("config_key_hygiene", { alias }),
    enabled: !!alias,
  });
}

/**
 * The resolved (`ssh -G`) effective config for a host as ordered
 * keyword/value tuples. This can be large and shells out, so callers should
 * gate it behind an `enabled` flag (e.g. only when the section is expanded).
 */
export function useEffectiveConfig(
  alias: string | null | undefined,
  options?: Omit<UseQueryOptions<Array<[string, string]>>, "queryKey" | "queryFn">,
) {
  return useQuery<Array<[string, string]>>({
    queryKey: queryKeys.effective(alias ?? ""),
    queryFn: () =>
      tauriInvoke<Array<[string, string]>>("config_effective", { alias }),
    enabled: !!alias,
    ...options,
  });
}

/**
 * The ProxyJump chain for a host: ordered hops from the entry host through each
 * jump. Empty array = no ProxyJump. A node with `defined: false` is referenced
 * but not present in the user's config. Keyed per-alias, disabled until alias.
 */
export function useJumpChain(alias: string | null | undefined) {
  return useQuery<ChainNode[]>({
    queryKey: queryKeys.jumpChain(alias ?? ""),
    queryFn: () => tauriInvoke<ChainNode[]>("config_jump_chain", { alias }),
    enabled: !!alias,
  });
}

/**
 * Global config lint: issues across the whole config (not per-host). Naturally
 * refetched on a config reload because its key lives under `["config"]`, which
 * the reload path invalidates.
 */
export function useLint(
  options?: Omit<UseQueryOptions<LintIssue[]>, "queryKey" | "queryFn">,
) {
  return useQuery<LintIssue[]>({
    queryKey: queryKeys.lint,
    queryFn: () => tauriInvoke<LintIssue[]>("config_lint"),
    staleTime: 30_000,
    ...options,
  });
}

/**
 * Discover candidate hosts from `known_hosts` + Tailscale. Shells out, so it is
 * lazy: callers gate it behind an `enabled` flag (e.g. dialog-open state).
 */
export function useDiscoverHosts(
  options?: Omit<UseQueryOptions<Suggestion[]>, "queryKey" | "queryFn">,
) {
  return useQuery<Suggestion[]>({
    queryKey: queryKeys.discover,
    queryFn: () => tauriInvoke<Suggestion[]>("discover_hosts"),
    enabled: false,
    staleTime: 30_000,
    ...options,
  });
}

/**
 * List config backups. Newest-first is NOT guaranteed by the backend — sort by
 * `timestamp_ms` descending in the UI. Lazy: callers gate behind dialog-open.
 */
export function useBackups(
  options?: Omit<UseQueryOptions<BackupInfo[]>, "queryKey" | "queryFn">,
) {
  return useQuery<BackupInfo[]>({
    queryKey: queryKeys.backups,
    queryFn: () => tauriInvoke<BackupInfo[]>("config_list_backups"),
    enabled: false,
    ...options,
  });
}

/**
 * Restore a backup over its live config file. On success it primes the
 * hosts/files caches from the returned `LoadResult` (mirroring `useLoadConfig`)
 * then invalidates everything under `["config"]` so all derived views refetch.
 */
export function useRestoreBackup() {
  const queryClient = useQueryClient();
  return useMutation<LoadResult, unknown, { backupPath: string }>({
    mutationFn: ({ backupPath }) =>
      tauriInvoke<LoadResult>("config_restore_backup", { backupPath }),
    onSuccess: (data) => {
      queryClient.setQueryData<LoadResult>(queryKeys.hosts, data);
      queryClient.setQueryData<string[]>(queryKeys.files, data.files);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (e) =>
      toast.error("Failed to restore backup", { description: errMessage(e) }),
  });
}
