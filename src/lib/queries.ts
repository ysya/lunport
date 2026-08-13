import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { toast } from "sonner";
import { tauriInvoke } from "@/lib/ipc";
import { useSettingsStore } from "@/stores/settings";
import { applyOrderToHosts } from "@/lib/reorder";
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
import type { KeyInfo } from "@/bindings/KeyInfo";
import type { AgentStatus } from "@/bindings/AgentStatus";
import type { KnownHostEntry } from "@/bindings/KnownHostEntry";
import type { DeployOutcome } from "@/bindings/DeployOutcome";
import type { DeployPreflight } from "@/bindings/DeployPreflight";
import type { HostKeyStatus } from "@/bindings/HostKeyStatus";

/**
 * Centralized query keys. The hosts list is the canonical cache: both
 * `useLoadConfig` (mutation) and `useHostsQuery` write/read it so the UI has a
 * single source of truth for the loaded host summaries.
 */
export const queryKeys = {
  hosts: ["config", "hosts"] as const,
  host: (alias: string) => ["config", "host", alias] as const,
  files: ["config", "files"] as const,
  fileText: (path: string) => ["config", "fileText", path] as const,
  drift: ["config", "drift"] as const,
  lint: ["config", "lint"] as const,
  keyHygiene: (alias: string) => ["config", "keyHygiene", alias] as const,
  effective: (alias: string) => ["config", "effective", alias] as const,
  jumpChain: (alias: string) => ["config", "jumpChain", alias] as const,
  discover: ["discover", "hosts"] as const,
  backups: ["config", "backups"] as const,
  // Both live under ["keys"] so one invalidation refreshes the list AND agent.
  keys: ["keys", "list"] as const,
  agent: ["keys", "agent"] as const,
  knownHosts: ["known_hosts"] as const,
  hostPassword: (alias: string) => ["hostPassword", alias] as const,
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
    // Read the persisted config path at FETCH time (not render time) so a
    // plain invalidation of ["config"] always reloads from the current
    // preference. The key stays stable because this cache entry is also primed
    // imperatively by `useLoadConfig`.
    queryFn: () => {
      const path = useSettingsStore.getState().configPath;
      return tauriInvoke<LoadResult>("config_load", path ? { path } : undefined);
    },
    ...options,
  });
}

/**
 * Imperative (re)load. Optionally takes a path. On success it primes the
 * hosts-query cache with the full `LoadResult` and refreshes the files cache.
 */
export function useLoadConfig() {
  const queryClient = useQueryClient();
  return useMutation<LoadResult, unknown, string | null | undefined>({
    // `undefined` = "use the persisted configPath preference" (toolbar reload),
    // `null` = "explicitly the default ~/.ssh/config" (Settings clearing the
    // path), a string = that exact path (Settings applying a new one).
    mutationFn: (path) => {
      const effective =
        path === undefined ? useSettingsStore.getState().configPath : path;
      return tauriInvoke<LoadResult>(
        "config_load",
        effective ? { path: effective } : undefined,
      );
    },
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

/**
 * Rename a host: replace the `Host` line's pattern tokens losslessly. The first
 * pattern is the host's identity, so on success BOTH the old and new detail
 * keys are invalidated (plus the hosts list, which refreshes the sidebar).
 */
export function useRenameHost() {
  const queryClient = useQueryClient();
  return useMutation<
    HostDetail | null,
    unknown,
    { alias: string; patterns: string[] }
  >({
    mutationFn: ({ alias, patterns }) =>
      tauriInvoke<HostDetail | null>("config_rename_host", { alias, patterns }),
    onSuccess: (_data, { alias, patterns }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      if (patterns[0] && patterns[0] !== alias) {
        queryClient.invalidateQueries({ queryKey: queryKeys.host(patterns[0]) });
      }
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) => toast.error("Failed to rename host", { description: errMessage(e) }),
  });
}

/**
 * Move a host block to another LOADED config file (verbatim, appended at the
 * end). The host's alias is unchanged, so callers keep the selection as-is;
 * both the list and the host's detail (its `source_file`) are invalidated.
 */
export function useMoveHost() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string; targetFile: string }>({
    mutationFn: ({ alias, targetFile }) =>
      tauriInvoke<void>("config_move_host", { alias, targetFile }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
      // Raw-file viewers of either file are stale now.
      queryClient.invalidateQueries({ queryKey: ["config", "fileText"] });
    },
    onError: (e) => toast.error("Failed to move host", { description: errMessage(e) }),
  });
}

/**
 * Duplicate a host within its file: a verbatim copy appended at the end with
 * only the `Host` line's patterns replaced by `newAlias`. Callers select the
 * new alias on success.
 */
export function useDuplicateHost() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string; newAlias: string }>({
    mutationFn: ({ alias, newAlias }) =>
      tauriInvoke<void>("config_duplicate_host", { alias, newAlias }),
    onSuccess: (_data, { newAlias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(newAlias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
      queryClient.invalidateQueries({ queryKey: ["config", "fileText"] });
    },
    onError: (e) =>
      toast.error("Failed to duplicate host", { description: errMessage(e) }),
  });
}

/**
 * Raw text of ONE loaded managed config file (read-only viewer). Disabled until
 * a path is provided — mount the consumer only while its dialog is open so each
 * open refetches the current on-disk text.
 */
export function useFileText(path: string | null) {
  return useQuery<string>({
    queryKey: queryKeys.fileText(path ?? ""),
    queryFn: () => tauriInvoke<string>("config_read_file", { path }),
    enabled: !!path,
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

/**
 * Toggle whether a single option line is enabled (commented out vs. active).
 * The line is addressed by `index` — its position in `HostDetail.options`
 * (document order), which uniquely identifies it even when the block holds an
 * enabled and a disabled line with the same keyword. `keyword` is a backend
 * sanity check: a mismatch (stale view) errors instead of hitting a wrong line.
 */
export function useSetOptionEnabled() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    unknown,
    { alias: string; keyword: string; index: number; enabled: boolean }
  >({
    mutationFn: ({ alias, keyword, index, enabled }) =>
      tauriInvoke<void>("config_set_option_enabled", {
        alias,
        keyword,
        index,
        enabled,
      }),
    onSuccess: (_data, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.host(alias) });
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
    onError: (e) =>
      toast.error("Failed to toggle option", { description: errMessage(e) }),
  });
}

/**
 * Reorder hosts within a file. `order` must be the COMPLETE alias list of every
 * host block in `file` (including wildcard-only blocks) in the desired order —
 * the backend pushes any unnamed block AFTER all named ones. Build it with
 * `buildNewOrder()` from `@/lib/reorder`.
 *
 * Optimistic: the hosts cache is reordered immediately (`onMutate`), restored
 * from a snapshot on error, and re-validated against the backend either way.
 */
export function useReorderHosts() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    unknown,
    { file: string; order: string[] },
    { previous: LoadResult | undefined }
  >({
    mutationFn: ({ file, order }) =>
      tauriInvoke<void>("config_reorder_hosts", { file, order }),
    onMutate: async ({ file, order }) => {
      await queryClient.cancelQueries({ queryKey: queryKeys.hosts });
      const previous = queryClient.getQueryData<LoadResult>(queryKeys.hosts);
      if (previous) {
        queryClient.setQueryData<LoadResult>(queryKeys.hosts, {
          ...previous,
          hosts: applyOrderToHosts(previous.hosts, file, order),
        });
      }
      return { previous };
    },
    onError: (e, _vars, context) => {
      // Roll back the optimistic reorder, then refetch the truth from disk.
      if (context?.previous) {
        queryClient.setQueryData<LoadResult>(queryKeys.hosts, context.previous);
      }
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
      toast.error("Failed to reorder hosts", { description: errMessage(e) });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    },
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
    { alias: string; terminalOverride?: string | null; newTab?: boolean | null }
  >({
    mutationFn: ({ alias, terminalOverride, newTab }) =>
      tauriInvoke<void>("connect_launch", {
        alias,
        terminalOverride: terminalOverride ?? null,
        // Only honored by terminals with `supports_new_tab` — callers gate via
        // `effectiveNewTab()` so this is false for unsupported terminals.
        newTab: newTab ?? null,
      }),
    onSuccess: (_data, { alias }) => {
      // Feeds the ⌘K "Recent" group; read via getState so this stays a plain fn.
      useSettingsStore.getState().recordConnection(alias);
      toast.success(`Launching ${alias}…`);
    },
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
 * Keypairs found in ~/.ssh (with fingerprints + agent membership). Shells out
 * to ssh-keygen/ssh-add, so it is lazy: callers gate behind dialog-open state.
 */
export function useKeys(
  options?: Omit<UseQueryOptions<KeyInfo[]>, "queryKey" | "queryFn">,
) {
  return useQuery<KeyInfo[]>({
    queryKey: queryKeys.keys,
    queryFn: () => tauriInvoke<KeyInfo[]>("keys_list"),
    enabled: false,
    ...options,
  });
}

/**
 * Entries in ~/.ssh/known_hosts (line index + first field + key type/fingerprint).
 * Lazy: callers gate behind dialog-open state.
 */
export function useKnownHosts(
  options?: Omit<UseQueryOptions<KnownHostEntry[]>, "queryKey" | "queryFn">,
) {
  return useQuery<KnownHostEntry[]>({
    queryKey: queryKeys.knownHosts,
    queryFn: () => tauriInvoke<KnownHostEntry[]>("known_hosts_list"),
    enabled: false,
    ...options,
  });
}

/**
 * Remove known_hosts lines by index, guarded by the expected first fields (the backend rejects a
 * stale view with a Conflict). Invalidates the list on success AND on error — a Conflict means
 * the file changed under us, so the dialog must re-show the truth either way.
 */
export function useRemoveKnownHosts() {
  const queryClient = useQueryClient();
  return useMutation<
    number,
    unknown,
    { lineIndices: number[]; expectedHosts: string[] }
  >({
    mutationFn: ({ lineIndices, expectedHosts }) =>
      tauriInvoke<number>("known_hosts_remove", { lineIndices, expectedHosts }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.knownHosts });
    },
    onError: (e) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.knownHosts });
      toast.error("Failed to remove host key", { description: errMessage(e) });
    },
  });
}

/** ssh-agent status (running + loaded key count). Lazy, like {@link useKeys}. */
export function useAgentStatus(
  options?: Omit<UseQueryOptions<AgentStatus>, "queryKey" | "queryFn">,
) {
  return useQuery<AgentStatus>({
    queryKey: queryKeys.agent,
    queryFn: () => tauriInvoke<AgentStatus>("keys_agent_status"),
    enabled: false,
    ...options,
  });
}

/**
 * Generate a new passphrase-LESS ed25519 keypair `~/.ssh/<name>` (the UI carries
 * the warning). Invalidates ["keys"] so the list refreshes with the new pair.
 */
export function useGenerateKey() {
  const queryClient = useQueryClient();
  return useMutation<KeyInfo, unknown, { name: string; comment: string | null }>({
    mutationFn: ({ name, comment }) =>
      tauriInvoke<KeyInfo>("keys_generate", { name, comment }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keys"] });
    },
    onError: (e) =>
      toast.error("Failed to generate key", { description: errMessage(e) }),
  });
}

/**
 * Launch INTERACTIVE `ssh-keygen` in the user's terminal (passphrase-protected
 * flow). The list is invalidated optimistically — the key appears once the user
 * finishes the prompts and reopens/refetches.
 */
export function useGenerateKeyInTerminal() {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    unknown,
    { name: string; comment: string | null; terminalOverride?: string | null }
  >({
    mutationFn: ({ name, comment, terminalOverride }) =>
      tauriInvoke<void>("keys_generate_in_terminal", {
        name,
        comment,
        terminalOverride: terminalOverride ?? null,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keys"] });
    },
    onError: (e) =>
      toast.error("Failed to open terminal", { description: errMessage(e) }),
  });
}

/** Launch `ssh-copy-id -i <pub> <alias>` in the user's terminal (interactive password). */
export function useDeployKey() {
  return useMutation<
    void,
    unknown,
    { alias: string; publicPath: string; terminalOverride?: string | null }
  >({
    mutationFn: ({ alias, publicPath, terminalOverride }) =>
      tauriInvoke<void>("keys_deploy", {
        alias,
        publicPath,
        terminalOverride: terminalOverride ?? null,
      }),
    onError: (e) =>
      toast.error("Failed to deploy key", { description: errMessage(e) }),
  });
}

/** Whether the keychain holds a password for this host (does not fetch it). */
export function useHasHostPassword(alias: string | null) {
  return useQuery<boolean>({
    queryKey: alias ? queryKeys.hostPassword(alias) : ["hostPassword", "none"],
    queryFn: () => tauriInvoke<boolean>("secrets_has", { alias }),
    enabled: !!alias,
  });
}

/**
 * Fetch this host's password from the keychain. Deliberately a mutation, not a
 * query — the password is read only when the user explicitly asks to see it,
 * never cached as part of rendering.
 */
export function useRevealHostPassword() {
  return useMutation<string | null, unknown, { alias: string }>({
    mutationFn: ({ alias }) =>
      tauriInvoke<string | null>("secrets_get", { alias }),
    onError: (e) =>
      toast.error("Failed to read password", { description: errMessage(e) }),
  });
}

export function useSetHostPassword() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string; password: string }>({
    mutationFn: ({ alias, password }) =>
      tauriInvoke<void>("secrets_set", { alias, password }),
    onSuccess: (_d, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.hostPassword(alias) });
    },
    onError: (e) =>
      toast.error("Failed to save password", { description: errMessage(e) }),
  });
}

export function useDeleteHostPassword() {
  const queryClient = useQueryClient();
  return useMutation<void, unknown, { alias: string }>({
    mutationFn: ({ alias }) => tauriInvoke<void>("secrets_delete", { alias }),
    onSuccess: (_d, { alias }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.hostPassword(alias) });
    },
    onError: (e) =>
      toast.error("Failed to delete password", { description: errMessage(e) }),
  });
}

/** Verify the host key before deploying so ssh can run with StrictHostKeyChecking=yes. */
export function usePrecheckHostKey() {
  return useMutation<HostKeyStatus, unknown, { alias: string }>({
    mutationFn: ({ alias }) =>
      tauriInvoke<HostKeyStatus>("deploy_precheck_host_key", { alias }),
    onError: (e) =>
      toast.error("Failed to check host key", { description: errMessage(e) }),
  });
}

/**
 * After the user confirms the fingerprint, append the host key to known_hosts.
 * Only the fingerprint crosses the IPC boundary — the backend re-scans and
 * writes its own key line, so the frontend stays out of the trust path.
 */
export function useTrustHostKey() {
  return useMutation<void, unknown, { alias: string; fingerprint: string }>({
    mutationFn: ({ alias, fingerprint }) =>
      tauriInvoke<void>("deploy_trust_host_key", { alias, fingerprint }),
    onError: (e) =>
      toast.error("Failed to trust host key", { description: errMessage(e) }),
  });
}

/** Deploy the public key directly from the app (no terminal involved). */
export function useDeployKeyDirect() {
  return useMutation<
    DeployOutcome,
    unknown,
    { alias: string; publicPath: string; password: string; remember: boolean }
  >({
    mutationFn: ({ alias, publicPath, password, remember }) =>
      tauriInvoke<DeployOutcome>("deploy_key", {
        alias,
        publicPath,
        password,
        remember,
      }),
    onError: (e) =>
      toast.error("Deploy failed", { description: errMessage(e) }),
  });
}

/**
 * Advisory environment probe for the deploy dialog: old OpenSSH, config that
 * blocks password auth, missing credential store. Warnings only — the hard
 * gates live in the deploy_key command itself.
 */
export function useDeployPreflight() {
  return useMutation<DeployPreflight, unknown, { alias: string }>({
    mutationFn: ({ alias }) =>
      tauriInvoke<DeployPreflight>("deploy_preflight", { alias }),
    onError: (e) =>
      toast.error("Failed to check deploy prerequisites", {
        description: errMessage(e),
      }),
  });
}

/**
 * Read a `.pub` file's contents (public material only — the backend enforces
 * the `.pub`-inside-~/.ssh rule). Imperative (mutation) for copy-to-clipboard.
 */
export function useReadPublicKey() {
  return useMutation<string, unknown, { path: string }>({
    mutationFn: ({ path }) => tauriInvoke<string>("keys_read_public", { path }),
    onError: (e) =>
      toast.error("Failed to read public key", { description: errMessage(e) }),
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
