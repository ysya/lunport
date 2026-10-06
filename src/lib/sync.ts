import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toast } from "sonner";

import type { DuplicateAlias } from "@/bindings/DuplicateAlias";
import type { KeyCandidates } from "@/bindings/KeyCandidates";
import type { KeyChoice } from "@/bindings/KeyChoice";
import type { MigrationFailure } from "@/bindings/MigrationFailure";
import type { MigrationReport } from "@/bindings/MigrationReport";
import type { NewSpaceGroup } from "@/bindings/NewSpaceGroup";
import type { PendingApprovalView } from "@/bindings/PendingApprovalView";
import type { ReviewOutcome } from "@/bindings/ReviewOutcome";
import type { ReviewedVersion } from "@/bindings/ReviewedVersion";
import type { SlotMode } from "@/bindings/SlotMode";
import type { SyncOverview } from "@/bindings/SyncOverview";
import { tauriInvoke } from "@/lib/ipc";
import { queryKeys } from "@/lib/queries";

export const syncOverviewKey = ["sync", "overview"] as const;
export const syncApprovalsKey = ["sync", "approvals"] as const;
/**
 * The shadow list sits UNDER the hosts query's key, not just under ["config"]: the app's own
 * add, save, rename, move and removal invalidate only the hosts (and one host's detail), and
 * those can create or end a duplicate, so the list has to follow the hosts to stay right.
 * Anything that invalidates ["config"] or the hosts refreshes it by prefix.
 */
export const syncDuplicatesKey = [...queryKeys.hosts, "syncDuplicates"] as const;
/** Under ["config"], so a config reload or a restore refreshes it; the wizard that shows it refetches when it opens. */
export const syncUnmovableKey = ["config", "syncUnmovable"] as const;

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Cloudflare's one-click deploy of this repository's relay/ folder — the README buttons' link. */
export const RELAY_DEPLOY_URL = "https://deploy.workers.cloudflare.com/?url=https://github.com/ysya/sshelter/tree/main/relay";

/** The relay README's "Updating your relay" section — linked wherever the app says the relay can be updated. */
export const RELAY_UPDATE_URL = "https://github.com/ysya/sshelter/blob/main/relay/README.md#updating-your-relay";

async function openInBrowser(url: string): Promise<void> {
  try {
    await openUrl(url);
  } catch (e) {
    toast.error("Could not open your browser", { description: errorMessage(e) });
  }
}

/** Open the relay deploy flow in the default browser. */
export function openRelayDeploy(): Promise<void> {
  return openInBrowser(RELAY_DEPLOY_URL);
}

/** Open "Updating your relay" in the default browser. */
export function openRelayUpdateGuide(): Promise<void> {
  return openInBrowser(RELAY_UPDATE_URL);
}

/** After anything that changes the sync account or its spaces: refetch the overview, every config view and the approvals. */
export function refreshSyncViews(queryClient: QueryClient): void {
  void queryClient.invalidateQueries({ queryKey: syncOverviewKey });
  void queryClient.invalidateQueries({ queryKey: ["config"] });
  void queryClient.invalidateQueries({ queryKey: syncApprovalsKey });
}

/** Everything Settings → Sync shows. `sync://status` pushes keep it fresh; the pane also polls while open. */
export function useSyncOverview(refetchInterval: number | false = false) {
  return useQuery<SyncOverview>({
    queryKey: syncOverviewKey,
    queryFn: () => tauriInvoke<SyncOverview>("sync_overview"),
    refetchInterval,
  });
}

/**
 * Non-secret commands that answer with the new overview: prime the cache, then
 * refetch the config views (space files come and go) and the approval list.
 * `refetchOnError`: the command can do part of its work and still answer with an
 * error, so a failure re-reads everything too. `failure` is the toast's title, or
 * picks one from the error's text; null shows no toast, for a caller that reports
 * the failures itself (one summary for a loop of calls).
 */
function useOverviewMutation<TVars>(
  cmd: string,
  failure: string | ((message: string) => string) | null,
  args: (vars: TVars) => Record<string, unknown>,
  refetchOnError = false,
) {
  const queryClient = useQueryClient();
  return useMutation<SyncOverview, unknown, TVars>({
    mutationFn: (vars) => tauriInvoke<SyncOverview>(cmd, args(vars)),
    onSuccess: (overview) => {
      queryClient.setQueryData(syncOverviewKey, overview);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      void queryClient.invalidateQueries({ queryKey: syncApprovalsKey });
    },
    onError: (error) => {
      if (refetchOnError) refreshSyncViews(queryClient);
      if (failure === null) return;
      const message = errorMessage(error);
      toast.error(typeof failure === "string" ? failure : failure(message), { description: message });
    },
  });
}

const noArgs = () => ({});

/**
 * Leave on this computer; `deleteRemote` also deletes the account and every space
 * from the relay (offered on the last computer only). Some errors arrive after
 * this computer already left (the relay part, a sync code change that can never
 * finish, the keychain or the state file), so a failure re-reads the overview as well.
 */
export function useLeaveAccount() {
  return useOverviewMutation<{ deleteRemote: boolean }>("sync_leave_account", leaveFailureTitle, ({ deleteRemote }) => ({ deleteRemote }), true);
}

/**
 * The title of a failed leave. Some errors come after this computer already left:
 * the account was not deleted from the relay (its sync code was changed on another
 * computer), a sync code change can never finish, or the sync code or the saved
 * state could not be cleaned up. All of them start with "left the sync account";
 * the errors of a leave that did not happen start differently ("could not keep…",
 * "the sync account was deleted…", "a sync code change is in progress…").
 */
export function leaveFailureTitle(message: string): string {
  return message.startsWith("left the sync account") ? "Left the sync account on this computer" : "Could not leave the sync account";
}

export function useSetRelayUrl() {
  return useOverviewMutation<{ url: string }>("sync_set_relay_url", "Could not update the relay URL", ({ url }) => ({ url }));
}

/** Ask the relay again what it supports (after the user updated it). */
export function useCheckRelay() {
  return useOverviewMutation<void>("sync_check_relay", "Could not reach the relay", noArgs);
}

/**
 * `relay` null in the overview means the relay was not asked yet — the first sync
 * asks, and so does the first one after the v1 upgrade — never "no freeze". Ask it
 * once when a view shows that; a failure stays quiet (the status line says why
 * the relay can't be reached) and "Check again" stays available.
 */
export function useCheckUnknownRelay(unknown: boolean): void {
  const queryClient = useQueryClient();
  const asked = useRef(false);
  useEffect(() => {
    if (!unknown || asked.current) return;
    asked.current = true;
    void tauriInvoke<SyncOverview>("sync_check_relay").then(
      (overview) => queryClient.setQueryData(syncOverviewKey, overview),
      () => undefined,
    );
  }, [unknown, queryClient]);
}

export function useSetDeviceName() {
  return useOverviewMutation<{ name: string }>("sync_set_device_name", "Could not rename this computer", ({ name }) => ({ name }));
}

/** Removes a device from the list only — it is NOT revocation (changing the sync code is; see the pane copy). */
export function useForgetDevice() {
  return useOverviewMutation<{ deviceId: string }>("sync_forget_device", "Could not forget the computer", ({ deviceId }) => ({ deviceId }));
}

export function useCreateSpace() {
  return useOverviewMutation<{ name: string }>("sync_create_space", "Could not create the space", ({ name }) => ({ name }));
}

export function useRenameSpace() {
  return useOverviewMutation<{ spaceId: string; name: string }>("sync_rename_space", "Could not rename the space", ({ spaceId, name }) => ({
    spaceId,
    name,
  }));
}

/** Deletes the space on every computer and on the relay (confirmed by the caller). */
export function useDeleteSpace() {
  return useOverviewMutation<{ spaceId: string }>("sync_delete_space", "Could not delete the space", ({ spaceId }) => ({ spaceId }));
}

/**
 * `quiet`: no toast per failure; the caller reports them (the chooser turns several spaces on in a row and
 * says what failed once). Nobody else reacts to a failure then, so the views are re-read.
 */
export function useSelectSpace(quiet = false) {
  return useOverviewMutation<{ spaceId: string }>(
    "sync_select_space",
    quiet ? null : "Could not sync the space on this computer",
    ({ spaceId }) => ({ spaceId }),
    quiet,
  );
}

/** Removes only this computer's file of the space (confirmed by the caller). */
export function useUnselectSpace() {
  return useOverviewMutation<{ spaceId: string }>("sync_unselect_space", "Could not remove the space from this computer", ({ spaceId }) => ({
    spaceId,
  }));
}

/** The space's data vanished from the relay: upload this computer's copy again. */
export function useRebuildSpace() {
  return useOverviewMutation<{ spaceId: string }>("sync_rebuild_space", "Could not rebuild the space", ({ spaceId }) => ({ spaceId }));
}

/**
 * Approve exactly the versions the review showed: each `{ alias, digest }` comes
 * from `PendingApprovalView`. A host whose waiting version changed meanwhile is left
 * alone and comes back in `ReviewOutcome.changed`.
 */
export function approveVersions(spaceId: string, approvals: ReviewedVersion[]): Promise<ReviewOutcome> {
  return tauriInvoke<ReviewOutcome>("sync_approve", { spaceId, approvals });
}

/** Reject exactly the versions the review showed; same rules as `approveVersions`. */
export function rejectVersions(spaceId: string, approvals: ReviewedVersion[]): Promise<ReviewOutcome> {
  return tauriInvoke<ReviewOutcome>("sync_reject", { spaceId, approvals });
}

/** A review decision: prime the overview from the outcome, then refetch the config views and the approval list. */
function useReviewMutation(review: typeof approveVersions, failure: string) {
  const queryClient = useQueryClient();
  return useMutation<ReviewOutcome, unknown, { spaceId: string; approvals: ReviewedVersion[] }>({
    mutationFn: ({ spaceId, approvals }) => review(spaceId, approvals),
    onSuccess: (outcome) => {
      queryClient.setQueryData(syncOverviewKey, outcome.overview);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      void queryClient.invalidateQueries({ queryKey: syncApprovalsKey });
    },
    onError: (error) => toast.error(failure, { description: errorMessage(error) }),
  });
}

export function useApproveHosts() {
  return useReviewMutation(approveVersions, "Could not apply the approved hosts");
}

export function useRejectHosts() {
  return useReviewMutation(rejectVersions, "Could not reject the hosts");
}

/** Clears `SyncOverview.notices[index]`. */
export function useDismissNotice() {
  return useOverviewMutation<{ index: number }>("sync_dismiss_notice", "Could not dismiss the notice", ({ index }) => ({ index }));
}

export function useChangeSyncCode() {
  return useOverviewMutation<void>("sync_change_sync_code", "Could not change the sync code", noArgs);
}

/** Only while `SyncOverview.rotation.cancellable`. */
export function useCancelSyncCodeChange() {
  return useOverviewMutation<void>("sync_cancel_sync_code_change", "Could not cancel changing the sync code", noArgs);
}

export function useSyncNow() {
  return useMutation<void, unknown, void>({
    mutationFn: () => tauriInvoke<void>("sync_now"),
    onError: (error) => toast.error("Could not start sync", { description: errorMessage(error) }),
  });
}

/** Hosts held back until the user approves their gated settings (spec §7.4). */
export function usePendingApprovals(enabled: boolean) {
  return useQuery<PendingApprovalView[]>({
    queryKey: syncApprovalsKey,
    queryFn: () => tauriInvoke<PendingApprovalView[]>("sync_pending_approvals"),
    enabled,
  });
}

/** Local hosts that can never move into a space, each with the backend's reason (an `Include`, a value ssh would pass to a shell, …). */
export function useUnmovableHosts(enabled: boolean) {
  return useQuery<MigrationFailure[]>({
    queryKey: syncUnmovableKey,
    queryFn: () => tauriInvoke<MigrationFailure[]>("sync_unmovable_hosts"),
    enabled,
  });
}

/** Move hosts into one space this computer syncs; refusals come back per host in the report. */
export function useMoveHostsToSpace() {
  const queryClient = useQueryClient();
  return useMutation<MigrationReport, unknown, { aliases: string[]; spaceId: string; tagByFile: boolean }>({
    mutationFn: ({ aliases, spaceId, tagByFile }) =>
      tauriInvoke<MigrationReport>("sync_move_hosts_to_space", { aliases, spaceId, tagByFile }),
    onSuccess: () => refreshSyncViews(queryClient),
    onError: (error) => {
      // A refused batch changed nothing, but a failed write reloads the config from disk.
      refreshSyncViews(queryClient);
      toast.error("Could not move hosts", { description: errorMessage(error) });
    },
  });
}

/** "One new space per file": create each space, then move its hosts in. */
export function useMoveFilesToNewSpaces() {
  const queryClient = useQueryClient();
  return useMutation<MigrationReport, unknown, { groups: NewSpaceGroup[]; tagByFile: boolean }>({
    mutationFn: ({ groups, tagByFile }) => tauriInvoke<MigrationReport>("sync_move_files_to_new_spaces", { groups, tagByFile }),
    onSuccess: () => refreshSyncViews(queryClient),
    onError: (error) => {
      refreshSyncViews(queryClient);
      toast.error("Could not move hosts", { description: errorMessage(error) });
    },
  });
}

/** Aliases defined in more than one file where ssh reads a space's copy first: the other copies. */
export function useDuplicateAliases(enabled: boolean) {
  return useQuery<DuplicateAlias[]>({
    queryKey: syncDuplicatesKey,
    queryFn: () => tauriInvoke<DuplicateAlias[]>("sync_duplicate_aliases"),
    enabled,
  });
}

const sameKey = (a: readonly unknown[], b: readonly unknown[]) => a.length === b.length && a.every((part, i) => part === b[i]);

/**
 * After a shadowed copy was renamed or removed: the command answered with the fresh list, whose key lives
 * under the hosts' — refresh every other config view (the hosts, a host's detail, a file's text) but keep
 * the list just set, or it would be refetched at once. Compared by the whole key: a host named like a
 * part of it must still be refreshed.
 */
export function applyResolved(queryClient: QueryClient, remaining: DuplicateAlias[]): void {
  queryClient.setQueryData(syncDuplicatesKey, remaining);
  void queryClient.invalidateQueries({ queryKey: ["config"], predicate: (query) => !sameKey(query.queryKey, syncDuplicatesKey) });
}

/** Rename or remove a shadowed copy of an alias, addressed by file path (never the copy ssh reads first). */
export function useResolveShadowed() {
  const queryClient = useQueryClient();
  return useMutation<DuplicateAlias[], unknown, { alias: string; file: string; action: "rename" | "remove" }>({
    mutationFn: ({ alias, file, action }) => tauriInvoke<DuplicateAlias[]>("sync_resolve_shadowed", { alias, file, action }),
    onSuccess: (remaining) => applyResolved(queryClient, remaining),
    onError: (error) => {
      // After a failed write the backend reloads the config from disk (or drops
      // it), and a write conflict may have brought in outside edits: refetch the
      // host views and the shadow list instead of trusting the cache.
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      toast.error("Could not update the host", { description: errorMessage(error) });
    },
  });
}

/**
 * Keys used by synced hosts that no slot holds yet. Under ["config"], so a reload, a sync apply and the key slot commands
 * refresh it; host edits don't, but the setup dialog's query turns on when it opens and so fetches it again.
 */
export const keyCandidatesKey = ["config", "keyCandidates"] as const;

export function fetchKeyCandidates(): Promise<KeyCandidates> {
  return tauriInvoke<KeyCandidates>("sync_key_candidates");
}

export function useKeyCandidates(enabled: boolean) {
  return useQuery<KeyCandidates>({ queryKey: keyCandidatesKey, queryFn: fetchKeyCandidates, enabled });
}

/** The key slot commands' arguments, in the backend's camelCase. */
export const keyArgs = {
  setup: (v: { choices: KeyChoice[] }) => ({ choices: v.choices }),
  setMode: (v: { slotId: string; mode: SlotMode }) => ({ slotId: v.slotId, mode: v.mode }),
  pick: (v: { slotId: string; path: string }) => ({ slotId: v.slotId, path: v.path }),
  slot: (v: { slotId: string }) => ({ slotId: v.slotId }),
};

/** Create or reuse slots and rewrite the hosts (it can fail after creating a slot, so a failure re-reads everything). */
export function useSetupKeys() {
  return useOverviewMutation("sync_setup_keys", "Could not set up the key", keyArgs.setup, true);
}

export function useKeySetMode() {
  return useOverviewMutation("sync_key_set_mode", "Could not change how the key is shared", keyArgs.setMode);
}

export function useKeyPick() {
  return useOverviewMutation("sync_key_pick", "Could not use that key", keyArgs.pick);
}

export function useKeyUseSynced() {
  return useOverviewMutation("sync_key_use_synced", "Could not use the synced key", keyArgs.slot);
}

export function useKeyDeleteCopy() {
  return useOverviewMutation("sync_key_delete_copy", "Could not delete the copy", keyArgs.slot);
}

/*
 * Sync-code calls deliberately bypass TanStack Query: `useMutation` keeps
 * `variables` and `data` in its cache, so the words would linger in memory long
 * after the dialog closed. Callers hold them in component state only, drop them
 * when the dialog closes, and never put them in a toast or a log.
 */

/** Create a sync account with the default space "Personal"; resolves to the 24-word sync code. */
export function createAccount(deviceName: string): Promise<string> {
  return tauriInvoke<string>("sync_create_account", { deviceName });
}

/** Join with a sync code. Selects no space: the user picks them next. */
export function joinAccount(words: string, deviceName: string): Promise<SyncOverview> {
  return tauriInvoke<SyncOverview>("sync_join_account", { words, deviceName });
}

/** After the sync code changed on another computer: continue with the new code, keeping spaces, file names and unsent edits. */
export function rejoinAccount(words: string): Promise<SyncOverview> {
  return tauriInvoke<SyncOverview>("sync_rejoin_account", { words });
}

export function showWords(): Promise<string> {
  return tauriInvoke<string>("sync_show_words");
}
