import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { ApprovalNotice } from "@/bindings/ApprovalNotice";
import type { SyncConflict } from "@/bindings/SyncConflict";
import type { SyncNotice } from "@/bindings/SyncNotice";
import type { SyncOverview } from "@/bindings/SyncOverview";
import { CONNECT_EXPIRED_EVENT, connectExpiredMessage } from "@/lib/agent";
import { listNames } from "@/lib/format";
import { syncApprovalsKey, syncOverviewKey } from "@/lib/sync";
import { approvalMessage, revealHidden } from "@/lib/sync-approvals";
import { useUiStore } from "@/stores/ui";

export interface SyncMessage {
  title: string;
  description: string;
}

/** `sync://conflict`: this computer's unsent edits lost to newer versions from another computer. */
export function conflictMessage(conflicts: readonly SyncConflict[]): SyncMessage | null {
  const named = conflicts.filter((c) => c.aliases.length > 0);
  if (named.length === 0) return null;
  const count = named.reduce((n, c) => n + c.aliases.length, 0);
  return {
    title: count === 1 ? "Sync replaced a local change" : "Sync replaced local changes",
    description: `${named.map((c) => `${listNames(c.aliases)} in ${revealHidden(c.space_name)}`).join("; ")} ${count === 1 ? "was" : "were"} edited on another computer more recently.`,
  };
}

type UpgradedNotice = Extract<SyncNotice, { kind: "upgraded" }>;

/** The one-time explanation after the v1 → v2 upgrade (spec §8), one sentence per point. */
export function upgradeExplanation(notice: UpgradedNotice): string[] {
  const lines = [
    "Your synced hosts moved into a space named “Synced”, unless another computer had already renamed or deleted it. Rename it or add more spaces in Settings → Sync; each computer chooses which spaces it syncs.",
    "Update SSHelter on your other computers too. Until they are updated, they don't see changes made here.",
  ];
  if (notice.kept_file && notice.kept_hosts.length > 0) {
    // Why a host stayed is the backend's business (a setting synced hosts can't
    // have, or a space deleted elsewhere); the wizard shows the reason per host.
    const one = notice.kept_hosts.length === 1;
    lines.push(
      `${listNames(notice.kept_hosts)} could not move into a space, so ${one ? "it stays" : "they stay"} on this computer in ${notice.kept_file}, where ssh keeps reading ${one ? "it" : "them"}.`,
    );
  }
  if (notice.moved_files.length > 0) {
    // v1 owned only hosts.config: the user's own files that the main config included
    // from ~/.ssh/sshelter now sit in ~/.ssh/sshelter-local (these are the new paths).
    const one = notice.moved_files.length === 1;
    lines.push(
      `Your own config ${one ? "file" : "files"} in ~/.ssh/sshelter moved to ${listNames(notice.moved_files)}, where ssh keeps reading ${one ? "it" : "them"}.`,
    );
  }
  return lines;
}

/** The upgrade notice waiting in the overview, with the index `sync_dismiss_notice` needs. */
export function upgradeNotice(notices: readonly SyncNotice[]): { index: number; notice: UpgradedNotice } | null {
  const index = notices.findIndex((n) => n.kind === "upgraded");
  if (index < 0) return null;
  return { index, notice: notices[index] as UpgradedNotice };
}

/**
 * Title and description of a notice, for its toast and its row in Settings → Sync. The names of spaces and
 * computers come from other computers, so hidden characters in them are revealed (`revealHidden`).
 */
export function noticeMessage(notice: SyncNotice): SyncMessage {
  switch (notice.kind) {
    case "upgraded":
      return { title: "Sync was upgraded", description: upgradeExplanation(notice).join(" ") };
    case "space_deleted":
      return {
        title: `“${revealHidden(notice.name)}” was deleted on ${revealHidden(notice.by_device)}`,
        description: "Its file was backed up and removed from this computer.",
      };
    case "rename_blocked":
      return {
        title: `The file of “${revealHidden(notice.name)}” keeps its old name`,
        description: `${notice.file_name} already exists in ~/.ssh/sshelter, so SSHelter did not overwrite it. Move that file away; SSHelter renames the space's file on the next sync.`,
      };
    case "left_account":
      // Not only after leaving: also after a sync code change or a rejoin (spaces the new
      // account does not continue), and when creating or joining moves aside a v1 leftover
      // (`hosts.config`) that an Include still reads — so the copy never says "left".
      return {
        title: "Your synced files are now local files",
        description: `ssh keeps reading ${listNames(notice.kept_files)}, but ${notice.kept_files.length === 1 ? "it no longer syncs" : "they no longer sync"}. To sync these hosts again, use “Move hosts into a space” in a sync account.`,
      };
    case "new_sync_code":
      return {
        title: "The sync code was changed",
        description: "Show the new sync code, save it, and enter it on each of your other computers.",
      };
    case "other_rotation":
      return {
        title: `${listNames(notice.devices.map(revealHidden))} also changed the sync code`,
        description:
          "Use one of the new sync codes on every computer. To use the other one on this computer, leave the sync account and join with it.",
      };
    case "keys_needed":
      return {
        title: "Pick keys for this computer",
        description: `Synced hosts use ${listNames(notice.names.map(revealHidden))}, which stay on your other computers.`,
      };
  }
}

/** Settings, on the Sync category (toast buttons). */
export function openSyncSettings(): void {
  const ui = useUiStore.getState();
  ui.setSettingsCategory("sync");
  ui.setSettingsOpen(true);
}

/**
 * Sync engine → UI. Status pushes refresh every overview reader without polling;
 * applied remote changes refresh the config views (a newly synced host can shadow
 * a local one) and the approval list; conflicts, hosts held for approval and
 * notices surface as toasts, and so does a Connect whose ssh asked its one-shot key
 * channel for the key after the one-minute window (`agent://connect-expired`, key vault spec §11).
 * The backend starts a round itself when the window regains focus, so nothing
 * here asks for one — a second round would double the relay usage.
 * Returns the unsubscribe function.
 */
export function subscribeSyncEvents(queryClient: QueryClient): () => void {
  let disposed = false;
  const unlisten: Array<() => void> = [];
  // Tauri's unlisten answers with a promise (it asks the backend to drop the listener); if that fails there
  // is nothing left to do, so it must not become an unhandled rejection.
  async function release(fn: () => void): Promise<void> {
    try {
      await fn();
    } catch {
      // the listener is gone already
    }
  }
  function on<T>(event: string, handler: (payload: T) => void): void {
    // `listen()` registers the callback before its promise resolves, so an event can still arrive after the
    // unsubscribe ran (React StrictMode mounts, unmounts and mounts again): drop it. A refused `listen()` stays quiet too.
    void listen<T>(event, (e) => {
      if (!disposed) handler(e.payload);
    }).then(
      (fn) => {
        if (disposed) void release(fn);
        else unlisten.push(fn);
      },
      () => undefined,
    );
  }

  on<SyncOverview>("sync://status", (overview) => queryClient.setQueryData(syncOverviewKey, overview));
  on<number>("sync://applied", () => {
    void queryClient.invalidateQueries({ queryKey: ["config"] });
    void queryClient.invalidateQueries({ queryKey: syncApprovalsKey });
  });
  on<SyncConflict[]>("sync://conflict", (conflicts) => {
    const message = conflictMessage(conflicts);
    if (message) toast.warning(message.title, { description: message.description });
    void queryClient.invalidateQueries({ queryKey: ["config"] });
  });
  on<ApprovalNotice[]>("sync://approval", (notices) => {
    void queryClient.invalidateQueries({ queryKey: syncApprovalsKey });
    const message = approvalMessage(notices);
    if (!message) return;
    toast.warning(message.title, {
      description: message.description,
      duration: 15_000,
      action: { label: "Review", onClick: () => useUiStore.getState().setSyncApprovalsOpen(true) },
    });
  });
  on<SyncNotice>("sync://notice", (notice) => {
    // The upgrade and the keys notice have their own dialogs (SyncUpgradeDialog, KeysNeededDialog).
    if (notice.kind === "upgraded" || notice.kind === "keys_needed") return;
    const message = noticeMessage(notice);
    toast.info(message.title, {
      description: message.description,
      action: { label: "Open", onClick: () => openSyncSettings() },
    });
  });

  on<string>(CONNECT_EXPIRED_EVENT, (alias) => {
    const m = connectExpiredMessage(alias);
    toast.warning(m.title, { description: m.description });
  });

  return () => {
    disposed = true;
    unlisten.forEach((u) => void release(u));
  };
}

export function useSyncEvents(): void {
  const queryClient = useQueryClient();
  useEffect(() => subscribeSyncEvents(queryClient), [queryClient]);
}
