import { useMemo } from "react";

import type { HostSummary } from "@/bindings/HostSummary";
import { labelsFor } from "@/lib/host-display";
import { useDuplicateAliases, useSyncOverview } from "@/lib/sync";
import { ambiguousNames, shadowedCopies, spaceFileLabels, type NameCopy } from "@/lib/sync-sidebar";
import { useSettingsStore } from "@/stores/settings";

/*
 * What the sidebar, the file pickers and the editor pane make of the sync overview. Each one
 * is memoised on the spaces themselves, not on the whole overview: a status push replaces the
 * overview every round, and the spaces keep their identity while their content is unchanged.
 */

/**
 * The files of the spaces this computer syncs, labeled with the space names, in Include order — or
 * undefined while the sync overview has not been read (it is loading, or it failed): then nothing is known
 * about which files are space files. An empty map means no space is synced.
 */
export function useSpaceFiles(): Map<string, string> | undefined {
  const spaces = useSyncOverview().data?.spaces;
  return useMemo(() => (spaces ? spaceFileLabels(spaces) : undefined), [spaces]);
}

const NO_SPACE_FILES: Map<string, string> = new Map();

/** The files of the spaces this computer syncs, labeled with the space names, in Include order (none while they are not known). */
export function useSpaceFileLabels(): Map<string, string> {
  return useSpaceFiles() ?? NO_SPACE_FILES;
}

/**
 * Display names for source files: the automatic labels, the user's own names over them, and the
 * space names over both (a space's name belongs to the account and is renamed under Settings → Sync).
 */
export function useFileLabels(files: string[]): Map<string, string> {
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const spaceLabels = useSpaceFileLabels();
  return useMemo(() => labelsFor(files, { ...fileAliases, ...Object.fromEntries(spaceLabels) }), [files, fileAliases, spaceLabels]);
}

/**
 * The names with several copies, one of them in a space file (`ambiguousNames`): what must not be edited by
 * name. Until the sync overview is known, every name with several copies is on the list: the check fails closed.
 */
export function useAmbiguousNames(hosts: readonly HostSummary[]): Map<string, NameCopy[]> {
  const spaceFiles = useSpaceFiles();
  return useMemo(() => ambiguousNames(hosts, spaceFiles), [hosts, spaceFiles]);
}

/**
 * The copies ssh reads second that the sidebar can fix by file (`shadowedCopies` over the backend's list
 * of duplicates), keyed by `shadowKey`: the row menus offer the fixes for exactly these, and so does the
 * editor pane's explanation of a name with several copies.
 */
export function useShadowedCopies(hosts: readonly HostSummary[]): Map<string, string> {
  const spaceLabels = useSpaceFileLabels();
  const duplicates = useDuplicateAliases(spaceLabels.size > 0);
  return useMemo(() => shadowedCopies(duplicates.data ?? [], hosts, [...spaceLabels.keys()]), [duplicates.data, hosts, spaceLabels]);
}
