import {
  moveRecordHost,
  updateRecordHost,
  type HostScope,
  type RecordOverview,
} from "@/lib/records";
import { beginEditor, buildEditorPayload, selectHost } from "./editor";
import { scopeKey } from "./group-tree";

export type CollectionAction =
  | { kind: "move"; destination: HostScope }
  | { kind: "tag"; tag: string };

/** Keep the reviewed revisions: a concurrent edit must fail instead of being overwritten. */
export async function applyCollectionAction(
  overview: RecordOverview,
  ids: string[],
  action: CollectionAction,
  accept: (overview: RecordOverview) => unknown,
): Promise<{ completed: string[]; error: string | null }> {
  if (!ids.length || new Set(ids).size !== ids.length)
    throw new Error("Select distinct hosts.");
  const hosts = ids.map((id) => selectHost(overview.hosts, id));
  if (hosts.some((host) => !host || host.group_error))
    throw new Error(
      "A selected host is unavailable or needs review. Refresh before continuing.",
    );
  if (action.kind === "tag" && !action.tag.trim())
    throw new Error("Enter a tag.");
  const completed: string[] = [];
  for (const host of hosts) {
    if (!host) continue;
    try {
      if (action.kind === "move") {
        if (scopeKey(host.scope) !== scopeKey(action.destination))
          accept(
            await moveRecordHost(host.id, host.revision, action.destination),
          );
      } else {
        const payload = buildEditorPayload(beginEditor(host));
        payload.tags = [...new Set([...payload.tags, action.tag.trim()])];
        accept(await updateRecordHost(host.id, host.revision, payload));
      }
      completed.push(host.id);
    } catch {
      return {
        completed,
        error:
          "The operation stopped. Completed hosts were kept; refresh and review the remaining hosts before retrying.",
      };
    }
  }
  return { completed, error: null };
}
