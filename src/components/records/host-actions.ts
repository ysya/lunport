import {
  deleteRecordHost,
  type RecordHostView,
  type RecordOverview,
} from "@/lib/records";
import { selectHost } from "./editor";
import { scopeKey } from "./group-tree";

export function reviewedHostIsCurrent(
  reviewed: RecordHostView,
  overview: RecordOverview,
): boolean {
  const current = selectHost(overview.hosts, reviewed.id);
  return (
    !!current &&
    scopeKey(current.scope) === scopeKey(reviewed.scope) &&
    current.revision.version === reviewed.revision.version &&
    current.revision.updated_at_ms === reviewed.revision.updated_at_ms &&
    current.revision.device_id === reviewed.revision.device_id
  );
}

export async function deleteReviewedHost(
  reviewed: RecordHostView,
  overview: RecordOverview,
  accept: (next: RecordOverview) => unknown,
) {
  if (!reviewedHostIsCurrent(reviewed, overview))
    throw new Error("This host changed. Reopen the menu and review it again.");
  accept(await deleteRecordHost(reviewed.id, reviewed.revision));
}
