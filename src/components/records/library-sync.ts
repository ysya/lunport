import { revealHidden } from "@/lib/sync-approvals";
import type { LibrarySyncPreview, LibraryRename } from "@/lib/records";

const failureCodes = new Set([
  "unavailable", "account_check", "account_review", "library_setup",
  "library_download", "sync_data_unavailable", "device_metadata",
  "upgrade_required", "name_conflict", "identity_conflict", "group_conflict",
  "record_validation", "stale_review", "invalid_rename",
]);

/** Only structured native library messages are public; never echo arbitrary transport errors. */
export function librarySyncError(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error && "message" in error &&
      typeof error.code === "string" && failureCodes.has(error.code) &&
      typeof error.message === "string" && error.message.length > 0 && error.message.length <= 2000) {
    return revealHidden(error.message);
  }
  return "Library sync could not finish. Check the relay connection and retry. Existing records have been kept.";
}

export function suggestedLibraryRenames(preview: LibrarySyncPreview): LibraryRename[] {
  return preview.conflicts.map(({ kind, id, suggested_name }) => ({ kind, id, name: suggested_name }));
}
