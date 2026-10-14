import type { QueryClient } from "@tanstack/react-query";
import {
  acceptStatus,
  recordsStatusKey,
  previewRecordMigration,
  confirmRecordMigration,
  resumeRecordMigration,
  pauseLegacyWorkspace,
  cancelRecordMigration,
  type RecordsStatus,
  type MigrationPreviewResult,
  type MigrationReceipt,
  type MigrationResult,
} from "@/lib/records";
export type MigrationDraft = {
  words: string;
  preview: MigrationPreviewResult | null;
  consent: boolean;
  consumed: boolean;
  receipt: MigrationReceipt | null;
  busy: boolean;
  error: string | null;
};
export function clearMigrationDraft(words = ""): MigrationDraft {
  return {
    words,
    preview: null,
    consent: false,
    consumed: false,
    receipt: null,
    busy: false,
    error: null,
  };
}
/** Native preview owns source validation. Codes and token-bearing replies remain in component memory. */
export async function previewMigrationDraft(
  state: MigrationDraft,
  update: (patch: Partial<MigrationDraft>) => void,
): Promise<boolean> {
  if (state.busy) return false;
  update({ busy: true, error: null });
  try {
    const preview = await previewRecordMigration(state.words || undefined);
    update({
      words: "",
      preview,
      consent: false,
      consumed: false,
      receipt: null,
    });
    return true;
  } catch {
    update({
      error:
        "Could not preview migration. Check the sync code and source workspace, then retry.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}
export async function applyMigrationStatus(
  client: QueryClient,
  result: MigrationResult,
): Promise<void> {
  // Cancel the request that may have captured Legacy before native activation. Only the public
  // status enters cache; an older partial receipt cannot downgrade an already active workspace.
  await applyNativeStatus(client, result.status);
}
export async function confirmMigrationDraft(
  client: QueryClient,
  state: MigrationDraft,
  update: (patch: Partial<MigrationDraft>) => void,
): Promise<boolean> {
  if (
    state.busy ||
    state.consumed ||
    !state.preview?.preview.can_confirm ||
    !state.consent
  )
    return false;
  update({ busy: true, error: null, consumed: true });
  try {
    const result = await confirmRecordMigration(
      state.preview.token,
      state.consent,
    );
    await applyMigrationStatus(client, result);
    update({
      words: "",
      preview: null,
      consent: false,
      receipt: result.receipt,
    });
    return true;
  } catch {
    update({
      error:
        "Migration could not finish. Refresh pending migrations and resume an existing operation, or preview again.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}
export async function resumeMigrationDraft(
  client: QueryClient,
  id: string,
  update: (patch: Partial<MigrationDraft>) => void,
): Promise<boolean> {
  update({ busy: true, error: null });
  try {
    const result = await resumeRecordMigration(id);
    await applyMigrationStatus(client, result);
    update({
      words: "",
      preview: null,
      consent: false,
      consumed: true,
      receipt: result.receipt,
    });
    return true;
  } catch {
    update({
      error:
        "Could not resume migration. The existing progress is retained; refresh and retry.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}

async function applyNativeStatus(
  client: QueryClient,
  status: RecordsStatus,
): Promise<void> {
  await client.cancelQueries({ queryKey: recordsStatusKey });
  client.setQueryData<RecordsStatus>(recordsStatusKey, (current) =>
    current?.format === "records" && status.format === "legacy"
      ? current
      : acceptStatus(current, status),
  );
}
export async function pauseLegacyForMigration(
  client: QueryClient,
  savedEdits: boolean,
): Promise<boolean> {
  if (!savedEdits) return false;
  const status = await pauseLegacyWorkspace();
  await applyNativeStatus(client, status);
  return true;
}

/** Dispose only the in-memory native preview; this cannot roll back a confirmed migration. */
export async function discardMigrationPreview(
  token: string | null,
): Promise<void> {
  if (!token) return;
  try {
    await cancelRecordMigration(token);
  } catch {
    /* Clear local secret state even if IPC is unavailable. */
  }
}
