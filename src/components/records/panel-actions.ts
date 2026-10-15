import type { QueryClient } from "@tanstack/react-query";
import {
  applyRecordOverview,
  importRecordKey,
  generateRecordKey,
  createRecordAccount,
  joinRecordAccount,
  confirmRecordImport,
  resumeRecordImport,
  type ImportPreviewResult,
  type ImportResult,
} from "@/lib/records";
import { isValidSlotName } from "@/lib/key-slots";
import { confirmedCopyIds } from "./editor";
export type KeyDraft = {
  name: string;
  privateText: string;
  busy: boolean;
  error: string | null;
};
export type AccountDraft = {
  deviceName: string;
  words: string;
  createdWords: string;
  migrationOffered: boolean;
  busy: boolean;
  error: string | null;
};
export function clearKeyDraft(): KeyDraft {
  return { name: "", privateText: "", busy: false, error: null };
}
export function clearAccountDraft(): AccountDraft {
  return {
    deviceName: "",
    words: "",
    createdWords: "",
    migrationOffered: false,
    busy: false,
    error: null,
  };
}
/** Secret arguments/results bypass QueryClient mutation variables and data. Only public overview is cached. */
export async function submitKeyDraft(
  client: QueryClient,
  state: KeyDraft,
  update: (patch: Partial<KeyDraft>) => void,
  generate = false,
): Promise<boolean> {
  if (
    state.busy ||
    !isValidSlotName(state.name) ||
    (!generate && !state.privateText.trim())
  )
    return false;
  update({ busy: true, error: null });
  try {
    const overview = generate
      ? await generateRecordKey(state.name)
      : await importRecordKey(state.name, state.privateText);
    update({ privateText: "", name: "" });
    applyRecordOverview(client, overview);
    return true;
  } catch {
    update({
      error: generate
        ? "Could not generate the key. Retry when the workspace is available."
        : "Could not import the key. Check the private key and workspace, then retry.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}
export async function submitAccountDraft(
  client: QueryClient,
  state: AccountDraft,
  update: (patch: Partial<AccountDraft>) => void,
  create: boolean,
  upgradeConfirmed?: boolean,
): Promise<boolean> {
  if (
    state.busy ||
    !state.deviceName.trim() ||
    (!create && !state.words.trim())
  )
    return false;
  update({ busy: true, error: null, migrationOffered: false });
  try {
    if (create) {
      const result = await createRecordAccount(
        state.deviceName,
        upgradeConfirmed,
      );
      update({
        words: "",
        createdWords: result.words,
        error: result.complete
          ? null
          : (result.pending_error ??
            "Sync setup is pending. Save the code and retry setup."),
      });
      applyRecordOverview(client, result.overview);
    } else {
      const overview = await joinRecordAccount(
        state.words,
        state.deviceName,
        upgradeConfirmed,
      );
      update({ words: "", createdWords: "" });
      applyRecordOverview(client, overview);
    }
    return true;
  } catch {
    update({
      migrationOffered: !create,
      error:
        "Could not set up sync. Check the sync code and workspace, then retry or resume a pending setup.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}
export async function submitImportConsent(
  client: QueryClient,
  preview: ImportPreviewResult,
  selected: string[],
): Promise<ImportResult> {
  const result = await confirmRecordImport(
    preview.token,
    confirmedCopyIds(preview, selected),
  );
  applyRecordOverview(client, result.overview);
  return result;
}
export async function resumeImport(
  client: QueryClient,
  importId: string,
): Promise<ImportResult> {
  const result = await resumeRecordImport(importId);
  applyRecordOverview(client, result.overview);
  return result;
}
