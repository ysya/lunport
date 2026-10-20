import type { QueryClient } from "@tanstack/react-query";
import {
  applyRecordOverview,
  recordKeyDestinationKey,
  type RecordKeyInvocation,
  importRecordKey,
  importRecordKeyFile,
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
  source: "file" | "paste";
  path: string | null;
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
  return { name: "", source: "file", path: null, privateText: "", busy: false, error: null };
}
export function hasKeyImportSource(state: KeyDraft): boolean {
  return state.source === "file" ? !!state.path?.trim() : !!state.privateText.trim();
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
  fence?: { invocation?: RecordKeyInvocation; destination: string; current: () => boolean },
): Promise<boolean> {
  if (
    (fence && !fence.current()) ||
    state.busy ||
    !isValidSlotName(state.name) ||
    (!generate && !hasKeyImportSource(state))
  )
    return false;
  update({ busy: true, error: null });
  try {
    const overview = generate
      ? await generateRecordKey(state.name, fence?.invocation)
      : state.source === "file"
        ? await importRecordKeyFile(state.name, state.path!, fence?.invocation)
        : await importRecordKey(state.name, state.privateText, fence?.invocation);
    if (fence && (!fence.current() || recordKeyDestinationKey(overview) !== fence.destination)) return false;
    update({ privateText: "", name: "", path: null });
    applyRecordOverview(client, overview);
    return true;
  } catch (error) {
    if (fence && !fence.current()) return false;
    update({
      error: keyActionError(error, generate
        ? "Could not generate the key. Retry when the workspace is available."
        : "Could not import the key. Choose a readable OpenSSH private key (up to 1 MiB) and retry. Public keys, PuTTY and PEM formats are not supported."),
    });
    return false;
  } finally {
    if (!fence || fence.current()) update({ busy: false });
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

/** Only fixed native diagnostics may be reflected here; arbitrary errors can contain secrets. */
export function keyActionError(error: unknown, fallback = "The key action could not be completed. Refresh the workspace and retry."): string {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  switch (message) {
    case "This key has no material on this device.":
    case "The key material is unavailable on this device.":
      return "The key reference exists, but its private key is missing on this device. Complete encrypted library sync, or import the matching private key and select it for the host.";
    case "The vault key does not match its authoritative public identity.":
    case "The vault key does not match the authoritative public identity.":
    case "The saved SSH private key does not match this key reference.":
      return "The saved private key does not match this key reference. Review its fingerprint and the host’s selected key before retrying.";
    case "The vault is unavailable; its original file was retained.":
      return "The encrypted vault could not be unlocked. Allow access to your system credential store and retry. The original vault is retained.";
    case "The vault key cannot be read.":
    case "The saved key cannot be read.":
      return "The saved private key could not be decrypted or read. The original vault is retained.";
    case "The saved private key differs from the encrypted account copy.":
      return "This device’s private key differs from the current encrypted account copy. Sync the account before retrying.";
    case "The saved SSH private key could not be parsed.":
      return "The saved private key is not readable OpenSSH material. The original vault is retained.";
    case "The saved private key's passphrase state does not match this key reference.":
      return "The saved key’s passphrase state differs from its account metadata. Review the key on the device that originally synced it.";
    case "record account is not writable":
      return "Account sync is blocked. Open Account to resolve the migration, update or sync error before retrying.";
    case "the sync code could not be read":
    case "the sync code is unavailable on this device":
      return "The account’s sync credentials are unavailable. Allow credential-store access and check the Account page before retrying.";
    case "synced private material is unavailable":
      return "This account has no synced private copy of this key. Sync it from a device that still holds the private key.";
    default:
      return fallback;
  }
}
