import { tauriInvoke } from "@/lib/ipc";
import { pushBackendSettings } from "@/lib/backend-settings";
import { SETTINGS_STORAGE_KEY, useSettingsStore } from "@/stores/settings";

/**
 * The zustand-persist storage envelope for `sshelter-settings`. The current
 * store has no explicit version, so persist writes `version: 0`.
 */
export interface SettingsEnvelope {
  state: Record<string, unknown>;
  version?: number;
}

/** The persist schema version this build writes (zustand's default). */
export const SETTINGS_VERSION = 0;

/**
 * Parse + validate the contents of an imported settings file. Throws an
 * `Error` with a user-readable message on any problem. Pure — testable.
 */
export function parseSettingsEnvelope(text: string): SettingsEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("The file is not valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("The file is not an SSHelter settings export.");
  }
  const envelope = parsed as Record<string, unknown>;
  const state = envelope.state;
  if (typeof state !== "object" || state === null || Array.isArray(state)) {
    throw new Error("The file is not an SSHelter settings export (missing settings data).");
  }
  const version = envelope.version;
  if (version !== undefined && typeof version !== "number") {
    throw new Error("The file has an invalid settings version.");
  }
  if (typeof version === "number" && version > SETTINGS_VERSION) {
    throw new Error(
      `The file was exported by a newer SSHelter (settings version ${version}; this build supports ${SETTINGS_VERSION}).`,
    );
  }
  return { state: state as Record<string, unknown>, version: version as number | undefined };
}

/**
 * The current persisted envelope, pretty-printed for export. Falls back to
 * serializing the live store (matching what persist would write) when nothing
 * has been persisted yet — e.g. a fresh install with untouched defaults.
 */
export function currentSettingsJson(): string {
  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (raw) return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    // Unreadable/corrupt storage — fall through to the live store.
  }
  const state = Object.fromEntries(
    Object.entries(useSettingsStore.getState()).filter(([, v]) => typeof v !== "function"),
  );
  return JSON.stringify({ state, version: SETTINGS_VERSION }, null, 2);
}

/**
 * Export flow: native save dialog (Rust `settings_export`) → write. Resolves
 * to the chosen path, or null when the user cancels. Errors reject.
 */
export function exportSettings(): Promise<string | null> {
  return tauriInvoke<string | null>("settings_export", { json: currentSettingsJson() });
}

/**
 * Import, step 1: native open dialog (Rust `settings_import`, 1 MB cap) →
 * validate. Resolves to the parsed envelope, or null when the user cancels.
 * Invalid files / IO errors reject with a readable message.
 */
export async function pickSettingsImport(): Promise<SettingsEnvelope | null> {
  const contents = await tauriInvoke<string | null>("settings_import");
  if (contents === null) return null;
  return parseSettingsEnvelope(contents);
}

/**
 * Import, step 2 (after the user confirmed the overwrite): persist the
 * envelope, rehydrate the live store from storage, and re-send the
 * backend-affecting settings (tray / close-to-tray / retention) — the same
 * invokes `useSyncBackendSettings` fires on launch.
 */
export async function applySettingsImport(envelope: SettingsEnvelope): Promise<void> {
  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(envelope));
  // zustand persist re-reads storage and merges over the current state.
  await useSettingsStore.persist.rehydrate();
  pushBackendSettings();
}
