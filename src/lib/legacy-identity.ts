// The names this app went by before it became Lunport, kept only so that code which finds and carries over what an earlier version left
// behind can name them. Nothing here is a name this version uses; the current names are where they are used.
//
// Old names may appear only in this module and its test (`scripts/identity-guard.mjs` enforces it in CI). Anywhere else, import the
// value from here instead of writing it again.

/** The localStorage key of the preferences: the settings store's persisted envelope. */
export const LEGACY_SETTINGS_KEY = "sshelter-settings";

/** The localStorage key of the sidebar's navigation and layout state: the ui store's persisted state. */
export const LEGACY_UI_KEY = "sshelter-ui";

/** The localStorage key of the theme choice from before the settings store existed. It only ever seeded the theme. */
export const LEGACY_THEME_KEY = "sshelter-theme";

// The keys the stores read now (`SETTINGS_STORAGE_KEY` and `UI_STORAGE_KEY`). They are written out here because this module cannot
// import the stores: importing one creates it, and creating it reads the storage, which is what has to come after the carrying over.
// The tests start the real stores on top of legacy data, so a key here that drifts from the stores' own fails them.
const SETTINGS_KEY = "lunport-settings";
const UI_KEY = "lunport-ui";

/** One saved value on its way to a new key. */
interface Carry {
  from: string;
  to: string;
  value: string;
  /** A key that has nothing left to say once `to` holds the value, and is removed with `from`. */
  superseded?: string;
}

/** The value under `key`, or null when there is none or the storage cannot be read. */
function read(storage: Storage, key: string): string | null {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

/** What an earlier version saved in `storage`, with the key that has to receive each value. */
function savedByEarlierVersions(storage: Storage): Carry[] {
  const carries: Carry[] = [];
  const settings = read(storage, LEGACY_SETTINGS_KEY);
  const theme = read(storage, LEGACY_THEME_KEY);
  if (settings !== null) {
    // Settings that were saved hold the theme as well, and win over the stand-alone key as they always did, so that key is spent with them.
    carries.push({ from: LEGACY_SETTINGS_KEY, to: SETTINGS_KEY, value: settings, superseded: LEGACY_THEME_KEY });
  } else if (theme === "light" || theme === "dark") {
    // Nothing was saved since the theme lived on its own, so the settings start from it. Version 0 is the schema of that time: the
    // settings migrations still apply to it, as they do to every older envelope.
    carries.push({ from: LEGACY_THEME_KEY, to: SETTINGS_KEY, value: JSON.stringify({ state: { theme }, version: 0 }) });
  }
  const ui = read(storage, LEGACY_UI_KEY);
  if (ui !== null) carries.push({ from: LEGACY_UI_KEY, to: UI_KEY, value: ui });
  return carries;
}

/**
 * Carries what earlier versions saved in `storage` over to the keys the stores read now: the settings (or, when only the theme was
 * ever saved, a settings envelope seeded from it) and the sidebar state. Returns the old keys that were carried over, which are gone
 * from `storage` afterwards.
 *
 * The values are copied as they are, so every setting survives, those this build does not know included, and the stores' own
 * migrations then run over them as before. A new key is written in full and read back before the old one is removed, so a failure
 * leaves the old key for the next launch, and nothing is ever lost. A new key that already holds a value is the one in use: it is
 * never replaced, and the old key beside it is left alone. This never throws, because the app has to start without it.
 */
export function migrateLegacyStorage(storage: Storage): { moved: string[] } {
  const moved: string[] = [];
  for (const { from, to, value, superseded } of savedByEarlierVersions(storage)) {
    try {
      if (storage.getItem(to) !== null) continue;
      storage.setItem(to, value);
      if (storage.getItem(to) !== value) throw new Error(`${to} does not hold the value just written to it`);
      storage.removeItem(from);
      if (superseded !== undefined) storage.removeItem(superseded);
      moved.push(from);
    } catch (error) {
      console.warn(`[storage] could not carry ${from} over to ${to}; it stays where it is:`, error);
    }
  }
  return { moved };
}

/**
 * `window.localStorage`, once `migrateLegacyStorage` has carried over what earlier versions saved in it. The stores hand this to zustand's
 * `createJSONStorage`, which calls it as a store is created: the carrying over therefore happens before `persist` first reads the
 * storage, in every window that loads the app and whatever order its modules load in. Where there is no `window` or the browser blocks
 * its storage this throws, which `createJSONStorage` takes to mean that nothing can be persisted, as it does for the default storage.
 */
export function migratedLocalStorage(): Storage {
  migrateLegacyStorage(window.localStorage);
  return window.localStorage;
}
