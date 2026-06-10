import { create } from "zustand";

export type Theme = "light" | "dark";

/** localStorage key for the persisted theme preference. */
export const THEME_STORAGE_KEY = "sshelter-theme";

/** localStorage key for the persisted preferred-terminal id. */
export const TERMINAL_STORAGE_KEY = "sshelter-terminal";

/**
 * Resolve the initial terminal preference from localStorage. `null` means
 * "system default / first detected" — also the stored sentinel for default.
 */
function initialTerminalId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(TERMINAL_STORAGE_KEY);
    return stored && stored.length > 0 ? stored : null;
  } catch {
    return null;
  }
}

/**
 * Resolve the initial theme without importing theme.ts (avoids an import cycle):
 * persisted preference first, then the OS preference, defaulting to dark.
 */
function initialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // localStorage may be unavailable (private mode etc.) — fall through.
  }
  if (window.matchMedia?.("(prefers-color-scheme: light)").matches) return "light";
  return "dark";
}

interface UiState {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  /** Currently selected host alias in the master-detail layout (null = nothing selected). */
  selectedAlias: string | null;
  setSelectedAlias: (alias: string | null) => void;
  /** Free-text host-list filter. */
  search: string;
  setSearch: (search: string) => void;
  /** Full source_file paths of collapsed sidebar groups (in-memory only). */
  collapsedGroups: string[];
  toggleGroup: (file: string) => void;
  /**
   * Preferred terminal id to launch connections into (null = system default /
   * first detected). Persisted to localStorage. Passed as `terminalOverride`.
   */
  terminalId: string | null;
  setTerminalId: (id: string | null) => void;
  /** Whether the "New host" dialog is open (driven by the command palette + toolbar). */
  addHostOpen: boolean;
  setAddHostOpen: (open: boolean) => void;
}

/** 只放 UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。 */
export const useUiStore = create<UiState>((set) => ({
  theme: initialTheme(),
  setTheme: (theme) => set({ theme }),
  toggleTheme: () => set((s) => ({ theme: s.theme === "dark" ? "light" : "dark" })),
  selectedAlias: null,
  setSelectedAlias: (selectedAlias) => set({ selectedAlias }),
  search: "",
  setSearch: (search) => set({ search }),
  collapsedGroups: [],
  toggleGroup: (file) =>
    set((s) => ({
      collapsedGroups: s.collapsedGroups.includes(file)
        ? s.collapsedGroups.filter((f) => f !== file)
        : [...s.collapsedGroups, file],
    })),
  terminalId: initialTerminalId(),
  setTerminalId: (terminalId) => {
    try {
      if (terminalId) window.localStorage.setItem(TERMINAL_STORAGE_KEY, terminalId);
      else window.localStorage.removeItem(TERMINAL_STORAGE_KEY);
    } catch {
      // localStorage may be unavailable (private mode etc.) — preference stays in-memory.
    }
    set({ terminalId });
  },
  addHostOpen: false,
  setAddHostOpen: (addHostOpen) => set({ addHostOpen }),
}));
