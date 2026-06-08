import { create } from "zustand";

export type Theme = "light" | "dark";

/** localStorage key for the persisted theme preference. */
export const THEME_STORAGE_KEY = "sshelter-theme";

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
}));
