import { create } from "zustand";

interface UiState {
  theme: "light" | "dark";
  setTheme: (theme: "light" | "dark") => void;
  /** Currently selected host alias in the master-detail layout (null = nothing selected). */
  selectedAlias: string | null;
  setSelectedAlias: (alias: string | null) => void;
  /** Free-text host-list filter. */
  search: string;
  setSearch: (search: string) => void;
}

/** 只放 UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。 */
export const useUiStore = create<UiState>((set) => ({
  theme: "light",
  setTheme: (theme) => set({ theme }),
  selectedAlias: null,
  setSelectedAlias: (selectedAlias) => set({ selectedAlias }),
  search: "",
  setSearch: (search) => set({ search }),
}));
