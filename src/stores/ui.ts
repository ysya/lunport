import { create } from "zustand";

interface UiState {
  theme: "light" | "dark";
  setTheme: (theme: "light" | "dark") => void;
}

/** 只放 UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。 */
export const useUiStore = create<UiState>((set) => ({
  theme: "light",
  setTheme: (theme) => set({ theme }),
}));
