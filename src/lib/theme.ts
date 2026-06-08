import { useEffect } from "react";
import { useUiStore, THEME_STORAGE_KEY } from "@/stores/ui";

/**
 * Applies the current `useUiStore.theme` to the document: toggles the `dark`
 * class on <html> and persists the preference to localStorage. Mount once near
 * the app root. The store owns the initial value (computed inline in ui.ts to
 * avoid an import cycle); this hook is purely the side-effect bridge to the DOM.
 */
export function useApplyTheme(): void {
  const theme = useUiStore((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.style.colorScheme = theme;
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Persisting is best-effort; ignore storage failures.
    }
  }, [theme]);
}
