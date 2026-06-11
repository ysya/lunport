import { useEffect } from "react";

import { useSettingsStore } from "@/stores/settings";
import { clampFontSize, resolveTheme, systemPrefersDark } from "@/lib/settings-logic";

/**
 * Applies the current `useSettingsStore.theme` preference to the document:
 * resolves "system" via `prefers-color-scheme`, toggles the `dark` class on
 * <html>, and — while the preference is "system" — re-applies on OS theme
 * changes. Mount once near the app root. Persistence is handled by the
 * settings store itself (zustand persist).
 */
export function useApplyTheme(): void {
  const theme = useSettingsStore((s) => s.theme);

  useEffect(() => {
    const apply = () => {
      const resolved = resolveTheme(theme, systemPrefersDark());
      const root = document.documentElement;
      root.classList.toggle("dark", resolved === "dark");
      root.style.colorScheme = resolved;
    };
    apply();

    // Follow live OS changes only while the preference is "system".
    if (theme !== "system" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    mql.addEventListener("change", apply);
    return () => mql.removeEventListener("change", apply);
  }, [theme]);

  // Root font-size preference: the entire UI is rem-based, so this scales it
  // proportionally. Overrides the stylesheet's `html { font-size: 15px }`.
  const fontSize = useSettingsStore((s) => s.fontSize);
  useEffect(() => {
    document.documentElement.style.fontSize = `${clampFontSize(fontSize)}px`;
  }, [fontSize]);
}
