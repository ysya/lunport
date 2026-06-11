import { useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  isRegistered,
  register,
  unregister,
  type ShortcutEvent,
} from "@tauri-apps/plugin-global-shortcut";

import { usePlatform } from "@/lib/queries";
import { quickConnectShortcut } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

/** Hotkey trigger: surface the (possibly hidden/minimized) window, then open the ⌘K palette. */
function onQuickConnect(event: ShortcutEvent): void {
  if (event.state !== "Pressed") return;
  const win = getCurrentWindow();
  // Sequential: unminimize only works on a shown window; focus comes last.
  win
    .show()
    .then(() => win.unminimize())
    .then(() => win.setFocus())
    .catch((e) => console.warn("[hotkey] could not focus window:", e));
  useUiStore.getState().setPaletteOpen(true);
}

/**
 * Keeps the OS-level quick-connect hotkey (⌥⌘K / Ctrl+Alt+K) in sync with the
 * persisted `globalHotkey` preference. Mounted once in App: handles both the
 * startup sync (register if enabled) and live toggles from Settings.
 *
 * Registering an already-registered shortcut errors, so every sync checks
 * `isRegistered` first (also covers the StrictMode double-run in dev).
 */
export function useGlobalHotkey(): void {
  const enabled = useSettingsStore((s) => s.globalHotkey);
  // The accelerator differs per platform; wait for the platform query rather
  // than guessing (registering the wrong combo would orphan it on toggle-off).
  const platform = usePlatform().data;

  useEffect(() => {
    if (platform === undefined) return;
    const shortcut = quickConnectShortcut(platform);
    void (async () => {
      try {
        const registered = await isRegistered(shortcut);
        if (enabled && !registered) {
          await register(shortcut, onQuickConnect);
        } else if (!enabled && registered) {
          await unregister(shortcut);
        }
      } catch (e) {
        console.warn("[hotkey] could not sync global hotkey:", e);
      }
    })();
  }, [enabled, platform]);
}
