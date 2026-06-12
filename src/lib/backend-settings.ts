import { useEffect, useRef } from "react";

import { tauriInvoke } from "@/lib/ipc";
import { checkForUpdates } from "@/lib/updater";
import { useSettingsStore } from "@/stores/settings";

/**
 * Sends the CURRENT backend-affecting preferences (tray visibility,
 * close-to-tray, backup retention) to the backend. Fire-and-forget: failures
 * are logged, never toasted — the app is fully usable without them. Used by
 * the launch sync below and after a settings import replaces the store.
 */
export function pushBackendSettings(): void {
  const { trayVisible, closeToTray, backupRetention } = useSettingsStore.getState();
  const warn = (cmd: string) => (e: unknown) =>
    console.warn(`[settings] backend sync: ${cmd} failed:`, e);

  tauriInvoke<void>("tray_set_visible", { visible: trayVisible }).catch(
    warn("tray_set_visible"),
  );
  tauriInvoke<void>("app_set_close_to_tray", { enabled: closeToTray }).catch(
    warn("app_set_close_to_tray"),
  );
  tauriInvoke<void>("config_set_backup_retention", { limit: backupRetention }).catch(
    warn("config_set_backup_retention"),
  );
}

/**
 * Re-sends the persisted preferences the BACKEND also needs on every launch.
 * The backend resets to its own defaults at startup (tray visible, close-to-tray
 * off, retention unlimited), so the frontend re-applies the persisted values
 * once on mount.
 */
export function useSyncBackendSettings(): void {
  const fired = useRef(false);

  useEffect(() => {
    if (fired.current) return; // StrictMode double-mount guard
    fired.current = true;

    pushBackendSettings();
  }, []);

  // Auto update checks. A long-running app (especially with close-to-tray)
  // would otherwise only ever check once at launch, so while the preference is
  // on we ALSO re-check periodically and on window focus (throttled). The
  // updater module itself dedupes prompts per version.
  const autoCheckUpdates = useSettingsStore((s) => s.autoCheckUpdates);
  useEffect(() => {
    if (!autoCheckUpdates) return;

    const RECHECK_MS = 4 * 3_600_000; // every 4 hours while running
    const FOCUS_THROTTLE_MS = 3_600_000; // at most one focus-triggered check per hour
    let lastCheck = 0;

    const checkNow = () => {
      lastCheck = Date.now();
      void checkForUpdates({ silent: true });
    };

    // Initial check waits a few seconds so launch stays snappy.
    const initial = window.setTimeout(checkNow, 5_000);
    const interval = window.setInterval(checkNow, RECHECK_MS);
    const onFocus = () => {
      if (Date.now() - lastCheck >= FOCUS_THROTTLE_MS) checkNow();
    };
    window.addEventListener("focus", onFocus);

    return () => {
      window.clearTimeout(initial);
      window.clearInterval(interval);
      window.removeEventListener("focus", onFocus);
    };
  }, [autoCheckUpdates]);
}
