import { useEffect, useRef } from "react";

import { tauriInvoke } from "@/lib/ipc";
import { useSettingsStore } from "@/stores/settings";

/**
 * Re-sends the persisted preferences the BACKEND also needs on every launch.
 * The backend resets to its own defaults at startup (tray visible, close-to-tray
 * off, retention unlimited), so the frontend re-applies the persisted values
 * once on mount. Fire-and-forget: failures are logged, never toasted — the app
 * is fully usable without them.
 */
export function useSyncBackendSettings(): void {
  const fired = useRef(false);

  useEffect(() => {
    if (fired.current) return; // StrictMode double-mount guard
    fired.current = true;

    const { trayVisible, closeToTray, backupRetention } = useSettingsStore.getState();
    const warn = (cmd: string) => (e: unknown) =>
      console.warn(`[settings] startup sync: ${cmd} failed:`, e);

    tauriInvoke<void>("tray_set_visible", { visible: trayVisible }).catch(
      warn("tray_set_visible"),
    );
    tauriInvoke<void>("app_set_close_to_tray", { enabled: closeToTray }).catch(
      warn("app_set_close_to_tray"),
    );
    tauriInvoke<void>("config_set_backup_retention", { limit: backupRetention }).catch(
      warn("config_set_backup_retention"),
    );
  }, []);
}
