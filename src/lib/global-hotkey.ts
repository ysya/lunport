import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

/** Native registration also works while the macOS main WebView is deferred. */
export function useGlobalHotkey(): void {
  const enabled = useSettingsStore((s) => s.globalHotkey);

  useEffect(() => {
    void invoke("app_set_global_hotkey", { enabled }).catch((e) =>
      console.warn("[hotkey] could not sync global hotkey:", e),
    );
  }, [enabled]);

  useEffect(() => {
    const consume = () => {
      void invoke<boolean>("app_take_quick_connect").then((open) => {
        if (open) useUiStore.getState().setPaletteOpen(true);
      });
    };
    // Register before consuming: a shortcut during first mount is never lost.
    const unlisten = listen("app://quick-connect", consume);
    void unlisten.then(consume);
    return () => { void unlisten.then((stop) => stop()); };
  }, []);
}
