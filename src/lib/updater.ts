import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { toast } from "sonner";

import type { UpdateInfo } from "@/bindings/UpdateInfo";
import { tauriInvoke } from "@/lib/ipc";
import { normalizeUpdateChannel } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";

/** True while a check or install is already running (avoid double prompts). */
let busy = false;
/** Last version a silent check already prompted for — never re-toast the same one. */
let lastPromptedVersion: string | null = null;
/** A stable toast id so repeated prompts replace rather than stack. */
const UPDATE_TOAST_ID = "sshelter-update";

// Any channel change — the Settings switch or a settings import — retires the current prompt:
// its button would otherwise install from the channel the user just left.
useSettingsStore.subscribe((state, previous) => {
  if (normalizeUpdateChannel(state.updateChannel) !== normalizeUpdateChannel(previous.updateChannel)) {
    toast.dismiss(UPDATE_TOAST_ID);
  }
});

/** What the prompt needs from either channel. */
interface FoundUpdate {
  version: string;
  body?: string | null;
  install: () => Promise<void>;
}

/** Stable: the plugin's own check against tauri.conf.json's endpoint — the pre-channel path. */
async function checkStable(): Promise<FoundUpdate | null> {
  const update = await check();
  if (!update) return null;
  return { version: update.version, body: update.body, install: () => update.downloadAndInstall() };
}

/** Beta: the backend checks the `updater-beta` manifest and installs what it found. */
async function checkBeta(): Promise<FoundUpdate | null> {
  const info = await tauriInvoke<UpdateInfo | null>("updater_check_beta");
  if (!info) return null;
  return { version: info.version, body: info.body, install: () => tauriInvoke<void>("updater_install_beta") };
}

/**
 * Check the selected channel for a newer signed build: Stable reads GitHub
 * Releases' `latest.json`, Beta reads the `updater-beta` release's. When one is
 * found, prompt via a persistent toast; on confirm, download + install + relaunch.
 *
 * `silent` is for the automatic checks: no "up to date" confirmation, no error
 * toasts (dev builds and offline machines would nag otherwise), and the same
 * version is only prompted ONCE per app run — a manual check always prompts.
 */
export async function checkForUpdates({ silent }: { silent: boolean }): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const channel = normalizeUpdateChannel(useSettingsStore.getState().updateChannel);
    const update = channel === "beta" ? await checkBeta() : await checkStable();
    // The user switched channels while this check was in flight: its result belongs to the
    // old channel, so drop it rather than prompt (and later install) from the wrong one.
    if (normalizeUpdateChannel(useSettingsStore.getState().updateChannel) !== channel) return;
    if (!update) {
      if (!silent) toast.success("SSHelter is up to date");
      return;
    }

    if (silent && update.version === lastPromptedVersion) return;
    lastPromptedVersion = update.version;

    toast.info(`Update available: v${update.version}`, {
      id: UPDATE_TOAST_ID,
      description: update.body?.split("\n")[0],
      duration: Infinity,
      action: {
        label: "Install & restart",
        onClick: () => {
          void installUpdate(update);
        },
      },
    });
  } catch (e) {
    if (!silent) {
      toast.error("Could not check for updates", { description: String(e) });
    } else {
      console.warn("[updater] silent check failed:", e);
    }
  } finally {
    busy = false;
  }
}

async function installUpdate(update: FoundUpdate) {
  const id = toast.loading(`Downloading v${update.version}…`);
  try {
    await update.install();
    toast.success("Update installed — restarting…", { id });
    await relaunch();
  } catch (e) {
    toast.error("Update failed", { id, description: String(e) });
  }
}
