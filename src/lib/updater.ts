import { Channel } from "@tauri-apps/api/core";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { createElement } from "react";
import { toast } from "sonner";

import type { UpdateDownloadEvent } from "@/bindings/UpdateDownloadEvent";
import type { UpdateInfo } from "@/bindings/UpdateInfo";
import { UpdateProgress } from "@/components/UpdateProgress";
import { type DownloadEvent, createDownloadTracker, progressView } from "@/lib/download-progress";
import { tauriInvoke } from "@/lib/ipc";
import { normalizeUpdateChannel } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";

/** True while a check is already running (avoid double prompts). */
let busy = false;
/** True from "Install & restart" until that install fails (when it succeeds, the app restarts). */
let installing = false;
/** Last version a silent check already prompted for — never re-toast the same one. */
let lastPromptedVersion: string | null = null;
/** A stable toast id so repeated prompts replace rather than stack. */
const UPDATE_TOAST_ID = "sshelter-update";
/** How often the progress toast refreshes while an update installs (its stall timer counts on between chunks). */
export const PROGRESS_REFRESH_MS = 500;

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
  /** Downloads and installs the update, reporting the download to `onEvent`. */
  install: (onEvent: (event: DownloadEvent) => void) => Promise<void>;
}

/** Stable: the plugin's own check against tauri.conf.json's endpoint — the pre-channel path. */
async function checkStable(): Promise<FoundUpdate | null> {
  const update = await check();
  if (!update) return null;
  return { version: update.version, body: update.body, install: (onEvent) => update.downloadAndInstall(onEvent) };
}

/** Beta: the backend checks the `updater-beta` manifest and installs what it found. */
async function checkBeta(): Promise<FoundUpdate | null> {
  const info = await tauriInvoke<UpdateInfo | null>("updater_check_beta");
  if (!info) return null;
  return {
    version: info.version,
    body: info.body,
    install: (onEvent) => {
      const channel = new Channel<UpdateDownloadEvent>();
      channel.onmessage = onEvent;
      return tauriInvoke<void>("updater_install_beta", { onEvent: channel });
    },
  };
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
  // While an update installs, its toast shows the progress, and a new prompt could start a second download.
  if (busy || installing) return;
  busy = true;
  try {
    const channel = normalizeUpdateChannel(useSettingsStore.getState().updateChannel);
    const update = channel === "beta" ? await checkBeta() : await checkStable();
    // The user switched channels while this check was in flight: its result belongs to the
    // old channel, so drop it rather than prompt (and later install) from the wrong one. The same
    // when an install started meanwhile: a prompt now could only offer a second download.
    if (installing || normalizeUpdateChannel(useSettingsStore.getState().updateChannel) !== channel) return;
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

/**
 * Show an update's download in a toast until `stop()`: the bytes, the speed, the time left, and a warning when no
 * data arrives. It refreshes every PROGRESS_REFRESH_MS, and at once when the download finishes.
 */
function showDownloadProgress(version: string) {
  const tracker = createDownloadTracker(performance.now());
  let id: string | number | undefined;
  let stopped = false;
  const render = () => {
    const view = progressView(version, tracker.snapshot(performance.now()));
    id = toast.loading(view.title, {
      id,
      description: createElement(UpdateProgress, { view }),
      // Let the bar span the toast rather than the width of its text.
      classNames: { content: "flex-1" },
    });
  };
  render();
  const timer = setInterval(render, PROGRESS_REFRESH_MS);
  return {
    id: id as string | number,
    onEvent: (event: DownloadEvent) => {
      // Tauri evaluates channel messages in the page, apart from the command's result, so one can arrive after the
      // install returned: it must not replace the result.
      if (stopped) return;
      tracker.handle(event, performance.now());
      // The bytes wait for the next refresh: rendering at Started would flash "0 B" before the first chunk.
      if (event.event === "Finished") render();
    },
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

async function installUpdate(update: FoundUpdate) {
  if (installing) return;
  installing = true;
  const progress = showDownloadProgress(update.version);
  try {
    try {
      await update.install(progress.onEvent);
    } finally {
      progress.stop();
    }
    toast.success("Update installed — restarting…", { id: progress.id, description: undefined });
    await relaunch();
  } catch (e) {
    toast.error("Update failed", { id: progress.id, description: String(e) });
  } finally {
    installing = false;
  }
}
