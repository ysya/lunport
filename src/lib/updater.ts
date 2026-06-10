import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { toast } from "sonner";

/** True while a check or install is already running (avoid double prompts). */
let busy = false;

/**
 * Check GitHub Releases (`latest.json`) for a newer signed build. When one is
 * found, prompt via a persistent toast; on confirm, download + install + relaunch.
 *
 * `silent` is for the automatic startup check: no "up to date" confirmation and
 * no error toasts (dev builds and offline machines would nag otherwise).
 */
export async function checkForUpdates({ silent }: { silent: boolean }): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const update = await check();
    if (!update) {
      if (!silent) toast.success("SSHelter is up to date");
      return;
    }

    toast.info(`Update available: v${update.version}`, {
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

async function installUpdate(update: NonNullable<Awaited<ReturnType<typeof check>>>) {
  const id = toast.loading(`Downloading v${update.version}…`);
  try {
    await update.downloadAndInstall();
    toast.success("Update installed — restarting…", { id });
    await relaunch();
  } catch (e) {
    toast.error("Update failed", { id, description: String(e) });
  }
}
