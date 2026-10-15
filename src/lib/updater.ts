import { Channel } from "@tauri-apps/api/core";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { create } from "zustand";

import type { UpdateDownloadEvent } from "@/bindings/UpdateDownloadEvent";
import type { UpdateInfo } from "@/bindings/UpdateInfo";
import {
  type DownloadEvent,
  type ProgressView,
  createDownloadTracker,
  progressView,
} from "@/lib/download-progress";
import { tauriInvoke } from "@/lib/ipc";
import {
  normalizeUpdateChannel,
  type UpdateChannel,
} from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";

export type UpdatePhase =
  | "idle"
  | "checking"
  | "current"
  | "available"
  | "installing"
  | "restarting"
  | "restart_required"
  | "error";
export interface UpdaterState {
  phase: UpdatePhase;
  channel: UpdateChannel;
  version: string | null;
  body: string | null;
  checkedAt: number | null;
  progress: ProgressView | null;
  error: string | null;
  errorStage: "check" | "install" | null;
}
const selectedChannel = () =>
  normalizeUpdateChannel(useSettingsStore.getState().updateChannel);
const initialState = (): UpdaterState => ({
  phase: "idle",
  channel: selectedChannel(),
  version: null,
  body: null,
  checkedAt: null,
  progress: null,
  error: null,
  errorStage: null,
});
/** Session state survives closing Settings; it never persists an installer or automatically opens a window. */
export const useUpdaterState = create<UpdaterState>(initialState);
export const PROGRESS_REFRESH_MS = 500;
export const updateInProgress = (phase: UpdatePhase) =>
  phase === "installing" ||
  phase === "restarting" ||
  phase === "restart_required";

interface FoundUpdate {
  version: string;
  body?: string | null;
  install: (onEvent: (event: DownloadEvent) => void) => Promise<void>;
  close?: () => Promise<void>;
}
let candidate: FoundUpdate | null = null;
let checkFlight: Promise<void> | null = null;
let epoch = 0;
function retire(update: FoundUpdate | null) {
  void update?.close?.().catch(() => {});
}
function clearCandidate() {
  const old = candidate;
  candidate = null;
  retire(old);
}
useSettingsStore.subscribe((state, previous) => {
  if (
    normalizeUpdateChannel(state.updateChannel) ===
    normalizeUpdateChannel(previous.updateChannel)
  )
    return;
  epoch++;
  // A settings import may change the preference during installation. Keep showing the actual install.
  if (updateInProgress(useUpdaterState.getState().phase)) return;
  clearCandidate();
  useUpdaterState.setState(initialState(), true);
});

async function checkStable(): Promise<FoundUpdate | null> {
  const update = await check();
  return update
    ? {
        version: update.version,
        body: update.body,
        install: (onEvent) => update.downloadAndInstall(onEvent),
        close: () => update.close(),
      }
    : null;
}
async function checkBeta(): Promise<FoundUpdate | null> {
  const info = await tauriInvoke<UpdateInfo | null>("updater_check_beta");
  if (!info) return null;
  return {
    ...info,
    install: (onEvent) => {
      const channel = new Channel<UpdateDownloadEvent>();
      channel.onmessage = onEvent;
      return tauriInvoke<void>("updater_install_beta", { onEvent: channel });
    },
  };
}
const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

/** Manual and automatic checks update the same inline state. Neither creates a toast or opens Settings. */
export async function checkForUpdates({
  silent,
}: {
  silent: boolean;
}): Promise<void> {
  if (updateInProgress(useUpdaterState.getState().phase)) return;
  const channel = selectedChannel();
  if (checkFlight) {
    await checkFlight;
    // A channel switch waits for the old backend check, then checks the new channel.
    // This also keeps Beta's pending installer from being overwritten by concurrent checks.
    if (
      selectedChannel() === channel &&
      useUpdaterState.getState().phase === "idle"
    ) {
      return checkForUpdates({ silent });
    }
    return;
  }
  const generation = epoch;
  clearCandidate();
  useUpdaterState.setState({
    ...initialState(),
    phase: "checking",
    checkedAt: useUpdaterState.getState().checkedAt,
  });
  const flight = (async () => {
    try {
      const update =
        channel === "beta" ? await checkBeta() : await checkStable();
      if (generation !== epoch || selectedChannel() !== channel) {
        retire(update);
        return;
      }
      candidate = update;
      useUpdaterState.setState({
        phase: update ? "available" : "current",
        channel,
        version: update?.version ?? null,
        body: update?.body ?? null,
        checkedAt: Date.now(),
        progress: null,
        error: null,
        errorStage: null,
      });
    } catch (error) {
      if (generation !== epoch || selectedChannel() !== channel) return;
      useUpdaterState.setState({
        phase: "error",
        error: errorMessage(error),
        errorStage: "check",
      });
      if (silent) console.warn("[updater] automatic check failed:", error);
    }
  })();
  checkFlight = flight;
  try {
    await flight;
  } finally {
    if (checkFlight === flight) checkFlight = null;
  }
}

export async function restartAfterUpdate(): Promise<void> {
  if (useUpdaterState.getState().phase !== "restart_required") return;
  useUpdaterState.setState({ phase: "restarting", error: null });
  try {
    await relaunch();
  } catch (error) {
    useUpdaterState.setState({
      phase: "restart_required",
      error: errorMessage(error),
    });
  }
}

/** Only the explicitly reviewed candidate can install. Checking, double clicks and stale channels cannot start another download. */
export async function installAvailableUpdate(): Promise<void> {
  const state = useUpdaterState.getState();
  if (
    checkFlight ||
    state.phase !== "available" ||
    state.channel !== selectedChannel() ||
    !candidate
  )
    return;
  const update = candidate;
  candidate = null;
  const tracker = createDownloadTracker(performance.now());
  let stopped = false;
  const render = () =>
    useUpdaterState.setState({
      progress: progressView(
        update.version,
        tracker.snapshot(performance.now()),
      ),
    });
  useUpdaterState.setState({
    phase: "installing",
    error: null,
    errorStage: null,
  });
  render();
  const timer = setInterval(render, PROGRESS_REFRESH_MS);
  const stop = () => {
    stopped = true;
    clearInterval(timer);
  };
  try {
    await update.install((event) => {
      if (stopped) return;
      tracker.handle(event, performance.now());
      if (event.event === "Finished") render();
    });
  } catch (error) {
    useUpdaterState.setState({
      phase: "error",
      channel: selectedChannel(),
      error: errorMessage(error),
      errorStage: "install",
      progress: null,
    });
    return;
  } finally {
    stop();
    retire(update);
  }
  useUpdaterState.setState({ phase: "restarting", progress: null });
  try {
    await relaunch();
  } catch (error) {
    useUpdaterState.setState({
      phase: "restart_required",
      error: errorMessage(error),
    });
  }
}
