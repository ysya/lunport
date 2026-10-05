import type { DownloadEvent as PluginDownloadEvent } from "@tauri-apps/plugin-updater";

import type { UpdateDownloadEvent } from "@/bindings/UpdateDownloadEvent";

/**
 * A download event from either update channel: Stable's from the updater plugin, Beta's from the backend's
 * `updater_install_beta`, which sends the plugin's shape (updater_channel.rs). `Started` comes with the first
 * chunk, so until then nothing has arrived. An unknown size is null from the backend; the plugin's type
 * leaves it out.
 */
export type DownloadEvent = PluginDownloadEvent | UpdateDownloadEvent;

/** The speed is the average over about this long: it follows a change within seconds without jumping per chunk. */
export const SPEED_WINDOW_MS = 3_000;
/** No data for this long and the toast says the download may have stalled. */
export const STALL_AFTER_MS = 10_000;
/** Less data history than this gives no meaningful speed. */
const MIN_SPEED_SPAN_MS = 1_000;
/** Speed samples older than the newest are at least this far apart, so a fast download keeps only a few per window. */
const SAMPLE_EVERY_MS = 200;

export type DownloadPhase = "connecting" | "downloading" | "installing";

export interface DownloadSnapshot {
  phase: DownloadPhase;
  /** Bytes received so far. */
  downloaded: number;
  /** The size the server sent, if any. */
  total: number | null;
  /** Bytes per second over the last few seconds; null until there is a second of data, and while installing. */
  bytesPerSecond: number | null;
  /** Seconds left at that speed, when the size is known and data is arriving. */
  secondsLeft: number | null;
  /** Milliseconds since the last chunk, or since the start before the first one. */
  idleMs: number;
}

export interface DownloadTracker {
  handle(event: DownloadEvent, now: number): void;
  snapshot(now: number): DownloadSnapshot;
}

/** Follows one download from its events. Times are milliseconds on one clock (`performance.now()`). */
export function createDownloadTracker(startedAt: number): DownloadTracker {
  let phase: DownloadPhase = "connecting";
  let downloaded = 0;
  let total: number | null = null;
  let lastDataAt = startedAt;
  // Bytes received by each time, oldest first: the speed is measured from the oldest one still in use. The newest
  // always holds the latest data, so a download that stops counts as stopped from its last chunk on.
  const samples: { at: number; downloaded: number }[] = [];

  const sample = (now: number) => {
    const last = samples[samples.length - 1];
    const previous = samples[samples.length - 2];
    if (last && previous && now - previous.at < SAMPLE_EVERY_MS) {
      last.at = now;
      last.downloaded = downloaded;
    } else {
      samples.push({ at: now, downloaded });
    }
  };

  return {
    handle(event, now) {
      switch (event.event) {
        case "Started": {
          const size = event.data.contentLength;
          total = typeof size === "number" && size > 0 ? size : null;
          if (phase === "connecting") phase = "downloading";
          lastDataAt = now;
          sample(now);
          break;
        }
        case "Progress":
          if (phase === "connecting") phase = "downloading";
          // After a pause, measure from when the data resumed rather than across the pause.
          if (now - lastDataAt >= SPEED_WINDOW_MS) samples.splice(0, samples.length, { at: now, downloaded });
          downloaded += event.data.chunkLength;
          lastDataAt = now;
          sample(now);
          break;
        case "Finished":
          phase = "installing";
          break;
      }
    },
    snapshot(now) {
      // Keep the last sample at or before the window's start, so the speed covers the whole window.
      const windowStart = now - SPEED_WINDOW_MS;
      while (samples.length > 1 && samples[1].at <= windowStart) samples.shift();
      const base = samples[0];
      const span = base ? now - base.at : 0;
      const bytesPerSecond =
        phase === "downloading" && base && span >= MIN_SPEED_SPAN_MS ? ((downloaded - base.downloaded) * 1_000) / span : null;
      const secondsLeft = total !== null && bytesPerSecond ? Math.max(0, total - downloaded) / bytesPerSecond : null;
      return { phase, downloaded, total, bytesPerSecond, secondsLeft, idleMs: now - lastDataAt };
    },
  };
}

const UNITS = [
  { unit: "B", size: 1, digits: 0 },
  { unit: "KB", size: 1e3, digits: 0 },
  { unit: "MB", size: 1e6, digits: 1 },
  { unit: "GB", size: 1e9, digits: 2 },
] as const;

/** Decimal units (1 MB = 1,000,000 bytes): "850 KB", "12.3 MB", "1.25 GB". */
export function formatBytes(bytes: number): string {
  // The smallest unit whose rounded figure stays under 1000, so 999,950 bytes read "1.0 MB", not "1000 KB".
  let i = 0;
  while (i < UNITS.length - 1 && Number((bytes / UNITS[i].size).toFixed(UNITS[i].digits)) >= 1000) i++;
  const { unit, size, digits } = UNITS[i];
  return `${(bytes / size).toFixed(digits)} ${unit}`;
}

function timeLeft(seconds: number): string {
  const s = Math.max(1, Math.ceil(seconds));
  return s < 60 ? `about ${s} s left` : `about ${Math.round(s / 60)} min left`;
}

function idleFor(ms: number): string {
  const s = Math.floor(ms / 1_000);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min`;
}

/** What the progress toast shows. */
export interface ProgressView {
  title: string;
  /** The bytes, the speed and the time left, or what is happening. */
  line: string;
  /** Set when no data has arrived for STALL_AFTER_MS. */
  warning: string | null;
  /** 0–1 for the progress bar; null when the size is unknown. */
  fraction: number | null;
}

export function progressView(version: string, s: DownloadSnapshot): ProgressView {
  if (s.phase === "installing") {
    return { title: `Installing v${version}…`, line: `${formatBytes(s.downloaded)} downloaded`, warning: null, fraction: 1 };
  }
  const title = `Downloading v${version}…`;
  // Nothing is written before the whole download is in and its signature checked, so a restart is safe.
  const warning =
    s.idleMs >= STALL_AFTER_MS
      ? `No data for ${idleFor(s.idleMs)} — the download may have stalled. Restart SSHelter to try again.`
      : null;
  if (s.phase === "connecting") return { title, line: "Connecting…", warning, fraction: null };

  const parts = [s.total !== null ? `${formatBytes(s.downloaded)} of ${formatBytes(s.total)}` : formatBytes(s.downloaded)];
  if (s.bytesPerSecond !== null) parts.push(`${formatBytes(s.bytesPerSecond)}/s`);
  if (s.secondsLeft !== null) parts.push(timeLeft(s.secondsLeft));
  const fraction = s.total !== null ? Math.min(1, s.downloaded / s.total) : null;
  return { title, line: parts.join(" · "), warning, fraction };
}
