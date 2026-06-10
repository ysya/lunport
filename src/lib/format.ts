import type { BackupInfo } from "@/bindings/BackupInfo";

/**
 * Format a unix-millis timestamp as a coarse relative string ("2h ago").
 * `now` is injectable for testing (defaults to the current time).
 */
export function relativeTime(ms: number, now: number = Date.now()): string {
  const diff = now - ms;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const month = Math.floor(day / 30);
  if (month < 12) return `${month}mo ago`;
  return `${Math.floor(month / 12)}y ago`;
}

/**
 * Backups sorted newest-first by their timestamp. The backend does not
 * guarantee order, so the UI sorts. Returns a new array (does not mutate).
 */
export function sortBackupsByNewest(backups: readonly BackupInfo[]): BackupInfo[] {
  return [...backups].sort((a, b) => b.timestamp_ms - a.timestamp_ms);
}
