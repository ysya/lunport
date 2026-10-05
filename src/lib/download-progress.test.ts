import { describe, expect, it } from "vitest";

import {
  type DownloadSnapshot,
  STALL_AFTER_MS,
  createDownloadTracker,
  formatBytes,
  progressView,
} from "./download-progress";

const MB = 1_000_000;

/** A snapshot to bend per test: 8.5 MB of 48 MB at 2 MB/s, data still arriving. */
function snapshot(overrides: Partial<DownloadSnapshot> = {}): DownloadSnapshot {
  return {
    phase: "downloading",
    downloaded: 8.5 * MB,
    total: 48 * MB,
    bytesPerSecond: 2 * MB,
    secondsLeft: 19.75,
    idleMs: 200,
    ...overrides,
  };
}

describe("formatBytes", () => {
  it("uses decimal units with the precision a download needs", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(999.6)).toBe("1 KB");
    expect(formatBytes(1_000)).toBe("1 KB");
    expect(formatBytes(850_000)).toBe("850 KB");
    expect(formatBytes(12_345_678)).toBe("12.3 MB");
    expect(formatBytes(48 * MB)).toBe("48.0 MB");
    expect(formatBytes(1_250_000_000)).toBe("1.25 GB");
  });

  it("moves to the next unit when the figure would round up to 1000", () => {
    expect(formatBytes(999_950)).toBe("1.0 MB");
    expect(formatBytes(999_960_000)).toBe("1.00 GB");
  });
});

describe("the download tracker", () => {
  it("is connecting, with nothing downloaded, until the first chunk", () => {
    const tracker = createDownloadTracker(0);
    expect(tracker.snapshot(500)).toEqual({
      phase: "connecting",
      downloaded: 0,
      total: null,
      bytesPerSecond: null,
      secondsLeft: null,
      idleMs: 500,
    });
  });

  it("counts every chunk against the size the server sent", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 48 * MB } }, 100);
    tracker.handle({ event: "Progress", data: { chunkLength: MB } }, 100);
    tracker.handle({ event: "Progress", data: { chunkLength: 2 * MB } }, 300);
    expect(tracker.snapshot(400)).toMatchObject({ phase: "downloading", downloaded: 3 * MB, total: 48 * MB, idleMs: 100 });
  });

  it("treats a missing or zero size as unknown", () => {
    // The backend sends null for an unknown size; the plugin's own type leaves it out.
    for (const contentLength of [null, undefined, 0]) {
      const tracker = createDownloadTracker(0);
      tracker.handle({ event: "Started", data: { contentLength } } as never, 100);
      expect(tracker.snapshot(200).total).toBeNull();
    }
  });

  it("counts a chunk that arrives without Started", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Progress", data: { chunkLength: MB } }, 100);
    expect(tracker.snapshot(200)).toMatchObject({ phase: "downloading", downloaded: MB, total: null });
  });

  it("measures no speed until a second of data, then the average over the last 3 seconds", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 48 * MB } }, 0);
    // 0.5 MB every 250 ms: 2 MB/s.
    for (let at = 0; at <= 500; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.5 * MB } }, at);
    expect(tracker.snapshot(500)).toMatchObject({ bytesPerSecond: null, secondsLeft: null });

    for (let at = 750; at <= 4_000; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.5 * MB } }, at);
    const now = tracker.snapshot(4_000);
    expect(now.downloaded).toBe(8.5 * MB);
    expect(now.bytesPerSecond).toBeCloseTo(2 * MB);
    expect(now.secondsLeft).toBeCloseTo(19.75);
  });

  it("averages the speed over the last 3 seconds when it changes", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 48 * MB } }, 0);
    // 2 MB/s until 4 s, then 0.5 MB/s: the 3 seconds up to 5 s hold 2 s of the first and 1 s of the second.
    for (let at = 0; at <= 4_000; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.5 * MB } }, at);
    for (let at = 4_250; at <= 5_000; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.125 * MB } }, at);
    expect(tracker.snapshot(5_000).bytesPerSecond).toBeCloseTo(1.5 * MB);
  });

  // A pause just longer than the speed window, and a stall.
  it.each([3_500, 20_000])("measures the speed from when the data resumed after %i ms without data", (pause) => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 48 * MB } }, 0);
    for (let at = 0; at <= 2_000; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.5 * MB } }, at);
    // Then 1 MB/s.
    const resumed = 2_000 + pause;
    for (let at = resumed; at <= resumed + 1_500; at += 250) {
      tracker.handle({ event: "Progress", data: { chunkLength: 0.25 * MB } }, at);
    }
    const speed = tracker.snapshot(resumed + 1_500).bytesPerSecond ?? 0;
    expect(speed / MB).toBeGreaterThan(0.9);
    expect(speed / MB).toBeLessThan(1.25);
  });

  it("drops to zero speed and keeps counting the idle time when the data stops", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 48 * MB } }, 0);
    for (let at = 0; at <= 4_000; at += 250) tracker.handle({ event: "Progress", data: { chunkLength: 0.5 * MB } }, at);
    const stalled = tracker.snapshot(4_000 + STALL_AFTER_MS);
    expect(stalled).toMatchObject({ bytesPerSecond: 0, secondsLeft: null, idleMs: STALL_AFTER_MS });
  });

  it("shows no speed for a download that stopped right after its first chunk", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 4 * MB } }, 100);
    tracker.handle({ event: "Progress", data: { chunkLength: MB } }, 100);
    expect(tracker.snapshot(100 + STALL_AFTER_MS)).toMatchObject({ bytesPerSecond: 0, idleMs: STALL_AFTER_MS });
  });

  it("is installing once the download finished", () => {
    const tracker = createDownloadTracker(0);
    tracker.handle({ event: "Started", data: { contentLength: 2 * MB } }, 0);
    tracker.handle({ event: "Progress", data: { chunkLength: 2 * MB } }, 1_500);
    tracker.handle({ event: "Finished" }, 1_500);
    expect(tracker.snapshot(3_000)).toMatchObject({ phase: "installing", downloaded: 2 * MB, bytesPerSecond: null, secondsLeft: null });
  });
});

describe("what the progress toast says", () => {
  it("says it is connecting before the first chunk", () => {
    const view = progressView("0.17.0-4", snapshot({ phase: "connecting", downloaded: 0, total: null, bytesPerSecond: null, secondsLeft: null }));
    expect(view).toEqual({ title: "Downloading v0.17.0-4…", line: "Connecting…", warning: null, fraction: null });
  });

  it("shows the bytes, the speed and the time left, with a bar for a known size", () => {
    const view = progressView("0.17.0-4", snapshot());
    expect(view.title).toBe("Downloading v0.17.0-4…");
    expect(view.line).toBe("8.5 MB of 48.0 MB · 2.0 MB/s · about 20 s left");
    expect(view.warning).toBeNull();
    expect(view.fraction).toBeCloseTo(8.5 / 48);
  });

  it("leaves out what it does not know yet", () => {
    expect(progressView("1.0.0", snapshot({ bytesPerSecond: null, secondsLeft: null })).line).toBe("8.5 MB of 48.0 MB");
    const unknownSize = progressView("1.0.0", snapshot({ total: null, secondsLeft: null }));
    expect(unknownSize.line).toBe("8.5 MB · 2.0 MB/s");
    expect(unknownSize.fraction).toBeNull();
  });

  it("counts the time left in minutes from a minute up", () => {
    expect(progressView("1.0.0", snapshot({ secondsLeft: 59.2 })).line).toMatch(/about 1 min left$/);
    expect(progressView("1.0.0", snapshot({ secondsLeft: 61 })).line).toMatch(/about 1 min left$/);
    expect(progressView("1.0.0", snapshot({ secondsLeft: 125 })).line).toMatch(/about 2 min left$/);
    expect(progressView("1.0.0", snapshot({ secondsLeft: 0.2 })).line).toMatch(/about 1 s left$/);
  });

  it("warns when no data has arrived for a while, also before the first chunk, and says what to do", () => {
    const stalled = progressView("1.0.0", snapshot({ bytesPerSecond: 0, secondsLeft: null, idleMs: 12_400 }));
    expect(stalled.line).toBe("8.5 MB of 48.0 MB · 0 B/s");
    expect(stalled.warning).toBe("No data for 12 s — the download may have stalled. Restart SSHelter to try again.");

    const neverStarted = progressView("1.0.0", snapshot({ phase: "connecting", downloaded: 0, total: null, idleMs: STALL_AFTER_MS }));
    expect(neverStarted.warning).toMatch(/^No data for 10 s — /);
    expect(progressView("1.0.0", snapshot({ idleMs: 59_999 })).warning).toMatch(/^No data for 59 s — /);
    expect(progressView("1.0.0", snapshot({ idleMs: 60_000 })).warning).toMatch(/^No data for 1 min — /);
    expect(progressView("1.0.0", snapshot({ idleMs: 754_000 })).warning).toMatch(/^No data for 12 min — /);
    expect(progressView("1.0.0", snapshot({ idleMs: STALL_AFTER_MS - 1 })).warning).toBeNull();
  });

  it("says it is installing once the download finished, without a stall warning", () => {
    const view = progressView("0.17.0-4", snapshot({ phase: "installing", downloaded: 48 * MB, idleMs: 60_000 }));
    expect(view).toEqual({ title: "Installing v0.17.0-4…", line: "48.0 MB downloaded", warning: null, fraction: 1 });
  });
});
