import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ProgressView } from "@/lib/download-progress";
import { UpdateProgress } from "./UpdateProgress";

/**
 * The toaster is a polite live region that reads out added and changed text. The progress line changes at every
 * refresh and a stall warning counts up every second, so screen readers skip both (aria-hidden): the figures are the
 * progress bar's value text, read on request, and a stall is announced once.
 */
describe("UpdateProgress", () => {
  const stalled: ProgressView = {
    title: "Downloading v1.0.0…",
    line: "1.0 MB of 4.0 MB · 0 B/s",
    warning: "No data for 12 s — the download may have stalled. Restart SSHelter to try again.",
    fraction: 0.25,
  };

  it("keeps the changing text from being read out and announces a stall once, without its count", () => {
    const html = renderToStaticMarkup(<UpdateProgress view={stalled} />);
    expect(html).toMatch(/<p[^>]*aria-hidden="true"[^>]*>1\.0 MB of 4\.0 MB · 0 B\/s<\/p>/);
    expect(html).toMatch(/<p[^>]*aria-hidden="true"[^>]*>No data for 12 s — /);
    expect(html).toContain('<span class="sr-only">The download may have stalled. Restart SSHelter to try again.</span>');
  });

  it("gives screen readers the figures as the progress bar's value text", () => {
    const html = renderToStaticMarkup(<UpdateProgress view={stalled} />);
    expect(html).toMatch(/role="progressbar"[^>]*aria-valuetext="1\.0 MB of 4\.0 MB · 0 B\/s"/);
  });

  it("announces nothing extra while data arrives", () => {
    const html = renderToStaticMarkup(<UpdateProgress view={{ ...stalled, warning: null }} />);
    expect(html).not.toContain("sr-only");
    expect(html).toContain('role="progressbar"');
  });
});
