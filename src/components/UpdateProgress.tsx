import type { ProgressView } from "@/lib/download-progress";

/** The update toast's description while it downloads: a bar for a known size, the numbers, and a stall warning. */
export function UpdateProgress({ view }: { view: ProgressView }) {
  return (
    <div className="mt-1 space-y-1.5">
      {view.fraction !== null && (
        <div
          role="progressbar"
          aria-label="Download progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(view.fraction * 100)}
          aria-valuetext={view.line}
          className="h-1 w-full overflow-hidden rounded-full bg-foreground/15"
        >
          <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${view.fraction * 100}%` }} />
        </div>
      )}
      {/* The toaster is a live region, and this text changes at every refresh: screen readers skip it and read the
          figures from the bar's value text on request. */}
      <p className="tabular-nums" aria-hidden="true">
        {view.line}
      </p>
      {view.warning && (
        <>
          {/* Read out once when the warning appears; the visible one counts up every second. */}
          <span className="sr-only">The download may have stalled. Restart SSHelter to try again.</span>
          <p className="text-amber-700 dark:text-amber-400" aria-hidden="true">
            {view.warning}
          </p>
        </>
      )}
    </div>
  );
}
