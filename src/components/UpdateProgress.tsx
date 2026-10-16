import type { ProgressView } from "@/lib/download-progress";

/** Inline download progress; changing figures stay out of the live status announcement. */
export function UpdateProgress({ view }: { view: ProgressView }) {
  return (
    <div className="mt-1 space-y-1.5">
      <div
        role="progressbar"
        aria-label="Download progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={
          view.fraction === null ? undefined : Math.round(view.fraction * 100)
        }
        aria-valuetext={view.line}
        className="h-1 w-full overflow-hidden rounded-full bg-foreground/15"
      >
        <div
          className={`h-full rounded-full bg-primary transition-[width] duration-300 ${view.fraction === null ? "motion-safe:animate-pulse" : ""}`}
          style={{
            width: view.fraction === null ? "35%" : `${view.fraction * 100}%`,
          }}
        />
      </div>
      {/* Screen readers can inspect the bar without hearing a new announcement every half second. */}
      <p className="tabular-nums" aria-hidden="true">
        {view.line}
      </p>
      {view.warning && (
        <>
          {/* Read out once when the warning appears; the visible one counts up every second. */}
          <span role="status" className="sr-only">
            The download may have stalled. Restart Lunport to try again.
          </span>
          <p className="text-amber-700 dark:text-amber-400" aria-hidden="true">
            {view.warning}
          </p>
        </>
      )}
    </div>
  );
}
