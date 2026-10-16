import mark from "@/brand/lunport-mark.json";

/** Decorative companion to the visible Lunport name; shares the native icon geometry. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox={mark.viewBox} fill="currentColor" aria-hidden="true" focusable="false">
      {mark.paths.map((path) => <path key={path} d={path} />)}
    </svg>
  );
}
