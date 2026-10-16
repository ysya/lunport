import mark from "@/brand/lunport-mark.json";

/** Decorative companion to the visible Lunport name; shares the native icon geometry. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="10 16 80 68" fill="currentColor" aria-hidden="true" focusable="false">
      <path d={mark.crescent} />
      <path d={mark.beam} fill="none" stroke="currentColor" strokeWidth={mark.beamWidth} strokeLinecap="round" />
      <circle cx={mark.node.x} cy={mark.node.y} r={mark.node.radius} />
    </svg>
  );
}
