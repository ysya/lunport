import type { ReactNode } from "react";

/** Keep children mounted for reversible transitions, and remove closed content from interaction immediately. */
export function Disclosure({ open, id, children }: { open: boolean; id: string; children: ReactNode }) {
  return (
    <div id={id} className="app-disclosure" data-open={open} inert={!open} aria-hidden={!open}>
      <div className="app-disclosure-content">
        {children}
      </div>
    </div>
  );
}
