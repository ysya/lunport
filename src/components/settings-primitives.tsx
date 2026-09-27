import type { ReactNode } from "react";

import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

/**
 * A stacked editor section: a small uppercase system-font header (with an
 * optional right-aligned action and an optional description) above a grouped
 * inset. Shared between the host editor and the read-only intelligence panels
 * so they share the exact same macOS System-Settings density.
 */
export function Section({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      <div className="flex items-end justify-between gap-2">
        <span className="section-label">{title}</span>
        {action}
      </div>
      {children}
      {description && (
        <p className="px-2.5 pt-1.5 text-xs text-muted-foreground select-none">{description}</p>
      )}
    </section>
  );
}

/**
 * macOS System-Settings-style grouped inset container: a rounded card whose
 * direct children are separated by hairline dividers (see `.settings-group` in
 * index.css). Each child is expected to be a single row.
 */
export function SettingsGroup({ children }: { children: ReactNode }) {
  return <div className="settings-group">{children}</div>;
}

/**
 * A single settings row: label (plus optional muted description) on the left,
 * control on the right. `mono` renders the label in the mono face — for labels
 * that ARE technical values (e.g. `known_hosts`).
 */
export function SettingsRow({
  id,
  label,
  description,
  mono,
  children,
}: {
  id?: string;
  label: string;
  description?: string;
  mono?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-9 items-center justify-between gap-4 px-3 py-2">
      <div className="min-w-0 space-y-0.5 select-none">
        <Label
          htmlFor={id}
          className={cn("text-sm font-normal", mono && "font-mono")}
        >
          {label}
        </Label>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="flex shrink-0 items-center">{children}</div>
    </div>
  );
}
