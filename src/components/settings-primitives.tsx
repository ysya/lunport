import type { ReactNode } from "react";

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
