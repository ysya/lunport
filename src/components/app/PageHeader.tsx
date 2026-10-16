import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function PageHeader({ title, count, description, breadcrumb, actions, className }: {
  title: ReactNode;
  count?: number;
  description?: ReactNode;
  breadcrumb?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("app-page-header", className)}>
      <div className="app-page-heading">
        {breadcrumb}
        <h1 className="app-page-title">
          {title}
          {count !== undefined && <span className="app-page-count">
            {count}
          </span>}
        </h1>
        {description && <p className="app-page-description">
          {description}
        </p>}
      </div>
      {actions && <div className="app-page-actions">
        {actions}
      </div>}
    </header>
  );
}
