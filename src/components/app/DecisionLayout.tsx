import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { ActionBar } from "./Workflow";

/** Shared structure for small native windows. Response and actions stay visible while context scrolls. */
export function DecisionLayout({ title, description, icon, meta, danger, children, response, actions }: {
  title: string;
  description?: ReactNode;
  icon: ReactNode;
  meta?: ReactNode;
  danger?: boolean;
  children: ReactNode;
  response?: ReactNode;
  actions: ReactNode;
}) {
  return (
    <div className="app-shell app-decision-layout">
      <header className="app-decision-header">
        <span className={cn("app-editor-symbol", danger && "app-decision-danger")} aria-hidden="true">{icon}</span>
        <div className="app-editor-heading">
          <h1>{title}</h1>
          {description && <p>{description}</p>}
        </div>
        {meta && <div className="app-decision-meta">{meta}</div>}
      </header>
      <main className="app-decision-body">{children}</main>
      {response && <div className="app-decision-response">{response}</div>}
      <ActionBar className="app-decision-actions" label="Decision actions">{actions}</ActionBar>
    </div>
  );
}
