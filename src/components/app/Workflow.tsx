import { useId, type ReactNode, type Ref } from "react";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

/** Progress is descriptive: advancing always requires the action in the current step. */
export function WorkflowSteps({ steps, current, complete = false }: {
  steps: string[];
  current: number;
  complete?: boolean;
}) {
  return (
    <ol className="app-workflow-steps" aria-label="Progress">
      {steps.map((step, index) => (
        <li key={step} data-complete={complete || index < current} aria-current={!complete && index === current ? "step" : undefined}>
          <span className="app-step-number" aria-hidden="true">
            {complete || index < current ? <Check className="size-3.5" /> : index + 1}
          </span>
          <span>{step}</span>
        </li>
      ))}
    </ol>
  );
}

export function FormSection({ title, description, actions, children, className, headingRef }: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  headingRef?: Ref<HTMLHeadingElement>;
}) {
  const id = useId();
  return (
    <section className={cn("app-form-section", className)} aria-labelledby={id}>
      <div className="app-section-heading">
        <div>
          <h2 id={id} ref={headingRef} tabIndex={headingRef ? -1 : undefined} className={headingRef ? "outline-none" : undefined}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {actions && <div className="app-page-actions">{actions}</div>}
      </div>
      <div className="app-section-fields">{children}</div>
    </section>
  );
}

export function ActionBar({ children, hint, label = "Actions", className }: {
  children: ReactNode;
  hint?: ReactNode;
  label?: string;
  className?: string;
}) {
  return (
    <footer className={cn("app-action-bar", className)} aria-label={label}>
      {hint && <div className="app-action-hint">{hint}</div>}
      <div className="app-action-buttons">{children}</div>
    </footer>
  );
}

export function EditorHeader({ icon, title, description, close }: {
  icon: ReactNode;
  title: ReactNode;
  description: ReactNode;
  close?: ReactNode;
}) {
  return (
    <header className="app-editor-header">
      <span className="app-editor-symbol" aria-hidden="true">{icon}</span>
      <div className="app-editor-heading">{title}{description}</div>
      {close}
    </header>
  );
}
