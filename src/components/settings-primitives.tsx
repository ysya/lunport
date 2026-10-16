import { useId, type ReactNode } from "react";
import { Label } from "@/components/ui/label";
import { settingsSectionId } from "@/lib/settings-navigation";
import { cn } from "@/lib/utils";

/** Preference and inspector sections share the same hierarchy as workflow sections. */
export function Section({ title, description, action, children }: {
  title: string; description?: string; action?: ReactNode; children: ReactNode;
}) {
  const heading = useId();
  return <section className="settings-section" id={settingsSectionId(title)} aria-labelledby={heading} tabIndex={-1}>
    <div className="app-section-heading"><div><h2 id={heading}>{title}</h2>{description && <p>{description}</p>}</div>{action && <div className="app-page-actions">{action}</div>}</div>
    {children}
  </section>;
}

export function SettingsGroup({ children }: { children: ReactNode }) {
  return <div className="settings-group">{children}</div>;
}

/** A preference row stacks at narrow content widths instead of squeezing its label. */
export function SettingsRow({ id, label, description, mono, children }: {
  id?: string; label: string; description?: string; mono?: boolean; children: ReactNode;
}) {
  const uid = useId();
  return <div className="settings-row" role="group" aria-labelledby={`${uid}-label`} aria-describedby={description ? `${uid}-description` : undefined}>
    <div className="settings-row-copy"><Label id={`${uid}-label`} htmlFor={id} className={cn("text-sm font-normal", mono && "font-mono")}>{label}</Label>
      {description && <p id={`${uid}-description`}>{description}</p>}
    </div><div className="settings-row-control">{children}</div>
  </div>;
}
