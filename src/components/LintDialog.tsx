import { useMemo, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  CircleAlert,
  TriangleAlert,
  Info,
} from "lucide-react";

import type { LintIssue } from "@/bindings/LintIssue";
import { useLint } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { basename, cn } from "@/lib/utils";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const SEVERITY_ORDER: Record<string, number> = { error: 0, warning: 1, info: 2 };
const SEVERITY_LABEL: Record<string, string> = {
  error: "Errors",
  warning: "Warnings",
  info: "Info",
};

function severityIcon(sev: string) {
  if (sev === "error") return <CircleAlert className="size-4 text-destructive" />;
  if (sev === "warning")
    return <TriangleAlert className="size-4 text-amber-600 dark:text-amber-400" />;
  return <Info className="size-4 text-muted-foreground" />;
}

/** Toolbar lint indicator + a dialog listing issues grouped by severity. */
export function LintDialog() {
  const [open, setOpen] = useState(false);
  const { data } = useLint();
  const issues = data ?? [];
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);

  const errorCount = issues.filter((i) => i.severity === "error").length;
  const warningCount = issues.filter((i) => i.severity === "warning").length;
  const total = issues.length;

  const grouped = useMemo(() => {
    const order = [...issues].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
    );
    const map = new Map<string, LintIssue[]>();
    for (const i of order) {
      const arr = map.get(i.severity) ?? [];
      arr.push(i);
      map.set(i.severity, arr);
    }
    return map;
  }, [issues]);

  const tooltip =
    total === 0
      ? "Config lint — all clear"
      : `Config lint — ${errorCount} error${errorCount === 1 ? "" : "s"}, ${warningCount} warning${warningCount === 1 ? "" : "s"}`;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DialogTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="relative size-7"
              aria-label={tooltip}
            >
              {total === 0 ? (
                <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <ShieldAlert
                  className={cn(
                    "size-4",
                    errorCount > 0
                      ? "text-destructive"
                      : "text-amber-600 dark:text-amber-400",
                  )}
                />
              )}
              {total > 0 && (
                <span
                  className={cn(
                    "absolute -top-0.5 -right-0.5 flex h-3.5 min-w-3.5 items-center justify-center rounded-full px-1 text-[0.5625rem] font-semibold tabular-nums text-white",
                    errorCount > 0 ? "bg-destructive" : "bg-amber-500",
                  )}
                  aria-hidden
                >
                  {total > 99 ? "99+" : total}
                </span>
              )}
            </Button>
          </DialogTrigger>
        </TooltipTrigger>
        <TooltipContent>{tooltip}</TooltipContent>
      </Tooltip>

      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Config lint</DialogTitle>
          <DialogDescription>
            {total === 0
              ? "No issues found across your SSH config."
              : `${total} issue${total === 1 ? "" : "s"} across your SSH config.`}
          </DialogDescription>
        </DialogHeader>

        {total === 0 ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center select-none">
            <ShieldCheck className="size-8 text-emerald-600 dark:text-emerald-400" />
            <p className="text-sm text-muted-foreground">All clear</p>
          </div>
        ) : (
          <div className="-mx-1 max-h-[60vh] space-y-4 overflow-y-auto px-1">
            {[...grouped.entries()].map(([severity, list]) => (
              <div key={severity}>
                <span className="section-label">
                  {SEVERITY_LABEL[severity] ?? severity}
                </span>
                <div className="settings-group">
                  {list.map((issue, i) => (
                    <LintRow
                      key={`${severity}-${i}`}
                      issue={issue}
                      onSelect={() => {
                        if (issue.alias) {
                          setSelectedAlias(issue.alias);
                          setOpen(false);
                        }
                      }}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function LintRow({
  issue,
  onSelect,
}: {
  issue: LintIssue;
  onSelect: () => void;
}) {
  const clickable = !!issue.alias;
  const Row = clickable ? "button" : "div";
  return (
    <Row
      {...(clickable ? { type: "button" as const, onClick: onSelect } : {})}
      className={cn(
        "flex w-full items-start gap-2.5 px-3 py-2 text-left",
        clickable && "hover:bg-muted/60",
      )}
    >
      <span className="mt-0.5 shrink-0">{severityIcon(issue.severity)}</span>
      <span className="min-w-0 flex-1 space-y-0.5">
        <span className="block text-sm">{issue.message}</span>
        <span className="flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
          <span className="font-mono" title={issue.file}>
            {basename(issue.file)}
          </span>
          {issue.alias && (
            <>
              <span className="text-muted-foreground/40">·</span>
              <span className="font-mono">{issue.alias}</span>
            </>
          )}
          {issue.keyword && (
            <>
              <span className="text-muted-foreground/40">·</span>
              <span className="font-mono">{issue.keyword}</span>
            </>
          )}
        </span>
      </span>
    </Row>
  );
}

export default LintDialog;
