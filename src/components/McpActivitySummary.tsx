import { Bot } from "lucide-react";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import { activityResult, activityTitle, dayLabel, titleText } from "@/lib/mcp-activity";
import { revealHidden } from "@/lib/reveal-hidden";
import { Button } from "@/components/ui/button";
import { entryTime, recordedDate } from "@/components/records/ActivityEntry";

/** The latest AI entry, in a line: when, what and what became of it. */
function latestLine(latest: McpAuditEntry, now: number): string {
  const result = activityResult(latest);
  const what = `${revealHidden(titleText(activityTitle(latest, result.kind)))} · ${result.label}`;
  const ms = entryTime(latest);
  const date = recordedDate(ms);
  if (!date) return `Last: ${what}`;
  const day = dayLabel(ms, now);
  const when = day === "Today" || day === "Yesterday" ? day.toLowerCase() : day;
  return `Last: ${when} ${date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })} · ${what}`;
}

/** The AI activity in Settings: the latest entry, and the way to the AI activity page. */
export function McpActivitySummary({ latest, now, open }: { latest: McpAuditEntry | undefined; now: number; open?: () => void }) {
  return <div className="settings-row">
    <div className="settings-row-copy flex min-w-0 items-start gap-2">
      <Bot className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="min-w-0 break-words text-sm leading-normal">{latest ? latestLine(latest, now) : "No AI activity yet"}</div>
    </div>
    {open && <div className="settings-row-control">
      <Button variant="outline" size="sm" onClick={open}>Open AI activity</Button>
    </div>}
  </div>;
}
