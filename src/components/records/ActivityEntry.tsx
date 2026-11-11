import { useId, type MouseEvent } from "react";
import { Ban, CheckCircle2, ChevronDown, CircleHelp, CircleX, Copy, Server, TriangleAlert } from "lucide-react";
import { toast } from "sonner";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import type { RecordHostView } from "@/lib/records";
import {
  actionKind, activityResult, activityTitle, durationLabel, observedClient, resultSentence, reviewLabel, reviewSentence,
  type ActivityKind,
} from "@/lib/mcp-activity";
import { copyText } from "@/lib/clipboard";
import { revealHidden } from "@/lib/reveal-hidden";
import { cn, errorMessage } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { McpAttribution } from "@/components/McpAttribution";

const KINDS: Record<ActivityKind, { icon: typeof CheckCircle2; icon_color: string; badge: string }> = {
  succeeded: { icon: CheckCircle2, icon_color: "text-success", badge: "border-success/25 bg-success/10 text-success" },
  failed: { icon: CircleX, icon_color: "text-destructive", badge: "border-destructive/25 bg-destructive/10 text-destructive" },
  not_run: { icon: Ban, icon_color: "text-warning", badge: "border-warning/25 bg-warning/10 text-warning" },
  error: { icon: TriangleAlert, icon_color: "text-destructive", badge: "border-destructive/25 bg-destructive/10 text-destructive" },
  unknown: { icon: CircleHelp, icon_color: "text-muted-foreground", badge: "text-muted-foreground" },
};

const HOST_GONE = "This host is no longer in your library.";

/** A recorded time, or `null` when it cannot be one (never a made-up date). */
export function recordedDate(ms: number): Date | null {
  const date = new Date(ms);
  return Number.isFinite(ms) && ms > 0 && Number.isFinite(date.getTime()) ? date : null;
}

/** When the entry happened, as the page orders and groups it: its completion, else its request. */
export function entryTime(entry: McpAuditEntry): number {
  return recordedDate(entry.completed_at_ms) ? entry.completed_at_ms : entry.at_ms;
}

function RecordedTime({ ms }: { ms: number }) {
  const date = recordedDate(ms);
  if (!date) return <>Time unavailable</>;
  return <time dateTime={date.toISOString()}>
    {`${date.toLocaleDateString(undefined, { dateStyle: "medium" })} ${date.toLocaleTimeString(undefined, { timeStyle: "long" })}`}
  </time>;
}

/** One AI request on the AI activity page: what it was, what became of it and who asked; its details when expanded. */
export function ActivityEntry({ entry, host, expanded, onToggle, showHost }: {
  entry: McpAuditEntry;
  host: RecordHostView | null;
  expanded: boolean;
  onToggle: () => void;
  showHost: (hostId: string) => void;
}) {
  const detailsId = useId();
  const result = activityResult(entry);
  const title = activityTitle(entry, result.kind);
  const kind = KINDS[result.kind];
  const Icon = kind.icon;
  const time = recordedDate(entryTime(entry));
  const meta = [
    revealHidden(observedClient(entry)),
    reviewLabel(entry),
    time?.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    durationLabel(entry),
  ].filter(Boolean).join(" · ");
  const reason = entry.stop?.reason;
  const action = actionKind(entry);
  const command = action === "command";
  const transfer = action === "transfer";
  // The header toggles the details, unless the click selected text or was on the host's button.
  const toggleFromHeader = (event: MouseEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    if (window.getSelection()?.toString()) return;
    onToggle();
  };
  const copy = () => {
    copyText(entry.command).then(
      () => toast.success(transfer ? "Transfer paths copied" : "Command copied"),
      (error: unknown) => toast.error(transfer ? "Could not copy transfer paths" : "Could not copy the command", { description: revealHidden(errorMessage(error)) }),
    );
  };
  return <li className="min-w-0 rounded-lg border bg-card">
    <div className="flex cursor-pointer items-start gap-3 px-3 py-2.5" onClick={toggleFromHeader}>
      <Icon className={cn("mt-0.5 size-4 shrink-0", kind.icon_color)} aria-hidden="true" />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="break-words text-sm font-medium">
          {revealHidden(title.before)}
          {host
            ? <button type="button" className="rounded-sm underline-offset-2 hover:text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => showHost(host.id)}>{revealHidden(title.host)}</button>
            : revealHidden(title.host)}
          {revealHidden(title.after)}
        </p>
        {entry.command && <p className="truncate font-mono text-xs text-muted-foreground" title={revealHidden(entry.command)}>{revealHidden(entry.command)}</p>}
        {reason && <p className="break-words text-xs text-muted-foreground">{revealHidden(reason)}</p>}
        <p className="break-words text-xs text-muted-foreground">{meta}</p>
      </div>
      <Badge variant="outline" className={cn("shrink-0", kind.badge)}>{result.label}</Badge>
      <button
        type="button"
        className="-m-1 shrink-0 rounded-sm p-1 text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
        aria-expanded={expanded}
        aria-controls={detailsId}
        aria-label={expanded ? "Hide details" : "Show details"}
        onClick={onToggle}
      >
        <ChevronDown className={cn("size-4 transition-transform", expanded && "rotate-180")} aria-hidden="true" />
      </button>
    </div>
    {expanded && <div id={detailsId} className="space-y-3 border-t px-3 py-3 text-xs select-text">
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5">
        {entry.command && <><dt className="text-muted-foreground">{transfer ? "Transfer paths" : "Command"}</dt>
          <dd><pre className="max-h-48 overflow-auto font-mono whitespace-pre-wrap break-all"><code>{revealHidden(entry.command)}</code></pre></dd></>}
        <dt className="text-muted-foreground">Result</dt><dd>{revealHidden(resultSentence(entry, result))}</dd>
        <dt className="text-muted-foreground">Review</dt><dd>{reviewSentence(entry)}</dd>
        {entry.at_ms > 0 && <><dt className="text-muted-foreground">Requested</dt><dd className="tabular-nums"><RecordedTime ms={entry.at_ms} /></dd></>}
        <dt className="text-muted-foreground">Completed</dt><dd className="tabular-nums"><RecordedTime ms={entry.completed_at_ms} /></dd>
        <dt className="text-muted-foreground">Request ID</dt><dd className="break-all font-mono">{revealHidden(entry.id)}</dd>
        <dt className="text-muted-foreground">Host ID</dt><dd className="break-all font-mono">{entry.host_id ? revealHidden(entry.host_id) : "Not recorded"}</dd>
        {command && <>
          <dt className="text-muted-foreground">Termination</dt><dd>{entry.ended ? revealHidden(entry.ended) : "Not recorded"}</dd>
          <dt className="text-muted-foreground">Exit code</dt><dd>{entry.exit_code ?? "Not reported"}</dd>
          {entry.signal && <><dt className="text-muted-foreground">Signal</dt><dd>{revealHidden(entry.signal)}</dd></>}
        </>}
        <dt className="text-muted-foreground">Recorded outcome</dt><dd className="break-all">{revealHidden(entry.outcome)}</dd>
      </dl>
      <McpAttribution requestedBy={entry.requested_by} requesterId={entry.requester_id} clientInfo={entry.client_info} />
      <div className="flex flex-wrap gap-2">
        {host
          ? <Button size="sm" variant="outline" onClick={() => showHost(host.id)}><Server className="size-3.5" />Show host</Button>
          : <span title={HOST_GONE}>
            <Button size="sm" variant="outline" disabled aria-describedby={`${detailsId}-gone`}><Server className="size-3.5" />Show host</Button>
            <span id={`${detailsId}-gone`} className="sr-only">{HOST_GONE}</span>
          </span>}
        {entry.command && <Button size="sm" variant="outline" onClick={copy}><Copy className="size-3.5" />{transfer ? "Copy transfer paths" : "Copy command"}</Button>}
      </div>
    </div>}
  </li>;
}
