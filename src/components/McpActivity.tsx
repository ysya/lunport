import { Ban, CheckCircle2, CircleHelp, CircleX, Clock3, ShieldX, TriangleAlert } from "lucide-react";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import { auditRows } from "@/lib/mcp-audit-rows";
import { revealHidden } from "@/lib/sync-approvals";
import { Badge } from "@/components/ui/badge";
import { McpAttribution } from "./McpAttribution";

const results = {
  succeeded: { label: "Succeeded", icon: CheckCircle2, color: "border-success/25 bg-success/10 text-success" },
  failed: { label: "Failed", icon: CircleX, color: "border-destructive/25 bg-destructive/10 text-destructive" },
  canceled: { label: "Canceled", icon: Ban, color: "text-muted-foreground" },
  denied: { label: "Denied", icon: ShieldX, color: "border-warning/25 bg-warning/10 text-warning" },
  timed_out: { label: "Timed out", icon: Clock3, color: "border-warning/25 bg-warning/10 text-warning" },
  truncated: { label: "Output limit reached", icon: TriangleAlert, color: "border-warning/25 bg-warning/10 text-warning" },
  disconnected: { label: "Connection lost", icon: TriangleAlert, color: "border-warning/25 bg-warning/10 text-warning" },
  signaled: { label: "Stopped by signal", icon: TriangleAlert, color: "border-warning/25 bg-warning/10 text-warning" },
  unknown: { label: "Result unavailable", icon: CircleHelp, color: "text-muted-foreground" },
};

const managementResults: Record<string, { label: string; succeeded: boolean }> = {
  host_created: { label: "Host created", succeeded: true },
  host_updated: { label: "Host updated", succeeded: true },
  host_key_verified: { label: "Fingerprint verified", succeeded: true },
  host_creation_not_completed: { label: "Host creation not completed", succeeded: false },
  host_update_not_completed: { label: "Host update not completed", succeeded: false },
  host_key_not_verified: { label: "Fingerprint not verified", succeeded: false },
  transport_set: { label: "Route saved", succeeded: true },
  transport_removed: { label: "Route removed", succeeded: true },
  transport_not_set: { label: "Route not saved", succeeded: false },
  transport_not_removed: { label: "Route not removed", succeeded: false },
};

function activityResult(entry: McpAuditEntry) {
  const management = managementResults[entry.outcome];
  if (management) return { ...results[management.succeeded ? "succeeded" : "denied"], label: management.label };
  if (entry.outcome === "canceled" || entry.outcome === "denied" || entry.outcome === "timed_out") return results[entry.outcome];
  if (entry.outcome === "failed" || entry.outcome === "error") return results.failed;
  // Permission to execute is separate from the command's actual termination.
  if (entry.outcome === "allowed") {
    if (entry.ended === "canceled" || entry.ended === "timed_out" || entry.ended === "truncated" || entry.ended === "disconnected" || entry.ended === "signaled") return results[entry.ended];
    if (entry.signal) return results.signaled;
    if (entry.exit_code !== null && entry.exit_code !== 0) return { ...results.failed, label: `Failed · exit ${entry.exit_code}` };
    if (entry.ended === "exited" && entry.exit_code === 0) return results.succeeded;
  }
  return results.unknown;
}

function recordedDate(ms: number) {
  const date = new Date(ms);
  return Number.isFinite(ms) && ms > 0 && Number.isFinite(date.getTime()) ? date : null;
}

function McpAuditTimes({ requested, completed }: { requested: number; completed: number }) {
  return <div className="space-y-1 text-xs tabular-nums text-muted-foreground">
    {[{ label: "Requested", ms: requested }, { label: "Completed", ms: completed }].map(({ label, ms }) => {
      const date = recordedDate(ms);
      return date && <p key={label}>{label}: <time dateTime={date.toISOString()}>
        {date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "long" })}
      </time></p>;
    })}
  </div>;
}

export function McpActivity({ entries }: { entries: McpAuditEntry[] }) {
  if (entries.length === 0) return <p className="px-3 py-3 text-sm text-muted-foreground">No AI activity yet.</p>;
  return <ol aria-label="Recent AI activity" className="divide-y">
    {auditRows(entries).map(({ entry, key }) => {
      const result = activityResult(entry);
      const Icon = result.icon;
      const completed = recordedDate(entry.completed_at_ms);
      const date = completed ?? recordedDate(entry.at_ms);
      const management = entry.outcome.startsWith("host_") || entry.outcome.startsWith("transport_");
      return <li key={key} className="min-w-0 space-y-2.5 px-3 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="min-w-0 break-all text-sm font-medium">{revealHidden(entry.alias)}</span>
          <Badge variant="outline" className={result.color}><Icon aria-hidden="true" />{result.label}</Badge>
        </div>
        {entry.command ? <pre className="rounded-md bg-muted/50 px-2.5 py-2 font-mono text-xs whitespace-pre-wrap break-all select-text"><code className="line-clamp-2">{revealHidden(entry.command)}</code></pre>
          : <p className="text-xs text-muted-foreground">{management ? "Connection management · No remote command" : "Command not recorded"}</p>}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span>{entry.mode === "auto_log" ? "Auto-log mode" : "Ask mode"}</span>
          {date ? <time dateTime={date.toISOString()} title={`${completed ? "Completed" : "Requested"}: ${date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "long" })}`}>
            {date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
          </time> : <span>Time unavailable</span>}
        </div>
        <details className="text-xs text-muted-foreground">
          <summary className="w-fit cursor-pointer rounded-sm focus-visible:outline-2 focus-visible:outline-ring">Details<span className="sr-only"> for {revealHidden(entry.alias)}</span></summary>
          <div className="mt-2 space-y-2 border-l-2 pl-3 select-text">
            {entry.command && <pre className="max-h-48 overflow-auto font-mono text-xs whitespace-pre-wrap break-all"><code>{revealHidden(entry.command)}</code></pre>}
            {entry.detail && <p className="break-words">{revealHidden(entry.detail)}</p>}
            <McpAuditTimes requested={entry.at_ms} completed={entry.completed_at_ms} />
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 break-all">
              <dt>Request ID</dt><dd className="font-mono">{revealHidden(entry.id)}</dd>
              <dt>Host ID</dt><dd className="font-mono">{entry.host_id ? revealHidden(entry.host_id) : "Not recorded"}</dd>
              <dt>Recorded outcome</dt><dd>{revealHidden(entry.outcome)}</dd>
              {!management && <>
                <dt>Termination</dt><dd>{entry.ended ? revealHidden(entry.ended) : "Not recorded"}</dd>
                <dt>Exit code</dt><dd>{entry.exit_code ?? "Not reported"}</dd>
                {entry.signal && <><dt>Signal</dt><dd>{revealHidden(entry.signal)}</dd></>}
              </>}
              {entry.client && <><dt>Protocol client</dt><dd>{revealHidden(entry.client)}</dd></>}
            </dl>
            <McpAttribution requestedBy={entry.requested_by} requesterId={entry.requester_id} clientInfo={entry.client_info} />
          </div>
        </details>
      </li>;
    })}
  </ol>;
}
