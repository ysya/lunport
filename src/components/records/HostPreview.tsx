import {
  ArrowUpRight,
  ArrowRight,
  KeyRound,
  Pencil,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { groupPath } from "./group-tree";
import { readinessLabel } from "./HostList";
import { DetailPane } from "./DetailPane";
import { KnownHostsManager } from "./KnownHostsManager";
import { ConnectionCheck } from "./ConnectionCheck";

export function HostPreview({
  host,
  overview,
  connect,
  edit,
  close,
  busy,
}: {
  host: RecordHostView;
  overview: RecordOverview;
  connect: () => void;
  edit: () => void;
  close: () => void;
  busy: boolean;
}) {
  const payload = host.effective_payload;
  const ready = host.readiness.kind === "ready" && !host.group_error;
  const field = (name: string, value: string, mono = false) => (
    <div>
      <dt>{name}</dt>
      <dd className={mono ? "font-mono" : undefined}>{revealHidden(value)}</dd>
    </div>
  );
  return (
    <DetailPane itemId={host.id} title="Connection details" label="Host details" close={close}>
        <h2>{revealHidden(host.payload.alias)}</h2>
        <p className="library-preview-address">
          {revealHidden(payload.hostname)}
        </p>
        <div className="library-preview-buttons">
          <Button disabled={!ready || busy} onClick={connect}>
            <ArrowUpRight className="size-4" />
            {busy ? "Opening…" : "Connect"}
          </Button>
          <Button variant="outline" disabled={busy} onClick={edit}>
            <Pencil className="size-3.5" />
            Edit
          </Button>
        </div>
        {!ready && (
          <div role="status" className="library-preview-warning">
            <strong>
              {host.group_error
                ? "Needs review"
                : readinessLabel[host.readiness.kind]}
            </strong>
            <p>
              {host.group_error
                ? revealHidden(host.group_error)
                : "Review this host’s settings and key before connecting."}
            </p>
            <button type="button" disabled={busy} onClick={edit}>
              Review settings <ArrowRight className="size-3.5" />
            </button>
          </div>
        )}
        <div className="library-preview-section">
          <h3>Connection</h3>
          <dl>
            {field("Address", payload.hostname, true)}
            {field("Username", payload.user || "Terminal default", true)}
            {field("Port", String(payload.port), true)}
            {field(
              "Group",
              host.payload.group_id
                ? groupPath(overview, host.payload.group_id, host.scope)
                : "Ungrouped",
            )}
          </dl>
        </div>
        <div className="library-preview-section">
          <h3>
            <KeyRound className="size-3.5" />
            Authentication
          </h3>
          <p>
            {payload.auth === "key"
              ? "SSH key"
              : payload.auth === "interactive"
                ? "Keyboard interactive"
                : "Password"}
          </p>
          {payload.key_id && (
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
              {revealHidden(
                overview.keys.find((key) => key.id === payload.key_id)?.public
                  ?.name ?? payload.key_id,
              )}
            </p>
          )}
        </div>
        <ConnectionCheck host={host} />
        {!!host.payload.tags.length && (
          <div className="library-preview-section">
            <h3>Tags</h3>
            <div className="library-preview-tags">
              {host.payload.tags.map((tag) => (
                <span key={tag}>{revealHidden(tag)}</span>
              ))}
            </div>
          </div>
        )}
        {host.payload.notes && (
          <div className="library-preview-section">
            <h3>Notes</h3>
            <p className="whitespace-pre-wrap">
              {revealHidden(host.payload.notes)}
            </p>
          </div>
        )}
        {(
          <div className="library-preview-section">
            <h3>
              <ShieldCheck className="size-3.5" />
              Server identity
            </h3>
            <p className="text-xs text-muted-foreground">
              {payload.host_key ? "The saved identity is checked again when connecting." : "No server key has been verified yet."}
            </p>
            <KnownHostsManager overview={overview} hostId={host.id} trigger={<Button variant="outline" size="sm" className="mt-3">Manage identity…</Button>} />
          </div>
        )}
    </DetailPane>
  );
}
