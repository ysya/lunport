import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  ArrowRight,
  Cloud,
  KeyRound,
  LockKeyhole,
  Pencil,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import {
  grantHeld,
  grantLine,
  grantMemoryFor,
  iapTarget,
  pamStatusQuery,
  transportFor,
  type GrantMemoryView,
  type HostTransport,
} from "@/lib/transports";
import { GrantRequestDialog } from "./GrantRequestDialog";
import { groupPath } from "./group-tree";
import { readinessLabel } from "./HostList";
import { DetailPane } from "./DetailPane";
import { KnownHostsManager } from "./KnownHostsManager";
import { ConnectionCheck } from "./ConnectionCheck";

/**
 * A route's Privileged Access Manager grant as it stands now (design 2026-10-26, Host list and details): read when the pane opens and
 * every minute, with Request grant…, which is off while a grant is active or activating. Mount it for one host at a time (key it).
 */
function AccessGrant({ transport, alias, memory }: { transport: HostTransport; alias: string; memory: GrantMemoryView | null }) {
  const [requesting, setRequesting] = useState(false);
  const client = useQueryClient();
  const query = pamStatusQuery(transport.host_id);
  const read = useQuery(query);
  // The latest read failing speaks for the grant, whatever an earlier read found.
  const status = read.isError ? null : (read.data ?? null);
  const held = grantHeld(status);
  return (
    <div className="library-preview-section">
      <h3>
        <LockKeyhole className="size-3.5" />
        Access grant
      </h3>
      <p className={held ? "text-primary" : undefined}>
        {revealHidden(status ? grantLine(status) : read.isError ? errorMessage(read.error) : "Checking the grant…")}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">Required: {revealHidden(transport.kind.pam?.entitlements.join(", ") ?? "")}</p>
      <Button variant="outline" size="sm" className="mt-3" disabled={held} onClick={() => setRequesting(true)}>
        Request grant…
      </Button>
      {requesting && (
        <GrantRequestDialog
          transport={transport}
          alias={alias}
          memory={memory}
          onClose={() => setRequesting(false)}
          onRequested={(view) => client.setQueryData(query.queryKey, view)}
        />
      )}
    </div>
  );
}

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
  const transport = transportFor(overview, host.id);
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
          {transport ? (
            <>
              <Cloud className="mr-1.5 inline size-3.5 align-[-2px]" aria-hidden="true" />
              {revealHidden(iapTarget(transport.kind))}
            </>
          ) : (
            revealHidden(payload.hostname)
          )}
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
            {transport ? (
              <>
                {field("Connect via", "Google Cloud IAP")}
                {field("Instance", `${transport.kind.instance} · ${transport.kind.zone}`, true)}
                {field("Project", transport.kind.project, true)}
                {field("Google account", transport.kind.account ?? "gcloud's active account")}
                {(transport.kind.os_login || transport.kind.pam) &&
                  field("Checks", [transport.kind.os_login ? "OS Login" : null, transport.kind.pam ? "PAM grant" : null].filter(Boolean).join(" · "))}
              </>
            ) : (
              field("Address", payload.hostname, true)
            )}
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
        {transport?.kind.pam && (
          <AccessGrant key={host.id} transport={transport} alias={host.payload.alias} memory={grantMemoryFor(overview, host.id)} />
        )}
        <ConnectionCheck host={host} transport={transport} />
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
