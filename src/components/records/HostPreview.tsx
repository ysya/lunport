import { useEffect, useRef } from "react";
import {
  ArrowUpRight,
  ArrowRight,
  KeyRound,
  Pencil,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { groupPath } from "./group-tree";
import { readinessLabel } from "./HostList";

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
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (window.matchMedia("(max-width: 820px)").matches)
      closeButton.current?.focus();
  }, [host.id]);
  const ready = host.readiness.kind === "ready" && !host.group_error;
  const field = (name: string, value: string, mono = false) => (
    <div>
      <dt>{name}</dt>
      <dd className={mono ? "font-mono" : undefined}>{revealHidden(value)}</dd>
    </div>
  );
  return (
    <aside className="library-host-preview" aria-label="Host details">
      <header>
        <span>Connection details</span>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Close details"
          ref={closeButton}
          onClick={close}
        >
          <X className="size-4" />
        </Button>
      </header>
      <div className="library-preview-scroll">
        <div className="library-preview-icon">
          <Server className="size-7" />
        </div>
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
        {payload.host_key && (
          <div className="library-preview-section">
            <h3>
              <ShieldCheck className="size-3.5" />
              Host key saved
            </h3>
            <p className="text-xs text-muted-foreground">
              The server’s identity is checked again when connecting.
            </p>
          </div>
        )}
      </div>
      <footer>Use Quick connect to switch hosts</footer>
    </aside>
  );
}
