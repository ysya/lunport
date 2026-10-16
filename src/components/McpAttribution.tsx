import type { McpClientInfo } from "@/bindings/McpClientInfo";
import { revealHidden } from "@/lib/sync-approvals";

/** clientInfo is never an identity claim; limit again at the app display boundary. */
const clientText = (value: string | null) =>
  value ? revealHidden([...value].slice(0, 100).join("")) : null;

export function McpAttribution({ requestedBy, requesterId, clientInfo }: {
  requestedBy: string[];
  requesterId: string | null;
  clientInfo: McpClientInfo;
}) {
  return (
    <div className="space-y-1 break-all text-xs text-muted-foreground">
      <p>
        Observed requester: {requestedBy.length ? requestedBy.map(revealHidden).join(" → ") : "Unknown"}
        {requesterId ? ` · ${revealHidden(requesterId)}` : ""}
      </p>
      <p>
        Self-reported client: {[clientText(clientInfo.title), clientText(clientInfo.name), clientText(clientInfo.version)].filter(Boolean).join(" · ") || "Unknown"}
      </p>
    </div>
  );
}
