import { Button } from "@/components/ui/button";
import type { CatalogCollision, CatalogReview } from "@/lib/central-sync";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { iapTarget } from "@/lib/transports";
import { tunnelRoute } from "@/lib/tunnels";

/* The shared Catalog's row in Central conflicts (design 2026-10-27, Collisions: the review): the items both devices changed, in plain
   words. Every other change of both devices merges on its own; a choice settles only these. */

export const CATALOG_TITLE = "Tunnels, routes and collections";
const COLLIDING = "Another device changed the same items at the same time. When you choose, Lunport keeps every other change from both devices. Until then, changes to tunnels, routes and collections wait on this device.";
const WAITING = "Lunport combines both devices’ changes on the next sync.";
export const CATALOG_CHOICE_NOTE = "Every other change from both devices stays. Previous versions are kept in an encrypted local recovery snapshot on this device.";
export const catalogChoiceTitle = (choice: "local" | "remote") =>
  choice === "local" ? "Keep this device’s versions of these items?" : "Use the synced versions of these items?";

const quoted = (name: string) => `“${revealHidden(name)}”`;
const hostName = (id: string, overview?: RecordOverview) => overview?.hosts.find((host) => host.id === id)?.payload.alias ?? id;
const groupName = (id: string, overview?: RecordOverview) => overview?.groups.find((group) => group.id === id)?.payload.name ?? id;
const collectionName = (id: string, overview?: RecordOverview) => overview?.spaces.find((space) => space.id === id)?.name ?? id;
const key = (item: CatalogCollision) =>
  item.kind === "route" ? `route:${item.host_id}` : item.kind === "group_order" ? `group_order:${item.scope.kind === "space" ? item.scope.space_id : ""}` : `${item.kind}:${item.id}`;

/** The item, named by this device's version when it has one, else by the synced one; an unknown host or collection by its id. */
export function collisionLabel(item: CatalogCollision, overview?: RecordOverview): string {
  switch (item.kind) {
    case "tunnel": return `Tunnel ${quoted((item.local ?? item.remote)?.name ?? item.id)}`;
    case "route": return `Google Cloud route of ${quoted(hostName(item.host_id, overview))}`;
    case "collection": return `Name of collection ${quoted(item.local ?? item.remote ?? collectionName(item.id, overview))}`;
    case "group_order": return item.scope.kind === "space" ? `Group order in ${quoted(collectionName(item.scope.space_id, overview))}` : "Group order";
  }
}

/** One side's version of the item, or "Removed". */
export function collisionValue(item: CatalogCollision, side: "local" | "remote", overview?: RecordOverview): string {
  switch (item.kind) {
    case "tunnel": {
      const rule = item[side], other = item[side === "local" ? "remote" : "local"];
      if (!rule) return "Removed";
      const name = other && other.name !== rule.name ? `${quoted(rule.name)} · ` : "";
      return `${name}${revealHidden(tunnelRoute(rule))} through ${revealHidden(hostName(rule.host_id, overview))}`;
    }
    case "route": {
      const route = item[side];
      if (!route) return "Removed";
      const kind = route.kind;
      return [
        `${revealHidden(iapTarget(kind))} · ${revealHidden(kind.zone)}`,
        kind.account && `account ${revealHidden(kind.account)}`,
        kind.os_login && "OS Login",
        kind.pam && `PAM ${kind.pam.entitlements.map(revealHidden).join(", ")}`,
      ].filter(Boolean).join(", ");
    }
    case "collection": {
      const name = item[side];
      return name === null ? "Removed" : revealHidden(name);
    }
    case "group_order": {
      const ids = item[side];
      return ids === null ? "Removed" : ids.map((id) => revealHidden(groupName(id, overview))).join(", ");
    }
  }
}

export function CatalogConflictView({ review, overview, disabled, choose }: { review: CatalogReview; overview?: RecordOverview; disabled: boolean; choose: (choice: "local" | "remote") => void }) {
  if (!review.items.length) return <p className="text-sm text-muted-foreground">{review.over ?? WAITING}</p>;
  return <div className="space-y-2">
    <p className="text-sm">{COLLIDING}</p>
    <div className="max-h-72 overflow-auto rounded-md border"><table className="w-full table-fixed text-left text-xs" aria-label="Items both devices changed"><thead><tr className="border-b bg-muted"><th className="w-1/4 p-2">Item</th><th className="p-2">This device</th><th className="p-2">Synced version</th></tr></thead>
      <tbody>{review.items.map(item => <tr key={key(item)} className="border-b last:border-0"><th className="p-2 align-top font-medium break-words">{collisionLabel(item, overview)}</th><td className="p-2 align-top whitespace-pre-wrap break-all">{collisionValue(item, "local", overview)}</td><td className="p-2 align-top whitespace-pre-wrap break-all">{collisionValue(item, "remote", overview)}</td></tr>)}</tbody></table></div>
    {review.over && <p role="alert" className="text-sm">{review.over}</p>}
    <div className="flex flex-wrap gap-2">
      {review.can_local && <Button size="sm" variant="outline" disabled={disabled} onClick={() => choose("local")}>Keep this device’s versions…</Button>}
      {review.can_remote && <Button size="sm" variant="outline" disabled={disabled} onClick={() => choose("remote")}>Use the synced versions…</Button>}
    </div>
  </div>;
}
