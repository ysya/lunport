import "./transports.css";
import { useState } from "react";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/app/PageHeader";
import { FormSection } from "@/components/app/Workflow";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { iapTarget, routeLocalReason, routeSynced, type HostTransport } from "@/lib/transports";
import { GoogleAccountsTab } from "./GoogleAccountsTab";
import { PamAccessTab } from "./PamAccessTab";

/*
 * The Google Cloud page (design 2026-10-27, The Cloud section and the Google Cloud page): the Cloud section's first provider, in three
 * tabs. Accounts is gcloud on this computer and its Google accounts, with the actions that change them; Access is Privileged Access
 * Manager on its own; IAP hosts lists the hosts that connect through IAP. Nothing here edits a route: that is the host editor's
 * Connect via.
 */

/** A route the page lists, with the host that has it. */
export type ListedRoute = { route: HostTransport; host: RecordHostView };

/**
 * The routes the page lists, by host alias as the host list orders them: those whose host this computer has. A route whose host is not
 * here (deleted on another device while its route was still in the library) is listed nowhere on the page, and counted nowhere.
 */
export function listedRoutes(overview: RecordOverview): ListedRoute[] {
  const hosts = new Map(overview.hosts.map((host) => [host.id, host]));
  return (overview.transports ?? [])
    .flatMap((route) => {
      const host = hosts.get(route.host_id);
      return host ? [{ route, host }] : [];
    })
    .sort((a, b) => a.host.payload.alias.localeCompare(b.host.payload.alias) || a.host.id.localeCompare(b.host.id));
}

export type GoogleCloudTab = "accounts" | "access" | "hosts";
export const GOOGLE_CLOUD_TABS: Array<{ value: GoogleCloudTab; label: string }> = [
  { value: "accounts", label: "Accounts" },
  { value: "access", label: "Access" },
  { value: "hosts", label: "IAP hosts" },
];

/** The IAP hosts tab: each host with a route, the ones a central library keeps on this computer after the others. */
export function IapHostsTab({ overview, editHost }: { overview: RecordOverview; editHost: (id: string) => void }) {
  const listed = listedRoutes(overview);
  // In a central library a route that stays on this computer is said to, after the others, with the reason when it is that the library
  // has no room for it (R65); elsewhere every route stays on its computer, by design.
  const central = overview.central_mode === true && Boolean(overview.account);
  const apart = ({ route }: ListedRoute) => central && !routeSynced(overview, route.host_id);
  const apartLine = ({ route }: ListedRoute) =>
    routeLocalReason(overview, route.host_id) === "no_room"
      ? "Saved on this computer only: the library has no room for this route"
      : "Saved on this computer only";
  const hostRow = (entry: ListedRoute) => {
    const { route, host } = entry;
    return (
      <li key={host.id} className="app-review-row">
        <div className="min-w-0 space-y-1">
          <button
            type="button"
            className="wrap-anywhere block rounded-sm text-left text-sm font-medium outline-none hover:text-primary focus-visible:ring-3 focus-visible:ring-ring/50"
            onClick={() => editHost(host.id)}
          >
            {revealHidden(host.payload.alias)}
          </button>
          <p className="wrap-anywhere text-xs text-muted-foreground">{revealHidden(`${iapTarget(route.kind)} · ${route.kind.zone}`)}</p>
          <p className="wrap-anywhere text-xs text-muted-foreground">{revealHidden(route.kind.account ?? "gcloud's active account")}</p>
          {apart(entry) && <p className="text-xs text-warning">{apartLine(entry)}</p>}
        </div>
      </li>
    );
  };
  return (
    <FormSection title="Hosts through IAP">
      {listed.length === 0 ? (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host.
        </p>
      ) : (
        <ul className="app-review-list min-w-0">{[...listed.filter((entry) => !apart(entry)), ...listed.filter(apart)].map(hostRow)}</ul>
      )}
    </FormSection>
  );
}

export type GoogleCloudPageViewProps = {
  overview: RecordOverview;
  tab: GoogleCloudTab;
  onTab: (tab: GoogleCloudTab) => void;
  accept: (next: RecordOverview) => void;
  createIapHost: () => void;
  editHost: (id: string) => void;
};

/** The page apart from the tab it keeps: the tests call it, and find the open tab's content in what it draws. */
export function GoogleCloudPageView({ overview, tab, onTab, accept, createIapHost, editHost }: GoogleCloudPageViewProps) {
  const routes = listedRoutes(overview).map(({ route }) => route);
  return (
    <div className="transports-panel space-y-6">
      <PageHeader
        title="Google Cloud"
        description="Google accounts, access grants and IAP hosts on this computer."
        actions={
          <Button onClick={() => createIapHost()}>
            <Plus className="size-4" />
            New IAP host
          </Button>
        }
      />
      <Tabs value={tab} onValueChange={(value) => onTab(value as GoogleCloudTab)}>
        <TabsList aria-label="Google Cloud">
          {GOOGLE_CLOUD_TABS.map((entry) => (
            <TabsTrigger key={entry.value} value={entry.value}>
              {entry.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      {/* Only the open tab is drawn, so only its reads run: every read of Access is a Google call. */}
      <div role="tabpanel" aria-label={GOOGLE_CLOUD_TABS.find((entry) => entry.value === tab)?.label} className="space-y-6">
        {tab === "accounts" && <GoogleAccountsTab overview={overview} routes={routes} />}
        {tab === "access" && <PamAccessTab overview={overview} accept={accept} />}
        {tab === "hosts" && <IapHostsTab overview={overview} editHost={editHost} />}
      </div>
    </div>
  );
}

/** The tab the page was left on, for the app's run: coming back to the page opens it there. */
let lastTab: GoogleCloudTab = "accounts";

/**
 * The Google Cloud page. `accept` takes the library's overview an edit answers (a search scope saved or removed), `createIapHost` opens
 * the host editor on a new host with Google Cloud IAP chosen, and `editHost` the editor of a host.
 */
export function GoogleCloudPanel({ overview, accept, createIapHost, editHost }: { overview: RecordOverview; accept: (next: RecordOverview) => void; createIapHost: () => void; editHost: (id: string) => void }) {
  const [tab, setTab] = useState<GoogleCloudTab>(lastTab);
  return (
    <GoogleCloudPageView
      overview={overview}
      tab={tab}
      onTab={(next) => {
        lastTab = next;
        setTab(next);
      }}
      accept={accept}
      createIapHost={createIapHost}
      editHost={editHost}
    />
  );
}
