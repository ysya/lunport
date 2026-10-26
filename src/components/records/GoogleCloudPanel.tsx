import "./transports.css";
import { useState } from "react";
import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { FormSection } from "@/components/app/Workflow";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import {
  gcloudAccountsQuery,
  grantMemoryFor,
  grantStateOrMessage,
  iapTarget,
  pamGrantsKey,
  pamGrantsQuery,
  routeSynced,
  type GcloudAccountsView,
  type GrantMemoryView,
  type HostTransport,
  type PamGrantView,
  type PamStatusView,
} from "@/lib/transports";
import { cn } from "@/lib/utils";
import { GrantRequestDialog } from "./GrantRequestDialog";

/*
 * The Google Cloud page (design 2026-10-26, "The Google Cloud page"): Google sign-in on this computer, the Privileged Access Manager
 * grants the routes need, and the hosts that connect through IAP. Nothing here edits a route: that is the host editor's Connect via.
 */

/** A route the page lists, with the host that has it. */
type ListedRoute = { route: HostTransport; host: RecordHostView };

/**
 * The routes the page lists, by host alias as the host list orders them: those whose host this computer has. A route whose host is not
 * here (deleted on another device while its route was still in the library) is listed nowhere on the page, and counted nowhere.
 */
function listedRoutes(overview: RecordOverview): ListedRoute[] {
  const hosts = new Map(overview.hosts.map((host) => [host.id, host]));
  return (overview.transports ?? [])
    .flatMap((route) => {
      const host = hosts.get(route.host_id);
      return host ? [{ route, host }] : [];
    })
    .sort((a, b) => a.host.payload.alias.localeCompare(b.host.payload.alias) || a.host.id.localeCompare(b.host.id));
}

/** Whether a route the page lists requires a grant: the page then has Access grants to show, and reads them. */
const requiresGrant = (listed: ListedRoute[]) => listed.some(({ route }) => route.kind.pam !== null);

/** What a read has to show: its answer, or the sentence why there is none; neither while the first answer is awaited. */
type Reading<T> = { data: T | undefined; error: string | null };

/** The latest read speaks: one that failed shows its sentence, whatever an earlier read found, since that may be gone by now. */
const reading = <T,>(query: UseQueryResult<T>): Reading<T> =>
  query.isError ? { data: undefined, error: errorMessage(query.error) } : { data: query.data, error: null };

/** How many routes use an account, in words. */
const routeCount = (count: number) => (count === 0 ? "No routes" : count === 1 ? "1 route" : `${count} routes`);

/** gcloud's sign-in as a command to run, in code: for `account` when one is named. */
const loginCommand = (account?: string) => (
  <code className="select-all font-mono">gcloud auth login{account === undefined ? "" : ` ${revealHidden(account)}`}</code>
);

/** The state of a sign-in as the page words it: gcloud's three, and the one only a route knows of. */
type SignIn = "signed_in" | "expired" | "unknown" | "missing";
const signInLabel: Record<SignIn, string> = {
  signed_in: "Signed in",
  expired: "Sign-in expired",
  unknown: "Could not be checked",
  missing: "Not signed in on this computer",
};
const signInDot: Record<SignIn, string> = {
  signed_in: "bg-success",
  expired: "bg-warning",
  unknown: "bg-muted-foreground/50",
  missing: "bg-warning",
};

type SignInRow = { account: string; signIn: SignIn; message: string | null; active: boolean; routes: number };

/**
 * The rows of Google sign-in: each account gcloud holds credentials for, then each account only a route names (this computer has no
 * sign-in for it), in the order of their names. A route counts for the account it names, and a route that names none for gcloud's
 * active account.
 */
function signInRows(gcloud: GcloudAccountsView, listed: ListedRoute[]): SignInRow[] {
  const routesOf = (account: string) => listed.filter(({ route }) => (route.kind.account ?? gcloud.active) === account).length;
  const held = new Set(gcloud.accounts.map((entry) => entry.account));
  const named = [...new Set(listed.flatMap(({ route }) => (route.kind.account !== null && !held.has(route.kind.account) ? [route.kind.account] : [])))].sort();
  const row = (account: string, signIn: SignIn, message: string | null): SignInRow => ({
    account,
    signIn,
    message,
    active: account === gcloud.active,
    routes: routesOf(account),
  });
  return [
    // A state this release does not know is one that could not be checked.
    ...gcloud.accounts.map((entry) => row(entry.account, entry.state === "signed_in" || entry.state === "expired" ? entry.state : "unknown", entry.message)),
    ...named.map((account) => row(account, "missing", null)),
  ];
}

const signInRow = ({ account, signIn, message, active, routes }: SignInRow) => (
  <li key={account} className="app-review-row">
    <div className="min-w-0 space-y-1">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium">
        <span data-sign-in={signIn} aria-hidden="true" className={cn("size-1.5 shrink-0 rounded-full", signInDot[signIn])} />
        <span className="wrap-anywhere">{revealHidden(account)}</span>
        {active && <Badge variant="secondary">gcloud active</Badge>}
      </p>
      <p className="text-xs text-muted-foreground">
        {signInLabel[signIn]} · {routeCount(routes)}
      </p>
      {(signIn === "expired" || signIn === "missing") && <p className="wrap-anywhere text-xs">{loginCommand(account)}</p>}
      {signIn === "unknown" && message && <p className="wrap-anywhere text-xs text-muted-foreground">{revealHidden(message)}</p>}
    </div>
  </li>
);

/** What Google sign-in shows: the rows, or why there are none. A function, not a component, so a test finds the rows in the page's tree. */
function signInContent(gcloud: Reading<GcloudAccountsView>, listed: ListedRoute[]) {
  if (gcloud.error !== null)
    return (
      <p role="alert" className="text-sm text-destructive">
        {revealHidden(gcloud.error)}
      </p>
    );
  if (!gcloud.data)
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Checking Google sign-ins…
      </p>
    );
  if (!gcloud.data.config_found)
    return (
      <p className="rounded-lg bg-muted/50 p-3 text-sm">
        gcloud was not found on this computer. Install the Google Cloud CLI, then run {loginCommand()}.
      </p>
    );
  const rows = signInRows(gcloud.data, listed);
  if (rows.length === 0)
    return (
      <p className="text-sm text-muted-foreground">
        gcloud has no signed-in Google account on this computer. Run {loginCommand()} to sign in.
      </p>
    );
  return <ul className="app-review-list min-w-0">{rows.map(signInRow)}</ul>;
}

/** The request a grant row's button starts: through the row's first host, with that host's route, alias and this computer's memory of it. */
export type GrantAsk = { row: PamGrantView; transport: HostTransport; memory: GrantMemoryView | null; alias: string };

/** What makes a row one: the account, the project, the location and the entitlement id together. */
const grantKey = (row: PamGrantView) => JSON.stringify([row.account, row.project, row.location, row.entitlement]);

/**
 * The request a row's Request grant starts (design 2026-10-26, "The Google Cloud page"): the entitlement of the row, asked through the
 * first host of the row, since the request is made through a host's route. None while the overview has no route for that host (yet).
 */
function askFor(overview: RecordOverview, listed: ListedRoute[], row: PamGrantView): GrantAsk | null {
  const first = listed.find(({ host }) => host.id === row.host_ids[0]);
  return first ? { row, transport: first.route, memory: grantMemoryFor(overview, first.host.id), alias: first.host.payload.alias } : null;
}

/** The rows with the answer of a request taken into the row it was for: the grant it got, or the sentence why it got none. */
function withAnswer(rows: PamGrantView[] | undefined, asked: PamGrantView, status: PamStatusView): PamGrantView[] | undefined {
  return rows?.map((row) =>
    grantKey(row) === grantKey(asked) ? { ...row, state: status.state, active_until_ms: status.active_until_ms, message: status.message } : row,
  );
}

export type GoogleCloudPageViewProps = {
  overview: RecordOverview;
  /** gcloud's accounts on this computer, as `gcp_accounts` answered. */
  accounts: Reading<GcloudAccountsView>;
  /** The grants the routes require, as `gcp_pam_grants` answered. */
  grants: Reading<PamGrantView[]>;
  /** The request being made, if any: the dialog is open for it. */
  requesting: GrantAsk | null;
  onRequest: (ask: GrantAsk) => void;
  onCloseRequest: () => void;
  /** A request got `status` for the row it was made for. */
  onRequested: (row: PamGrantView, status: PamStatusView) => void;
  createIapHost: () => void;
  editHost: (id: string) => void;
};

/** The page, apart from its state and its reads: no hooks, so the tests call it and press what it draws. */
export function GoogleCloudPageView({ overview, accounts, grants, requesting, onRequest, onCloseRequest, onRequested, createIapHost, editHost }: GoogleCloudPageViewProps) {
  const listed = listedRoutes(overview);
  // In a central library a route the library has no room for stays on this computer and is said to; elsewhere every route does, by design.
  const central = overview.central_mode === true && Boolean(overview.account);
  const apart = ({ route }: ListedRoute) => central && !routeSynced(overview, route.host_id);
  const hosts = new Map(overview.hosts.map((host) => [host.id, host]));
  const grantRows = (grants.data ?? []).filter((row) => row.host_ids.some((id) => hosts.has(id)));

  const grantRow = (row: PamGrantView) => {
    const ask = askFor(overview, listed, row);
    const held = row.state === "active" || row.state === "activating";
    const names = row.host_ids.flatMap((id) => {
      const host = hosts.get(id);
      return host ? [revealHidden(host.payload.alias)] : [];
    });
    return (
      <li key={grantKey(row)} className="app-review-row">
        <div className="min-w-0 space-y-1">
          <p className="wrap-anywhere text-sm font-medium">{revealHidden(row.entitlement)}</p>
          <p className="wrap-anywhere text-xs text-muted-foreground">
            {revealHidden([row.project, row.location, row.account].filter((part): part is string => Boolean(part)).join(" · "))}
          </p>
          <p className="wrap-anywhere text-xs text-muted-foreground">Required by {names.join(", ")}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className={cn("wrap-anywhere max-w-xs text-sm", held && "text-primary")}>{revealHidden(grantStateOrMessage(row))}</span>
          <Button
            size="sm"
            variant="outline"
            aria-label={`Request grant for ${revealHidden(row.entitlement)}`}
            disabled={held || ask === null}
            onClick={() => ask && onRequest(ask)}
          >
            Request grant
          </Button>
        </div>
      </li>
    );
  };

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
          {apart(entry) && <p className="text-xs text-warning">Saved on this computer only: the library has no room for this route</p>}
        </div>
      </li>
    );
  };

  return (
    <div className="transports-panel space-y-6">
      <PageHeader
        title="Google Cloud"
        description="Google sign-in and access grants on this computer. A host connects through IAP when its Connect via is set to Google Cloud IAP."
        actions={
          <Button onClick={() => createIapHost()}>
            <Plus className="size-4" />
            New IAP host
          </Button>
        }
      />
      <FormSection title="Google sign-in" description="Accounts come from gcloud on this computer. Sign-ins are per computer and are not synced.">
        {signInContent(accounts, listed)}
      </FormSection>
      {requiresGrant(listed) && (
        <FormSection title="Access grants" description="Privileged Access Manager grants your hosts require. A grant ends on its own; Lunport never revokes one.">
          {grants.error !== null ? (
            <p role="alert" className="text-sm text-destructive">
              {revealHidden(grants.error)}
            </p>
          ) : !grants.data ? (
            <p role="status" className="text-sm text-muted-foreground">
              Checking grants…
            </p>
          ) : grantRows.length === 0 ? (
            <p className="text-sm text-muted-foreground">No grants to show.</p>
          ) : (
            <ul className="app-review-list min-w-0">{grantRows.map(grantRow)}</ul>
          )}
        </FormSection>
      )}
      <FormSection title="Hosts through IAP">
        {listed.length === 0 ? (
          <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
            No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host.
          </p>
        ) : (
          <ul className="app-review-list min-w-0">{[...listed.filter((entry) => !apart(entry)), ...listed.filter(apart)].map(hostRow)}</ul>
        )}
      </FormSection>
      {requesting && (
        <GrantRequestDialog
          key={grantKey(requesting.row)}
          transport={requesting.transport}
          entitlement={requesting.row.entitlement}
          memory={requesting.memory}
          alias={requesting.alias}
          onClose={onCloseRequest}
          onRequested={(status) => onRequested(requesting.row, status)}
        />
      )}
    </div>
  );
}

/**
 * The Google Cloud page: gcloud's sign-ins, read through the cache the host editor's account picker shares; the grants the routes need,
 * read only while a listed route requires one; and the request being made. `createIapHost` opens the host editor on a new host with
 * Google Cloud IAP chosen, and `editHost` the editor of a host.
 */
export function GoogleCloudPanel({ overview, createIapHost, editHost }: { overview: RecordOverview; createIapHost: () => void; editHost: (id: string) => void }) {
  const client = useQueryClient();
  const [requesting, setRequesting] = useState<GrantAsk | null>(null);
  const accounts = useQuery(gcloudAccountsQuery);
  const grants = useQuery({ ...pamGrantsQuery, enabled: requiresGrant(listedRoutes(overview)) });
  return (
    <GoogleCloudPageView
      overview={overview}
      accounts={reading(accounts)}
      grants={reading(grants)}
      requesting={requesting}
      onRequest={setRequesting}
      onCloseRequest={() => setRequesting(null)}
      onRequested={(row, status) => client.setQueryData<PamGrantView[]>(pamGrantsKey, (rows) => withAnswer(rows, row, status))}
      createIapHost={createIapHost}
      editHost={editHost}
    />
  );
}
