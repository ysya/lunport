import { useId, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { FormSection } from "@/components/app/Workflow";
import type { RecordOverview } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import {
  gcloudAccountsQuery,
  grantBusy,
  grantHeld,
  grantStateOrMessage,
  pamOverviewKey,
  pamOverviewQuery,
  parentLabel,
  removePamScope,
  savePamScope,
  scopeParent,
  upTo,
  type GcloudAccountsView,
  type PamEntitlementView,
  type PamOverview,
  type PamScopeView,
  type PamStatusView,
  type ScopeKind,
} from "@/lib/transports";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import { EntitlementGrantDialog } from "./GrantRequestDialog";
import { reading, type Reading } from "./GoogleAccountsTab";

/*
 * The Google Cloud page's Access tab (design 2026-10-27, The Access tab): Privileged Access Manager on its own. Where Lunport looks for
 * entitlements (the projects the routes use, and the scopes the person added, which sync with the library), and every entitlement the
 * person may request there or a route names, each with its grant and Request grant.
 */

/** What makes an entitlement row one: its account and its full name. */
export const entitlementKey = (row: Pick<PamEntitlementView, "account" | "name">) => JSON.stringify([row.account, row.name]);

/** The rows with the answer of a request taken into the row it was for. */
export function withAnswer(overview: PamOverview | undefined, asked: PamEntitlementView, status: PamStatusView): PamOverview | undefined {
  return (
    overview && {
      ...overview,
      entitlements: overview.entitlements.map((row) =>
        entitlementKey(row) === entitlementKey(asked) ? { ...row, state: status.state, active_until_ms: status.active_until_ms, message: status.message } : row,
      ),
    }
  );
}

/** A scope as the tab names it: `project acme-dev-654321 · global · frank@example.com`. */
export const scopeLine = (scope: Pick<PamScopeView, "parent" | "location" | "account">) =>
  [parentLabel(scope.parent), scope.location, scope.account ?? "gcloud's active account"].join(" · ");

/** The Add scope dialog's draft. */
export type ScopeDraft = { kind: ScopeKind; id: string; location: string; account: string };
export const newScopeDraft = (): ScopeDraft => ({ kind: "projects", id: "", location: "global", account: "" });

export type AccessTabViewProps = {
  now?: number;
  overview: RecordOverview;
  data: Reading<PamOverview>;
  accounts: GcloudAccountsView | undefined;
  /** The entitlement being requested: the dialog is open for it. */
  requesting: PamEntitlementView | null;
  onRequest: (row: PamEntitlementView) => void;
  onCloseRequest: () => void;
  onRequested: (row: PamEntitlementView, status: PamStatusView) => void;
  /** The Add scope dialog's draft while it is open, and why the last save failed. */
  draft: ScopeDraft | null;
  draftError: string | null;
  busy: boolean;
  onOpenScope: () => void;
  onDraft: (draft: ScopeDraft) => void;
  onSaveScope: (draft: ScopeDraft) => void;
  onCloseScope: () => void;
  onRemoveScope: (id: string) => void;
};

const kinds: Array<{ value: ScopeKind; label: string; placeholder: string }> = [
  { value: "projects", label: "Project", placeholder: "acme-dev-654321" },
  { value: "folders", label: "Folder", placeholder: "123456789012" },
  { value: "organizations", label: "Organization", placeholder: "987654321098" },
];
const selectClass = "h-9 w-full rounded-md border border-input bg-transparent px-2 text-sm shadow-xs outline-none focus-visible:ring-3 focus-visible:ring-ring/50";

/** The tab, apart from its state and its reads: no hooks but the dialog's ids, so the tests call it and press what it draws. */
export function AccessTabView({ now = Date.now(), overview, data, accounts, requesting, onRequest, onCloseRequest, onRequested, draft, draftError, busy, onOpenScope, onDraft, onSaveScope, onCloseScope, onRemoveScope }: AccessTabViewProps) {
  const hosts = new Map(overview.hosts.map((host) => [host.id, host]));
  const aliases = (ids: string[]) => ids.flatMap((id) => (hosts.has(id) ? [revealHidden(hosts.get(id)!.payload.alias)] : []));

  const scopeRow = (scope: PamScopeView) => {
    const used = aliases(scope.host_ids);
    return (
      <li key={scope.id ?? `route:${scopeLine(scope)}`} className="app-review-row">
        <div className="min-w-0 space-y-1">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
            <span className="wrap-anywhere">{revealHidden(scopeLine(scope))}</span>
            {scope.from_routes && <Badge variant="secondary">From routes</Badge>}
          </p>
          {used.length > 0 && <p className="wrap-anywhere text-xs text-muted-foreground">Used by {used.join(", ")}</p>}
          {scope.message && (
            <p role="alert" className="wrap-anywhere text-xs text-destructive">
              {revealHidden(scope.message)}
            </p>
          )}
        </div>
        {scope.id !== null && (
          <Button size="sm" variant="ghost" aria-label={`Remove ${revealHidden(scopeLine(scope))}`} disabled={busy} onClick={() => onRemoveScope(scope.id!)}>
            Remove
          </Button>
        )}
      </li>
    );
  };

  const entitlementRow = (row: PamEntitlementView) => {
    const used = aliases(row.host_ids);
    const held = grantHeld(row, now);
    const details = [
      row.max_duration_secs === null ? null : upTo(row.max_duration_secs),
      row.needs_approval ? "Needs approval" : null,
      used.length > 0 ? `Used by ${used.join(", ")}` : null,
    ].filter((part): part is string => part !== null);
    return (
      <li key={entitlementKey(row)} className="app-review-row">
        <div className="min-w-0 space-y-1">
          <p className="wrap-anywhere text-sm font-medium">{revealHidden(row.entitlement)}</p>
          <p className="wrap-anywhere text-xs text-muted-foreground">
            {revealHidden([parentLabel(row.parent), row.location, row.account ?? "gcloud's active account"].join(" · "))}
          </p>
          {row.roles.length > 0 && (
            <p className="wrap-anywhere text-xs text-muted-foreground">{revealHidden(row.roles.map((role) => `${role.role} on ${role.resource}`).join(", "))}</p>
          )}
          {details.length > 0 && <p className="wrap-anywhere text-xs text-muted-foreground">{details.join(" · ")}</p>}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className={cn("wrap-anywhere max-w-xs text-sm", held && "text-primary")}>{revealHidden(grantStateOrMessage(row, now))}</span>
          <Button size="sm" variant="outline" aria-label={`Request grant for ${revealHidden(row.entitlement)}`} disabled={grantBusy(row, now)} onClick={() => onRequest(row)}>
            Request grant
          </Button>
        </div>
      </li>
    );
  };

  const body = () => {
    if (data.error !== null)
      return (
        <p role="alert" className="text-sm text-destructive">
          {revealHidden(data.error)}
        </p>
      );
    if (!data.data)
      return (
        <p role="status" className="text-sm text-muted-foreground">
          Looking for entitlements…
        </p>
      );
    if (data.data.entitlements.length === 0)
      return (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          No entitlement found. Add a scope where your Google account can request a grant, or require a grant in a host&apos;s Google Cloud options.
        </p>
      );
    return <ul className="app-review-list min-w-0">{data.data.entitlements.map(entitlementRow)}</ul>;
  };

  return (
    <>
      <FormSection
        title="Entitlements"
        description="Privileged Access Manager grants for your Google accounts. A grant gives its roles to every tool that uses the account until it ends; Lunport never ends one early."
      >
        {body()}
      </FormSection>
      <FormSection
        title="Where Lunport looks"
        description="The projects your routes use, and the projects, folders and organizations you add. Added scopes sync with the library."
        actions={
          <Button size="sm" variant="outline" disabled={busy} onClick={onOpenScope}>
            <Plus className="size-4" />
            Add scope
          </Button>
        }
      >
        {draft === null && draftError && (
          <p role="alert" className="mb-2 text-sm text-destructive">
            {revealHidden(draftError)}
          </p>
        )}
        {data.data && data.data.scopes.length > 0 ? (
          <ul className="app-review-list min-w-0">{data.data.scopes.map(scopeRow)}</ul>
        ) : (
          <p className="text-sm text-muted-foreground">{data.data ? "Lunport looks nowhere yet." : "…"}</p>
        )}
      </FormSection>
      {draft && <ScopeDialog draft={draft} error={draftError} busy={busy} accounts={accounts} onDraft={onDraft} onSave={onSaveScope} onClose={onCloseScope} />}
      {requesting && <EntitlementGrantDialog key={entitlementKey(requesting)} row={requesting} onClose={onCloseRequest} onRequested={(status) => onRequested(requesting, status)} />}
    </>
  );
}

/** Add scope: the kind of place, its id or number, the location, and the account (empty: gcloud's active account on each computer). */
export function ScopeDialog({ draft, error, busy, accounts, onDraft, onSave, onClose }: {
  draft: ScopeDraft;
  error: string | null;
  busy: boolean;
  accounts: GcloudAccountsView | undefined;
  onDraft: (draft: ScopeDraft) => void;
  onSave: (draft: ScopeDraft) => void;
  onClose: () => void;
}) {
  const ids = { kind: useId(), id: useId(), location: useId(), account: useId() };
  const kind = kinds.find((entry) => entry.value === draft.kind) ?? kinds[0];
  const parent = scopeParent(draft.kind, draft.id);
  const problem = draft.id.trim() === "" ? null : "problem" in parent ? parent.problem : !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(draft.location.trim()) ? "Enter the PAM location, such as global." : null;
  const ready = !busy && draft.id.trim() !== "" && problem === null;
  return (
    <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
      <TaskDialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add a scope</DialogTitle>
          <DialogDescription>Lunport asks Google which entitlements the account may request there. The scope syncs with the library.</DialogDescription>
        </DialogHeader>
        <TaskDialogBody>
          <div className="space-y-3 text-sm">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor={ids.kind}>Kind</Label>
                <select id={ids.kind} className={selectClass} value={draft.kind} disabled={busy} onChange={(event) => onDraft({ ...draft, kind: event.target.value as ScopeKind })}>
                  {kinds.map((entry) => (
                    <option key={entry.value} value={entry.value}>
                      {entry.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1 sm:col-span-2">
                <Label htmlFor={ids.id}>{draft.kind === "projects" ? "Project ID" : `${kind.label} number`}</Label>
                <Input id={ids.id} autoFocus value={draft.id} placeholder={kind.placeholder} autoComplete="off" disabled={busy} onChange={(event) => onDraft({ ...draft, id: event.target.value })} />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor={ids.location}>Location</Label>
                <Input id={ids.location} value={draft.location} placeholder="global" autoComplete="off" disabled={busy} onChange={(event) => onDraft({ ...draft, location: event.target.value })} />
              </div>
              <div className="space-y-1 sm:col-span-2">
                <Label htmlFor={ids.account}>Google account</Label>
                {accounts?.config_found ? (
                  <select id={ids.account} className={selectClass} value={draft.account} disabled={busy} onChange={(event) => onDraft({ ...draft, account: event.target.value })}>
                    <option value="">{accounts.active ? `gcloud's active account (${accounts.active})` : "gcloud's active account"}</option>
                    {accounts.accounts.map((entry) => (
                      <option key={entry.account} value={entry.account}>
                        {entry.account}
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input id={ids.account} value={draft.account} placeholder="gcloud's active account" autoComplete="off" disabled={busy} onChange={(event) => onDraft({ ...draft, account: event.target.value })} />
                )}
              </div>
            </div>
            {(problem ?? error) && (
              <p role="alert" className="text-xs text-destructive">
                {revealHidden((problem ?? error)!)}
              </p>
            )}
          </div>
        </TaskDialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!ready} onClick={() => onSave(draft)}>
            {busy ? "Adding…" : "Add scope"}
          </Button>
        </DialogFooter>
      </TaskDialogContent>
    </Dialog>
  );
}

/**
 * The Access tab: the overview (read while the tab shows, and every minute), the request being made, and the scope being added. A
 * scope saved or removed answers the library's overview, which `accept` takes, and the entitlements are read again.
 */
export function PamAccessTab({ overview, accept }: { overview: RecordOverview; accept: (next: RecordOverview) => void }) {
  const now = useNow(1000);
  const client = useQueryClient();
  const data = useQuery(pamOverviewQuery);
  const accounts = useQuery(gcloudAccountsQuery).data;
  const [requesting, setRequesting] = useState<PamEntitlementView | null>(null);
  const [draft, setDraft] = useState<ScopeDraft | null>(null);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const change = async (edit: () => Promise<RecordOverview>, after?: () => void) => {
    setBusy(true);
    setDraftError(null);
    try {
      accept(await edit());
      after?.();
      void client.invalidateQueries({ queryKey: pamOverviewKey });
    } catch (failure) {
      setDraftError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  };
  return (
    <AccessTabView
      now={now}
      overview={overview}
      data={reading(data)}
      accounts={accounts}
      requesting={requesting}
      onRequest={setRequesting}
      onCloseRequest={() => setRequesting(null)}
      onRequested={(row, status) => client.setQueryData<PamOverview>(pamOverviewKey, (now) => withAnswer(now, row, status))}
      draft={draft}
      draftError={draftError}
      busy={busy}
      onOpenScope={() => {
        setDraftError(null);
        setDraft(newScopeDraft());
      }}
      onDraft={setDraft}
      onSaveScope={(next) => {
        const parent = scopeParent(next.kind, next.id);
        if ("problem" in parent) return setDraftError(parent.problem);
        void change(() => savePamScope(parent.parent, next.location.trim(), next.account.trim() || null), () => setDraft(null));
      }}
      onCloseScope={() => setDraft(null)}
      onRemoveScope={(id) => void change(() => removePamScope(id))}
    />
  );
}
