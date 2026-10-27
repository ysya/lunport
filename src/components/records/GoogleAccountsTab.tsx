import { useEffect, useState } from "react";
import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Plus } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { FormSection } from "@/components/app/Workflow";
import type { RecordOverview } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import {
  cancelAccountAction,
  gcloudAccountsKey,
  gcloudAccountsQuery,
  gcloudCliKey,
  gcloudCliQuery,
  locateGcloudAgain,
  runAccountAction,
  SIGN_IN_URL_EVENT,
  type AccountAction,
  type AccountActionView,
  type GcloudAccountsView,
  type GcloudCliView,
  type HostTransport,
} from "@/lib/transports";
import { cn } from "@/lib/utils";

/*
 * The Google Cloud page's Accounts tab (design 2026-10-27, The Accounts tab): gcloud on this computer and its Google accounts, with
 * the actions that change them. Each action runs gcloud and changes gcloud for every tool on this computer, so every one but signing in
 * again to an account whose sign-in failed is confirmed first, in words that say so.
 */

/** What a read has to show: its answer, or the sentence why there is none; neither while the first answer is awaited. */
export type Reading<T> = { data: T | undefined; error: string | null };

/** The latest read speaks: one that failed shows its sentence, whatever an earlier read found, since that may be gone by now. */
export const reading = <T,>(query: UseQueryResult<T>): Reading<T> =>
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

export type SignInRow = { account: string; signIn: SignIn; message: string | null; active: boolean; routes: number };

/**
 * The rows of Google accounts: each account gcloud holds credentials for, then each account only a route names (this computer has no
 * sign-in for it), in the order of their names. A route counts for the account it names, and a route that names none for gcloud's
 * active account.
 */
export function signInRows(gcloud: GcloudAccountsView, routes: HostTransport[]): SignInRow[] {
  const routesOf = (account: string) => routes.filter((route) => (route.kind.account ?? gcloud.active) === account).length;
  const held = new Set(gcloud.accounts.map((entry) => entry.account));
  const named = [...new Set(routes.flatMap((route) => (route.kind.account !== null && !held.has(route.kind.account) ? [route.kind.account] : [])))].sort();
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

/** An action the person asked for and has yet to confirm, with what the confirmation says of it. */
export type Confirming = { action: AccountAction; routes: number; active: boolean };

/** The words of a confirmation (design 2026-10-27, The Accounts tab). */
export function confirmation({ action, routes, active }: Confirming): { title: string; body: string[]; button: string; destructive: boolean } | null {
  switch (action.kind) {
    case "activate":
      return {
        title: `Make ${action.account} gcloud's active account?`,
        body: [
          `gcloud, kubectl, Terraform and every other tool on this computer that uses gcloud's active account will use ${action.account}. Routes that name no account connect as it too.`,
        ],
        button: "Make active",
        destructive: false,
      };
    case "remove": {
      const using = routes === 0 ? "" : `, and the routes that use it (${routes}) cannot connect until you sign in again`;
      return {
        title: `Remove ${action.account} from gcloud on this computer?`,
        body: [
          `gcloud revokes this sign-in at Google and deletes its credentials here. Every tool on this computer that uses gcloud loses this account${using}. Google may also end this account's gcloud sign-in on your other computers.`,
          ...(active ? ["gcloud will have no active account until you choose one."] : []),
        ],
        button: "Remove account",
        destructive: true,
      };
    }
    default:
      return null;
  }
}

/** An action gcloud is running, or has ended: the sign-in page's address once gcloud printed one, and how it ended. */
export type Running = { action: AccountAction; url: string | null; done: AccountActionView | null; error: string | null };

/** What the running dialog says while gcloud works. */
export function runningLine(action: AccountAction): string {
  switch (action.kind) {
    case "sign_in":
      return `Finish signing in to ${action.account} in your browser.`;
    case "add":
      return "Finish signing in to the new account in your browser.";
    case "activate":
      return `Making ${action.account} gcloud's active account…`;
    case "remove":
      return `Removing ${action.account} from gcloud…`;
  }
}

const runningTitle: Record<AccountAction["kind"], string> = {
  sign_in: "Sign in to Google",
  add: "Add a Google account",
  activate: "Change gcloud's active account",
  remove: "Remove a Google account",
};

export type AccountsTabViewProps = {
  overview: RecordOverview;
  /** The routes the page lists: those whose host this computer has. */
  routes: HostTransport[];
  accounts: Reading<GcloudAccountsView>;
  cli: Reading<GcloudCliView>;
  confirming: Confirming | null;
  running: Running | null;
  /** Asks for an action: straight to gcloud for a sign-in, to the confirmation for the others. */
  onAsk: (ask: Confirming) => void;
  onConfirm: (ask: Confirming) => void;
  onCloseConfirm: () => void;
  onCancelRun: () => void;
  onCloseRun: () => void;
  onOpenUrl: (url: string) => void;
  onLocateAgain: () => void;
};

/** The tab, apart from its state and its reads: no hooks, so the tests call it and press what it draws. */
export function AccountsTabView({ routes, accounts, cli, confirming, running, onAsk, onConfirm, onCloseConfirm, onCancelRun, onCloseRun, onOpenUrl, onLocateAgain }: AccountsTabViewProps) {
  const gcloud = cli.data?.path ?? null;
  const usable = gcloud !== null && running === null;
  const ask = (action: AccountAction, row?: SignInRow) => onAsk({ action, routes: row?.routes ?? 0, active: row?.active ?? false });

  const signInRow = (row: SignInRow) => (
    <li key={row.account} className="app-review-row">
      <div className="min-w-0 space-y-1">
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium">
          <span data-sign-in={row.signIn} aria-hidden="true" className={cn("size-1.5 shrink-0 rounded-full", signInDot[row.signIn])} />
          <span className="wrap-anywhere">{revealHidden(row.account)}</span>
          {row.active && <Badge variant="secondary">gcloud active</Badge>}
        </p>
        <p className="text-xs text-muted-foreground">
          {signInLabel[row.signIn]} · {routeCount(row.routes)}
        </p>
        {gcloud === null && (row.signIn === "expired" || row.signIn === "missing") && <p className="wrap-anywhere text-xs">{loginCommand(row.account)}</p>}
        {row.signIn === "unknown" && row.message && <p className="wrap-anywhere text-xs text-muted-foreground">{revealHidden(row.message)}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant={row.signIn === "expired" || row.signIn === "missing" ? "default" : "outline"}
          aria-label={`Sign in again as ${revealHidden(row.account)}`}
          disabled={!usable}
          onClick={() => ask({ kind: "sign_in", account: row.account }, row)}
        >
          Sign in again
        </Button>
        {!row.active && row.signIn !== "missing" && (
          <Button size="sm" variant="outline" aria-label={`Make ${revealHidden(row.account)} gcloud's active account`} disabled={!usable} onClick={() => ask({ kind: "activate", account: row.account }, row)}>
            Make active
          </Button>
        )}
        {row.signIn !== "missing" && (
          <Button size="sm" variant="ghost" className="text-destructive" aria-label={`Remove ${revealHidden(row.account)}`} disabled={!usable} onClick={() => ask({ kind: "remove", account: row.account }, row)}>
            Remove…
          </Button>
        )}
      </div>
    </li>
  );

  const accountsContent = () => {
    if (accounts.error !== null)
      return (
        <p role="alert" className="text-sm text-destructive">
          {revealHidden(accounts.error)}
        </p>
      );
    if (!accounts.data)
      return (
        <p role="status" className="text-sm text-muted-foreground">
          Checking Google sign-ins…
        </p>
      );
    const rows = accounts.data.config_found ? signInRows(accounts.data, routes) : [];
    if (rows.length === 0)
      return (
        <p className="text-sm text-muted-foreground">
          {gcloud === null ? <>gcloud has no signed-in Google account on this computer. Run {loginCommand()} to sign in.</> : "gcloud has no Google account on this computer yet."}
        </p>
      );
    return <ul className="app-review-list min-w-0">{rows.map(signInRow)}</ul>;
  };

  const confirmWords = confirming ? confirmation(confirming) : null;
  return (
    <>
      <FormSection title="gcloud" description="Lunport runs gcloud on this computer to sign in, add, remove and activate accounts.">
        {cli.error !== null ? (
          <p role="alert" className="text-sm text-destructive">
            {revealHidden(cli.error)}
          </p>
        ) : !cli.data ? (
          <p role="status" className="text-sm text-muted-foreground">
            Looking for gcloud…
          </p>
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-3">
            {gcloud !== null ? (
              <p className="min-w-0 text-sm">
                gcloud found at <code className="wrap-anywhere select-all font-mono text-xs">{revealHidden(gcloud)}</code>
              </p>
            ) : (
              <p className="min-w-0 text-sm">
                Lunport could not find gcloud on this computer.{" "}
                <button type="button" className="text-primary underline-offset-4 hover:underline" onClick={() => onOpenUrl("https://cloud.google.com/sdk/docs/install")}>
                  Install the Google Cloud CLI
                </button>
                , then press Check again.
              </p>
            )}
            <Button size="sm" variant="outline" disabled={running !== null} onClick={onLocateAgain}>
              Check again
            </Button>
          </div>
        )}
      </FormSection>
      <FormSection
        title="Google accounts"
        description="Accounts come from gcloud on this computer and are not synced. Changes here change gcloud for every tool on this computer."
        actions={
          <Button size="sm" variant="outline" disabled={!usable} onClick={() => ask({ kind: "add" })}>
            <Plus className="size-4" />
            Add account
          </Button>
        }
      >
        {accountsContent()}
      </FormSection>
      <AlertDialog open={confirmWords !== null} onOpenChange={(open) => { if (!open) onCloseConfirm(); }}>
        {confirming && confirmWords && (
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{revealHidden(confirmWords.title)}</AlertDialogTitle>
              {confirmWords.body.map((line) => (
                <AlertDialogDescription key={line}>{revealHidden(line)}</AlertDialogDescription>
              ))}
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant={confirmWords.destructive ? "destructive" : "default"} onClick={() => onConfirm(confirming)}>
                {confirmWords.button}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        )}
      </AlertDialog>
      {running && (
        <Dialog open onOpenChange={(open) => { if (!open) (running.done || running.error ? onCloseRun : onCancelRun)(); }}>
          <TaskDialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>{runningTitle[running.action.kind]}</DialogTitle>
              <DialogDescription>Lunport runs gcloud on this computer; the change applies to every tool that uses gcloud.</DialogDescription>
            </DialogHeader>
            <TaskDialogBody>
              <div className="space-y-2 text-sm">
                {running.done ? (
                  <p role="status">{revealHidden(running.done.message)}</p>
                ) : running.error ? (
                  <p role="alert" className="text-destructive">
                    {revealHidden(running.error)}
                  </p>
                ) : (
                  <>
                    <p role="status">{revealHidden(runningLine(running.action))}</p>
                    {running.url && (
                      <p className="text-xs text-muted-foreground">
                        Browser did not open?{" "}
                        <button type="button" className="text-primary underline-offset-4 hover:underline" onClick={() => onOpenUrl(running.url!)}>
                          Open the sign-in page
                        </button>
                      </p>
                    )}
                  </>
                )}
              </div>
            </TaskDialogBody>
            <DialogFooter>
              {running.done || running.error ? (
                <Button onClick={onCloseRun}>Close</Button>
              ) : (
                <Button variant="outline" onClick={onCancelRun}>
                  Cancel
                </Button>
              )}
            </DialogFooter>
          </TaskDialogContent>
        </Dialog>
      )}
    </>
  );
}

/**
 * The Accounts tab: gcloud's sign-ins (one cache entry with the host editor's account picker), where gcloud is, the confirmation
 * asked for and the action running. A sign-in goes to gcloud at once; every other action is confirmed first. After an action the
 * accounts are read again.
 */
export function GoogleAccountsTab({ overview, routes }: { overview: RecordOverview; routes: HostTransport[] }) {
  const client = useQueryClient();
  const accounts = useQuery(gcloudAccountsQuery);
  const cli = useQuery(gcloudCliQuery);
  const [confirming, setConfirming] = useState<Confirming | null>(null);
  const [running, setRunning] = useState<Running | null>(null);
  const active = running !== null && running.done === null && running.error === null;

  useEffect(() => {
    if (!active) return;
    let gone = false;
    const stop = listen<string>(SIGN_IN_URL_EVENT, (event) => {
      if (!gone) setRunning((now) => (now && now.done === null && now.error === null ? { ...now, url: event.payload } : now));
    });
    return () => {
      gone = true;
      void stop.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [active]);

  const run = async (action: AccountAction) => {
    setConfirming(null);
    setRunning({ action, url: null, done: null, error: null });
    try {
      const done = await runAccountAction(action);
      setRunning((now) => (now ? { ...now, done } : now));
    } catch (failure) {
      setRunning((now) => (now ? { ...now, error: errorMessage(failure) } : now));
    } finally {
      void client.invalidateQueries({ queryKey: gcloudAccountsKey });
    }
  };

  return (
    <AccountsTabView
      overview={overview}
      routes={routes}
      accounts={reading(accounts)}
      cli={reading(cli)}
      confirming={confirming}
      running={running}
      onAsk={(ask) => (confirmation(ask) === null ? void run(ask.action) : setConfirming(ask))}
      onConfirm={(ask) => void run(ask.action)}
      onCloseConfirm={() => setConfirming(null)}
      onCancelRun={() => void cancelAccountAction().catch(() => {})}
      onCloseRun={() => setRunning(null)}
      onOpenUrl={(url) => void openUrl(url).catch(() => {})}
      onLocateAgain={() => void locateGcloudAgain().then((view) => client.setQueryData(gcloudCliKey, view)).catch(() => {})}
    />
  );
}
