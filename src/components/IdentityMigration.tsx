import { useEffect, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import type { ConflictChoice } from "@/bindings/ConflictChoice";
import type { MigrationStatus } from "@/bindings/MigrationStatus";
import type { MigrationStep } from "@/bindings/MigrationStep";
import { tauriInvoke } from "@/lib/ipc";
import { BrandMark } from "@/components/app/BrandMark";
import { CredentialPermissionSheet } from "@/components/CredentialPermissionSheet";
import { usePermissionSheetStore } from "@/stores/permission-sheet";
import { McpMigrationToast } from "@/components/McpMigrationNotice";
import { Button } from "@/components/ui/button";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";

export const identityMigrationKey = ["app", "identity-migration"] as const;

function useIdentityMigrationStatus() {
  // Asked again whenever the window comes back: another start of Lunport that handed over to this one may have moved what this one's
  // start left (the backend reads its journal again then).
  return useQuery({ queryKey: identityMigrationKey, queryFn: () => tauriInvoke<MigrationStatus>("identity_migration_status"), staleTime: Infinity, retry: false, refetchOnWindowFocus: "always" });
}

/**
 * The app, only once the backend says this version's data is in its folder. Otherwise what stops it and how to go on; until then the
 * backend starts nothing that reads or writes the new folder.
 */
export function IdentityMigrationGate({ children }: { children: ReactNode }) {
  const status = useIdentityMigrationStatus();
  if (status.isPending) return null;
  // Only the first check stops the app: one that fails later keeps what the check before said (the notice says it failed).
  if (status.isLoadingError) return <Page title="Lunport could not check where its data is"><p className="text-sm text-muted-foreground">The app opens once it knows its data is in place.</p><p className="break-words text-xs text-muted-foreground">{String(status.error)}</p><Button disabled={status.isFetching} onClick={() => void status.refetch()}>{status.isFetching ? "Checking…" : "Retry"}</Button></Page>;
  const { state } = status.data;
  if (state === "not_needed" || state === "completed" || state === "credentials_pending") return <>{children}<McpMigrationToast /></>;
  return <IdentityMigrationBlocked status={status.data} />;
}

/**
 * What the app says of saved credentials (passwords, the vault's key) still under the earlier version's name; `null` when there is
 * nothing to say. A `warning` asks for the user's attention: the vault waits for its keys, or the move waits for the user. It offers
 * Retry where a retry can move some now (`retry`), and Allow… where items wait for the user's permission (`allow`), which reopens the
 * sheet that asks for it (`CredentialPermissionSheet`); both where both help (a locked keychain, say). Otherwise they are only
 * mentioned: what a later start tries again by itself, or what stays for good. Nothing is ever deleted.
 */
export function credentialsNotice(status: MigrationStatus | undefined): { warning: boolean; retry: boolean; allow: boolean; title: string; description: string } | null {
  if (status?.state !== "credentials_pending" && status?.state !== "completed") return null;
  const why = status.detail ? ` Why: ${status.detail.replace(/[\s.…]+$/, "")}.` : "";
  if (status.failed_step === "credentials") {
    const unmoved = `Lunport has not finished moving your saved passwords and keys from the earlier version, so some may be unavailable. Nothing was deleted.${why}`;
    const permission = status.credentials_need_permission;
    const allow = permission > 0;
    // Only the user's permission holding the vault back makes a retry useless.
    const retry = status.credentials_retry_helps || !allow;
    const items = permission === 1 ? "1 saved item needs" : `${permission} saved items need`;
    const description = retry && allow
      ? `${unmoved} Retry moves what it can now, and ${items} your permission: Allow… asks for it (choose “Always Allow” when macOS asks). Lunport restarts if what it uses has moved.`
      : allow
        ? `${unmoved} ${items} your permission: Allow… asks for it again (choose “Always Allow” when macOS asks), and Lunport restarts if what it uses has moved.`
        : `${unmoved} Retry moves them, and Lunport restarts if what it uses has moved.`;
    return { warning: true, retry, allow, title: "Saved credentials have not moved yet", description };
  }
  if (status.credentials_left > 0) {
    const count = status.credentials_left === 1 ? "1 saved credential stays" : `${status.credentials_left} saved credentials stay`;
    return {
      warning: false,
      retry: false,
      allow: false,
      title: `${count} with the earlier version`,
      description: `Lunport could not move them, and nothing holds back the rest. Nothing was deleted.${why}`,
    };
  }
  return null;
}

/**
 * What the app says when a check of where its data is fails after the app opened (when the window comes back, say): it keeps what the
 * check before said. `null` when the check did not fail, or failed before the app opened, which the gate says itself.
 */
export function statusCheckFailure(check: { isRefetchError: boolean; error: unknown }): { title: string; description: string } | null {
  if (!check.isRefetchError) return null;
  return { title: "Lunport could not check where its data is", description: `Lunport keeps what it found before. ${String(check.error)}` };
}

// Two toasts, never both: the warning with Retry, and the mention of what stays. A failed check has a toast of its own.
const CREDENTIALS_RETRY = "identity-migration-credentials";
const CREDENTIALS_LEFT = "identity-migration-credentials-left";
const STATUS_CHECK = "identity-migration-check";

/** The notice of saved credentials still under the earlier name, with a Retry where it can move them (`identity_migration_retry_credentials`). */
export function CredentialsPendingNotice() {
  const status = useIdentityMigrationStatus();
  const queryClient = useQueryClient();
  const { mutate: retry, isPending: retrying } = useMutation({
    mutationFn: () => tauriInvoke<MigrationStatus>("identity_migration_retry_credentials"),
    onSuccess: (next) => queryClient.setQueryData(identityMigrationKey, next),
    onError: (error) => toast.error("Could not move the saved credentials", { description: String(error) }),
  });
  useEffect(() => {
    const notice = credentialsNotice(status.data);
    toast.dismiss(notice?.warning ? CREDENTIALS_LEFT : CREDENTIALS_RETRY);
    if (!notice) {
      toast.dismiss(CREDENTIALS_LEFT);
      return;
    }
    if (!notice.warning) {
      toast.info(notice.title, { id: CREDENTIALS_LEFT, description: notice.description });
      return;
    }
    // The notice stays while Retry runs, which nothing starts twice: it changes with the answer, and Lunport restarts if what it uses has
    // moved. Allow… reopens the sheet that asks for the user's permission; where both help, it is a second button that leaves the notice
    // up (sonner's own second button would close it).
    const reopen = () => usePermissionSheetStore.getState().reopen();
    const allow = { label: "Allow…", onClick: (event: { preventDefault(): void }) => { event.preventDefault(); reopen(); } };
    const retryAction = retrying
      ? { label: "Retrying…", onClick: (event: { preventDefault(): void }) => event.preventDefault() }
      : { label: "Retry", onClick: (event: { preventDefault(): void }) => { event.preventDefault(); retry(); } };
    const action = notice.retry ? retryAction : allow;
    const cancel = notice.retry && notice.allow ? <button type="button" data-button="" data-cancel="" onClick={reopen}>Allow…</button> : undefined;
    toast.warning(notice.title, { id: CREDENTIALS_RETRY, description: notice.description, duration: Infinity, action, cancel });
  }, [status.data, retry, retrying]);
  const { isRefetchError, error } = status;
  useEffect(() => {
    const failure = statusCheckFailure({ isRefetchError, error });
    if (!failure) {
      toast.dismiss(STATUS_CHECK);
      return;
    }
    toast.error(failure.title, { id: STATUS_CHECK, description: failure.description });
  }, [isRefetchError, error]);
  return <CredentialPermissionSheet status={status.data} settle={next => queryClient.setQueryData(identityMigrationKey, next)} />;
}

function Page({ title, children }: { title: string; children: ReactNode }) {
  return <div className="app-shell flex min-h-screen items-center justify-center p-8">
    <div className="w-full max-w-lg space-y-4">
      <BrandMark className="h-12 w-14 text-primary" />
      <h1 className="app-inspector-title">{title}</h1>
      {children}
    </div>
  </div>;
}

/** What failed to move, and, for a folder the app can start without, what starting without it means. */
const FOLDERS: Partial<Record<MigrationStep, { what: string; without?: string }>> = {
  data_root: { what: "Lunport could not move its data folder." },
  backups_root: { what: "Lunport could not move the folder with its backups of your SSH configuration.", without: "Earlier backups of your SSH configuration stay in the old folder." },
  webkit_store: { what: "Lunport could not move the folder with its interface settings (theme, update channel and sidebar).", without: "The theme, update channel and sidebar start from their defaults." },
};

const CHOICES: Record<ConflictChoice, { title: string; description: string; action: string }> = {
  use_old_data: {
    title: "Use the data from the earlier version?",
    description: "The new folders are moved aside next to them first, so nothing is deleted. Lunport then restarts with the earlier data.",
    action: "Use earlier data",
  },
  keep_new: {
    title: "Keep the data in the new folder?",
    description: "The earlier folder stays where it is, unchanged, and Lunport stops asking. Lunport then restarts.",
    action: "Keep new data",
  },
};

type Confirm = ConflictChoice | "continue";

function IdentityMigrationBlocked({ status }: { status: MigrationStatus }) {
  const queryClient = useQueryClient();
  const settle = (next: MigrationStatus) => queryClient.setQueryData(identityMigrationKey, next);
  const retry = useMutation({ mutationFn: () => tauriInvoke<MigrationStatus>("identity_migration_retry"), onSuccess: settle });
  const resolve = useMutation({ mutationFn: (choice: ConflictChoice) => tauriInvoke<MigrationStatus>("identity_migration_resolve_conflict", { choice }), onSuccess: settle });
  const leave = useMutation({ mutationFn: () => tauriInvoke<MigrationStatus>("identity_migration_continue_without_moving"), onSuccess: settle });
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const busy = retry.isPending || resolve.isPending || leave.isPending;
  const failure = retry.error ?? resolve.error ?? leave.error;
  const folder = status.failed_step ? FOLDERS[status.failed_step] : undefined;
  const dialog = confirm === "continue"
    ? { title: "Continue without moving this folder?", description: `The folder stays where it is, unchanged, so nothing is deleted. ${folder?.without ?? ""} Lunport then restarts.`, action: "Continue without moving", run: () => leave.mutate(undefined, { onSettled: () => setConfirm(null) }) }
    : confirm ? { ...CHOICES[confirm], run: () => resolve.mutate(confirm, { onSettled: () => setConfirm(null) }) } : null;
  const title = status.state === "conflict" ? "Choose which Lunport data to keep" : "Finish moving your Lunport data";
  return <Page title={title}>
    {status.state === "deferred" && !status.failed_step && <>
      <p className="text-sm text-muted-foreground">This version of Lunport keeps your hosts, keys and settings in a new folder. Another Lunport window, or an AI client connected to an earlier Lunport, is still using the old folder, so the move could not finish.</p>
      <p className="text-sm text-muted-foreground">Quit other Lunport windows and AI client connections, then retry. Nothing has been deleted or merged.</p>
    </>}
    {status.state === "deferred" && status.failed_step && <>
      <p className="text-sm text-muted-foreground">{folder?.what ?? "Lunport could not finish moving its data."} Nothing has been deleted or merged.</p>
      {folder?.without && <p className="text-sm text-muted-foreground">Retry, or continue without moving it: the folder stays where it is, unchanged.</p>}
    </>}
    {status.state === "deferred" && <>
      {status.detail && <p className="break-words text-xs text-muted-foreground">{status.detail}</p>}
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy} onClick={() => retry.mutate()}>{retry.isPending ? "Retrying…" : "Retry"}</Button>
        {folder?.without && <Button variant="outline" disabled={busy} onClick={() => setConfirm("continue")}>Continue without moving…</Button>}
      </div>
    </>}
    {status.state === "conflict" && <>
      <p className="text-sm text-muted-foreground">Lunport found data both in the folder an earlier version used and in its new folder. Nothing was merged or changed.</p>
      <dl className="space-y-2 text-sm">
        <div><dt className="text-muted-foreground">Earlier version</dt><dd className="break-all font-mono text-xs">{status.old_path}</dd></div>
        <div><dt className="text-muted-foreground">New folder</dt><dd className="break-all font-mono text-xs">{status.new_path}</dd></div>
      </dl>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={busy} onClick={() => setConfirm("use_old_data")}>Use the earlier data…</Button>
        <Button variant="outline" disabled={busy} onClick={() => setConfirm("keep_new")}>Keep the new data…</Button>
      </div>
    </>}
    {failure && <p role="alert" className="text-sm text-destructive">{String(failure)}</p>}
    <AlertDialog open={dialog !== null} onOpenChange={open => { if (!open && !busy) setConfirm(null); }}>
      {dialog && <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{dialog.title}</AlertDialogTitle><AlertDialogDescription>{dialog.description}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button disabled={busy} onClick={dialog.run}>{busy ? "Restarting…" : dialog.action}</Button></AlertDialogFooter></AlertDialogContent>}
    </AlertDialog>
  </Page>;
}
