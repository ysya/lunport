import { useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import type { MigrationStatus } from "@/bindings/MigrationStatus";
import { tauriInvoke } from "@/lib/ipc";
import { usePermissionSheetStore } from "@/stores/permission-sheet";
import { Button } from "@/components/ui/button";
import { AlertDialog, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";

/** What the sheet asks of the user; `null` when no saved credential waits for their permission, or while the app is not open. */
export type PermissionRequest = { count: number; title: string; description: string };

/**
 * The saved credentials (passwords, keys) that Lunport could not move from the earlier version by itself: macOS asks once for each
 * before Lunport may move it. `null` when none wait.
 */
export function permissionRequest(status: MigrationStatus | undefined): PermissionRequest | null {
  if (status?.state !== "credentials_pending" && status?.state !== "completed") return null;
  const count = status.credentials_need_permission;
  if (count <= 0) return null;
  return {
    count,
    title: count === 1 ? "1 saved item needs your permission once" : `${count} saved items need your permission once`,
    description:
      "Lunport could not move these saved passwords and keys from the earlier version by itself. For each one, macOS asks whether Lunport Credential Helper may use it, and may ask for your login password: choose “Always Allow”. Nothing is deleted before its copy is saved.",
  };
}

/**
 * Whether the sheet shows for `count` items once the user has answered it for `answered` items (Later, or Continue): again only when
 * more wait than they answered for.
 */
export function sheetShows(count: number, answered: number | null): boolean {
  return count > 0 && (answered === null || count > answered);
}

/**
 * For how many items the user has answered the sheet: in this window (`answered`, from `usePermissionSheetStore`), or else with Later
 * at an earlier start, which the backend remembers unless a vault key waits for permission. `null` when they have not.
 */
export function answeredFor(status: MigrationStatus | undefined, answered: number | null): number | null {
  return answered ?? (status?.credentials_permission_put_off || null);
}

/**
 * What the app says, once the user answered the sheet (Later, here or at an earlier start, or a Continue after which some still wait:
 * they denied it, say), of what still waits for their permission, and how to allow it. `null` while the sheet shows, when nothing
 * waits, and where the credentials notice offers Allow… itself (the vault waits for its key: `failed_step` is the credential step).
 */
export function permissionReminder(status: MigrationStatus | undefined, answered: number | null): { title: string; description: string } | null {
  const request = permissionRequest(status);
  if (!request || sheetShows(request.count, answered) || status?.failed_step === "credentials") return null;
  return {
    title: request.count === 1 ? "1 saved item still needs your permission" : `${request.count} saved items still need your permission`,
    description:
      "They stay where they were, under the earlier version's name, and nothing was deleted. Allow… asks again: choose “Always Allow” when macOS asks. Lunport reminds you each time it starts.",
  };
}

const PERMISSION_REMINDER = "identity-migration-permission";

/** The sheet itself: why, and Continue or Later. No hooks, so that a test can read and press it. */
export function PermissionSheetView({ request, busy, error, onContinue, onLater }: {
  request: PermissionRequest;
  busy: boolean;
  error: unknown;
  onContinue: () => void;
  onLater: () => void;
}) {
  return <AlertDialog open onOpenChange={open => { if (!open && !busy) onLater(); }}>
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>{request.title}</AlertDialogTitle>
        <AlertDialogDescription>{request.description}</AlertDialogDescription>
      </AlertDialogHeader>
      <p className="text-sm text-muted-foreground">Later keeps them where they are; Lunport reminds you of them, and Allow… asks again when you are ready.</p>
      {error ? <p role="alert" className="break-words text-sm text-destructive">{String(error)}</p> : null}
      <AlertDialogFooter>
        <Button variant="outline" disabled={busy} onClick={onLater}>Later</Button>
        <Button disabled={busy} onClick={onContinue}>{busy ? "Waiting for macOS…" : "Continue"}</Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>;
}

/**
 * Asks the user's permission for the saved credentials that wait for it (`identity_migration_adopt_credentials`): Continue lets macOS
 * ask once for each, Later leaves them where they are, and the backend remembers it for later starts
 * (`identity_migration_put_off_credentials`). `settle` takes the status the backend answers with. Once answered, here or with Later at
 * an earlier start (`answeredFor`), the sheet stays away until more wait than the user answered for, or until the credentials notice's
 * Allow… reopens it (`usePermissionSheetStore`); a reminder says how to allow what still waits (`permissionReminder`).
 */
export function CredentialPermissionSheet({ status, settle }: { status: MigrationStatus | undefined; settle: (next: MigrationStatus) => void }) {
  const answered = answeredFor(status, usePermissionSheetStore(state => state.answered));
  const request = permissionRequest(status);
  const adopt = useMutation({
    mutationFn: () => tauriInvoke<MigrationStatus>("identity_migration_adopt_credentials"),
    onSuccess: next => {
      usePermissionSheetStore.getState().answer(next.credentials_need_permission);
      settle(next);
    },
    // A run that stopped part way may still have moved some: the sheet counts what still waits, and says why it stopped.
    onError: () => void tauriInvoke<MigrationStatus>("identity_migration_status").then(settle, () => undefined),
  });
  const reminder = permissionReminder(status, answered);
  useEffect(() => {
    if (!reminder) {
      toast.dismiss(PERMISSION_REMINDER);
      return;
    }
    toast.info(reminder.title, {
      id: PERMISSION_REMINDER,
      description: reminder.description,
      action: { label: "Allow…", onClick: () => usePermissionSheetStore.getState().reopen() },
    });
  }, [reminder?.title, reminder?.description]);
  if (!request || !sheetShows(request.count, answered)) return null;
  return <PermissionSheetView
    request={request}
    busy={adopt.isPending}
    error={adopt.error}
    onContinue={() => adopt.mutate()}
    onLater={() => putOff(request.count)}
  />;
}

/**
 * Later: the sheet stays away in this window for `count` items, and the backend remembers it, so that later starts offer the reminder
 * instead. Not remembered (another Lunport holds the migration's lock, say), the next start asks again.
 */
function putOff(count: number) {
  usePermissionSheetStore.getState().answer(count);
  tauriInvoke<void>("identity_migration_put_off_credentials").catch(error => console.warn("[identity-migration] Later was not remembered:", error));
}
