import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Copy, LoaderCircle, Lock, LockOpen, RotateCw } from "lucide-react";
import { toast } from "sonner";
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
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/clipboard";
import { revealHidden } from "@/lib/reveal-hidden";
import { useNow } from "@/lib/use-now";
import {
  connectionUrl,
  databasePassword,
  databasePort,
  lockDatabaseWrites,
  reconnectLockedConnections,
  rotateDatabasePassword,
  runDatabaseAction,
  unlockDatabaseWrites,
  unlockMethod,
  writableLeft,
  writableSecondsLeft,
  type DatabaseView,
} from "@/lib/databases";

/*
 * What other apps need to connect to a database that is offered on a local port, and the write lock of a prod one: the address with
 * its Copy URL, Copy password and Rotate password, and for prod the lock itself, Reconnect now and the seconds left. The password is never
 * drawn: it goes from the keychain to the clipboard when a button asks for it.
 *
 * `DatabaseAccessCard` keeps the state and does the work; `DatabaseAccessView` is the card without hooks, so that the tests can press it.
 */

const COPY_FAILED = "Could not copy to the clipboard.";
const ROTATED_NOT_COPIED = "The password was rotated, but it could not be copied. Use Copy password.";
/** The seconds below which the card says that writes are about to lock. */
const LOCKING_SOON_SECONDS = 60;

/** Puts `text` on the clipboard. The clipboard plugin's own words are not passed on: they could hold anything, so `failure` is said instead. */
async function toClipboard(text: string, failure: string): Promise<void> {
  try {
    await copyText(text);
  } catch {
    throw new Error(failure);
  }
}

/**
 * Puts the database's port password on the clipboard. It is asked of the keychain when this runs, and held nowhere on the way: this is
 * neither a query nor a mutation (both keep their results), and the password is in no state of the card and on no page. The first ask makes
 * the password, so that it can be copied before the database has ever started.
 */
export async function copyPassword(id: string): Promise<void> {
  await toClipboard(await databasePassword(id), COPY_FAILED);
}

/**
 * Replaces the database's port password and puts the new one on the clipboard, held nowhere, as `copyPassword` does. Connections that
 * are open go on; the old password no longer works for new ones, so the new one is copied at once. A copy that fails says the password
 * was rotated, and that Copy password has it.
 */
export async function rotatePassword(id: string): Promise<void> {
  await toClipboard(await rotateDatabasePassword(id), ROTATED_NOT_COPIED);
}

/**
 * Starts unlocking writes on the prod database `id`, in the way this computer confirms an unlock. Where the system asks the person itself
 * (Touch ID, the Mac's password), the backend is asked to unlock at once and answers once the person has confirmed; the page's own yes is
 * not given. Where the system cannot, the page asks in a dialog of its own: `askInApp` opens it, nothing is unlocked yet, and the dialog's
 * confirmation unlocks with the page's yes (`unlockDatabaseWrites(id, true)`). The backend refuses what cannot be unlocked, in its own words.
 */
export async function beginUnlock(id: string, askInApp: () => void): Promise<void> {
  if ((await unlockMethod()) === "system") await unlockDatabaseWrites(id, false);
  else askInApp();
}

/** What Reconnect now says of the connections it closed. */
const reconnectLine = (closed: number) => (closed === 0 ? "No idle read-only connections to close." : `Closed ${closed} idle read-only connection${closed === 1 ? "" : "s"}.`);

/**
 * The time at this render, in milliseconds since the Unix epoch, with a render every second so that a countdown keeps moving. `useNow`
 * only schedules those renders: the time it answers is kept in state, so it can be up to a second old, while the end of a window that
 * the backend answered just now is not, and a countdown worked out from the two would show more time than the window has (15:01).
 */
function useRenderTime(): number {
  useNow(1000);
  return Date.now();
}

/** The change under way. Until it ends every control of the card is held. */
export type Step = "url" | "password" | "rotate" | "unlock" | "lock" | "reconnect";
/** The question the card asks before it acts: before it rotates the password, and where the system cannot ask, before it unlocks writes. */
export type Question = "rotate" | "unlock";

/** What the card's controls do. The ones that change something answer when they are done. */
export type AccessActions = {
  copyUrl: () => Promise<void>;
  copyPassword: () => Promise<void>;
  /** Opens a question, or closes the one that is open. */
  ask: (question: Question | null) => void;
  rotate: () => Promise<void>;
  /** The lock button while writes are locked. */
  unlock: () => Promise<void>;
  /** The yes to the page's own question about unlocking. */
  confirmUnlock: () => Promise<void>;
  /** The lock button while writes are on. */
  lock: () => Promise<void>;
  reconnect: () => Promise<void>;
};

export type DatabaseAccessViewProps = {
  view: DatabaseView;
  /** The address apps connect to (`connectionUrl`). */
  url: string;
  /** The time now, in milliseconds since the Unix epoch, which the countdown is worked out from. */
  now: number;
  pending: Step | null;
  /** The sentence the last change failed with. */
  error: string | null;
  asking: Question | null;
  actions: AccessActions;
};

/** One labelled group of the card. */
const group = "space-y-1.5";
const groupLabel = "text-xs font-medium text-muted-foreground";

/**
 * The lock of a prod database. It can be unlocked only while the database runs; the backend refuses otherwise, and the card says so
 * rather than ask a question that could not be answered. While writes are on it shows the time left and offers to lock again, and to
 * close the idle connections that opened before the unlock, which stay read-only until their apps connect again.
 */
function writeLock({ view, now, pending, actions }: DatabaseAccessViewProps) {
  const { live } = view;
  const busy = pending !== null;
  const left = writableLeft(live.writable_until_ms, now);
  const seconds = writableSecondsLeft(live.writable_until_ms, now);
  const hint = left !== null ? "Open connections stay read-only until their apps reconnect." : live.phase === "running" ? "Connections open read-only until you unlock writes." : "Start the database before you unlock writes.";
  return (
    <div className={group}>
      <p className={groupLabel}>Write lock</p>
      <div className="flex flex-wrap items-center gap-2">
        {left === null ? (
          <Button variant="outline" size="sm" title="Unlock writes for 15 minutes" disabled={busy || live.phase !== "running"} onClick={actions.unlock}>
            {pending === "unlock" ? <LoaderCircle className="animate-spin" /> : <Lock />}
            Locked
          </Button>
        ) : (
          <>
            <Button variant="destructive" size="sm" title="Lock writes again" disabled={busy} onClick={actions.lock}>
              {pending === "lock" ? <LoaderCircle className="animate-spin" /> : <LockOpen />}
              {`Writes on · ${left}`}
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onClick={actions.reconnect}>
              {pending === "reconnect" && <LoaderCircle className="animate-spin" />}
              Reconnect now
            </Button>
          </>
        )}
      </div>
      {seconds !== null && seconds < LOCKING_SOON_SECONDS && <p className="text-xs font-medium text-destructive">{`Writes lock again in ${seconds} s.`}</p>}
      <p className="text-xs text-muted-foreground">{hint}</p>
    </div>
  );
}

/**
 * The card drawn from the database as the list shows it. No hooks: exported for the tests. Only a prod database has the lock; whatever
 * the list says of a window for another, none is drawn. A window that has ended by the clock reads as locked even before the list is read
 * again. While a change is under way every control is held.
 */
export function DatabaseAccessView(props: DatabaseAccessViewProps) {
  const { view, url, pending, error, asking, actions } = props;
  const { database } = view;
  const name = revealHidden(database.name);
  const busy = pending !== null;
  return (
    <section aria-label={`Connection details for ${name}`} className="space-y-4 rounded-lg border bg-muted/30 p-4">
      <div className={group}>
        <p className={groupLabel}>Connection URL</p>
        <div className="flex flex-wrap items-center gap-2">
          <code className="min-w-0 flex-1 basis-64 select-text break-all rounded-md border bg-background px-2.5 py-1.5 font-mono text-xs">{url}</code>
          <Button variant="outline" size="sm" disabled={busy} onClick={actions.copyUrl}>
            <Copy />
            Copy URL
          </Button>
        </div>
      </div>
      <div className={group}>
        <p className={groupLabel}>Password</p>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" disabled={busy} onClick={actions.copyPassword}>
            <Copy />
            Copy password
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => actions.ask("rotate")}>
            <RotateCw />
            Rotate password
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">Apps sign in to the local port with it. It stays in the keychain and is never shown.</p>
      </div>
      {database.environment === "prod" && writeLock(props)}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <AlertDialog open={asking === "rotate"} onOpenChange={(open) => !open && actions.ask(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{`Rotate the password of ${name}?`}</AlertDialogTitle>
            <AlertDialogDescription>New connections need the new password. Open connections keep running.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={actions.rotate}>Rotate password</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog open={asking === "unlock"} onOpenChange={(open) => !open && actions.ask(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{`Unlock writes on ${name}?`}</AlertDialogTitle>
            <AlertDialogDescription>Writes stay on for 15 minutes or until you lock again.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={actions.confirmUnlock}>
              Unlock writes
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

/**
 * The connection details and write lock of the database `view` shows, with the database user the address names (`iamUser`). It keeps
 * what is under way, the sentence the last change failed with, and the question being asked. One change runs at a time; whatever came of
 * it the list is read again, so that the lock follows at once, and the sentence a change failed with is the backend's own, shown in the
 * card as the page shows the failure of its other changes. The countdown moves every second, from the time at each render.
 */
export function DatabaseAccessCard({ view, iamUser }: { view: DatabaseView; iamUser: string }) {
  const client = useQueryClient();
  const now = useRenderTime();
  const [pending, setPending] = useState<Step | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState<Question | null>(null);
  const flight = useRef(false);
  const id = view.database.id;
  const url = connectionUrl({ ...view.database, local_port: databasePort(view) }, iamUser);
  const act = async (step: Step, run: () => Promise<void>) => {
    if (flight.current) return;
    flight.current = true;
    setPending(step);
    setError(null);
    setError(await runDatabaseAction(client, run));
    flight.current = false;
    setPending(null);
  };
  const actions: AccessActions = {
    copyUrl: () =>
      act("url", async () => {
        await toClipboard(url, COPY_FAILED);
        toast.success("URL copied.");
      }),
    copyPassword: () =>
      act("password", async () => {
        await copyPassword(id);
        toast.success("Password copied.");
      }),
    ask: setAsking,
    rotate: () =>
      act("rotate", async () => {
        await rotatePassword(id);
        toast.success("New password copied.");
      }),
    unlock: () => act("unlock", () => beginUnlock(id, () => setAsking("unlock"))),
    confirmUnlock: () =>
      act("unlock", async () => {
        await unlockDatabaseWrites(id, true);
      }),
    lock: () => act("lock", () => lockDatabaseWrites(id)),
    reconnect: () =>
      act("reconnect", async () => {
        toast.success(reconnectLine(await reconnectLockedConnections(id)));
      }),
  };
  return <DatabaseAccessView view={view} url={url} now={now} pending={pending} error={error} asking={asking} actions={actions} />;
}
