import { useEffect, useRef, useState } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";

import type { KeyCandidate } from "@/bindings/KeyCandidate";
import type { UnsupportedIdentity } from "@/bindings/UnsupportedIdentity";
import { TONE_TEXT } from "@/components/sync-primitives";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { isImeKey } from "@/lib/ime";
import {
  choiceFor,
  isValidSlotName,
  keptNote,
  keySetupAskedBefore,
  keysToAsk,
  lockedNote,
  passphraseNote,
  rememberKeySetupAsked,
  reuseChoices,
  rewrittenLines,
  usesLine,
  type KeySetupRequest,
} from "@/lib/key-slots";
import { useHostsQuery } from "@/lib/queries";
import { useKeyCandidates, useSetupKeys, useSyncOverview } from "@/lib/sync";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

/**
 * One key's row: the hosts that use it, the question, what changes, and the two answers. A slot kept from the previous sync
 * account goes in under its own name: no Rename, and a note says where it came from. Exported for the markup tests.
 */
export function KeySetupRow({
  candidate,
  busy,
  onChoose,
}: {
  candidate: KeyCandidate;
  busy: boolean;
  onChoose: (sync: boolean, name: string) => void;
}) {
  const [typed, setTyped] = useState(candidate.default_name);
  const [renaming, setRenaming] = useState(false);
  const kept = candidate.kept_slot !== null;
  const keptText = keptNote(candidate);
  const name = kept ? candidate.default_name : typed;
  const valid = isValidSlotName(name);
  const note = passphraseNote(candidate);
  const locked = lockedNote(candidate);
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-start justify-between gap-2">
        <p className="flex items-center gap-1.5 text-sm">
          <KeyRound className="size-3.5 shrink-0 text-muted-foreground" />
          {usesLine(candidate, name)}
        </p>
        {!renaming && !kept && (
          <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" disabled={busy} onClick={() => setRenaming(true)}>
            Rename
          </Button>
        )}
      </div>
      {renaming && !kept && (
        <Input
          autoFocus
          value={typed}
          aria-label="Key name"
          className={cn("h-7 font-mono text-xs", !valid && "border-destructive")}
          onChange={(e) => setTyped(e.target.value)}
          onKeyDown={(e) => {
            if (isImeKey(e)) return;
            if (e.key === "Enter" && valid) setRenaming(false);
          }}
          onBlur={() => valid && setRenaming(false)}
        />
      )}
      <p className="text-sm">Sync this key to your other computers?</p>
      {keptText && <p className="text-xs text-muted-foreground">{keptText}</p>}
      {note && <p className="text-xs text-muted-foreground">{note}</p>}
      <ul className="space-y-0.5 font-mono text-xs text-muted-foreground">
        {rewrittenLines(candidate, name).map((line) => (
          <li key={line} className="break-all">
            {line}
          </li>
        ))}
      </ul>
      {locked && <p className={cn("text-xs", TONE_TEXT.warning)}>{locked}</p>}
      {candidate.unsyncable && <p className={cn("text-xs", TONE_TEXT.warning)}>{candidate.unsyncable}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" size="sm" disabled={busy || !valid} onClick={() => onChoose(false, name)}>
          Keep on this computer
        </Button>
        <Button type="button" size="sm" disabled={busy || !valid || candidate.unsyncable !== null} onClick={() => onChoose(true, name)}>
          Sync key
        </Button>
      </div>
    </div>
  );
}

/** Values SSHelter can't set up by itself (spec §5). Exported for the markup tests. */
export function UnsupportedList({ items }: { items: UnsupportedIdentity[] }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium text-muted-foreground">Can't set up automatically</p>
      <ul className="space-y-0.5 text-xs text-muted-foreground">
        {items.map((u) => (
          <li key={`${u.alias} ${u.value}`} className="break-all">
            {`${u.alias}: ${u.value} — ${u.reason}`}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Whether the dialog may be answered or closed: not while a choice is being applied, and not while the keys are read
 * again. A successful answer starts that read before the answer is reported, so for a moment the rows on screen are
 * still the old ones, the key just answered among them: a second click would act on a key that is already set up.
 * Exported for the tests.
 */
export function dialogBusy({ applying, rereading }: { applying: boolean; rereading: boolean }): boolean {
  return applying || rereading;
}

/**
 * "Keys used by synced hosts" (SP3 spec §7.1). Opens from the UI store (`keySetup`): after hosts move into a space,
 * after a save or a deploy that wrote IdentityFile, once after the update, or from Settings → Sync. Keys that already
 * have a slot are set up without asking; with nothing left to ask, it closes by itself without showing. It also runs the
 * question after the update (`useKeySetupOnUpgrade`): this component is mounted once and is a leaf, so the overview
 * updates that hook follows through the session don't re-render the app shell.
 */
export function SyncKeyDialog() {
  useKeySetupOnUpgrade();
  const request = useUiStore((s) => s.keySetup);
  const setRequest = useUiStore((s) => s.setKeySetup);
  const candidates = useKeyCandidates(request !== null);
  const { refetch } = candidates;
  const setup = useSetupKeys();
  // Each request reads the hosts as they are now: the edit or move that opened it just changed them, and host edits don't
  // refresh the candidates. Until that read is back nothing shows (the cached list may still have the old hosts).
  const [readFor, setReadFor] = useState<KeySetupRequest | null>(null);
  useEffect(() => {
    if (!request) return;
    let current = true;
    void refetch().then(() => {
      if (current) setReadFor(request);
    });
    return () => {
      current = false;
    };
  }, [request, refetch]);
  const ready = request !== null && readFor === request;
  const aliases = request?.aliases ?? null;
  const ask = ready ? keysToAsk(candidates.data, aliases) : [];
  const reuse = ready ? reuseChoices(candidates.data, aliases) : [];
  const reusedFor = useRef<KeySetupRequest | null>(null);

  useEffect(() => {
    if (!request || !ready || candidates.isFetching) return;
    if (reuse.length > 0 && reusedFor.current !== request) {
      reusedFor.current = request;
      setup.mutate({ choices: reuse });
    }
    if (ask.length === 0) setRequest(null);
  }, [request, ready, candidates.isFetching, ask.length, reuse, setup, setRequest]);

  const close = () => setRequest(null);
  const later = request?.reason === "upgrade" || request?.reason === "settings";
  const busy = dialogBusy({ applying: setup.isPending, rereading: candidates.isFetching });
  return (
    <Dialog open={ready && ask.length > 0} onOpenChange={(next) => !next && !busy && close()}>
      <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
        <DialogHeader>
          <DialogTitle>Keys used by synced hosts</DialogTitle>
          <DialogDescription>Choose for each key whether it goes to your other computers. Your servers aren't changed.</DialogDescription>
        </DialogHeader>
        <div className="max-h-[50vh] space-y-3 overflow-y-auto pr-1">
          {ask.map((candidate) => (
            <KeySetupRow
              key={candidate.path}
              candidate={candidate}
              busy={busy}
              onChoose={(sync, name) =>
                setup.mutate(
                  { choices: [choiceFor(candidate, sync, name)] },
                  { onSuccess: () => toast.success(sync ? `${name} syncs to your other computers` : `${name} stays on this computer`) },
                )
              }
            />
          ))}
        </div>
        <UnsupportedList items={candidates.data?.unsupported ?? []} />
        <DialogFooter>
          <Button type="button" variant="outline" disabled={busy} onClick={close}>
            {later ? "Later" : "Close"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Whether the question after the update may be decided now: this computer syncs, its config has loaded and it was not
 * asked before. The backend scans the config it holds and, while it holds none, answers an empty list rather than an
 * error. At start-up the config load and the sync overview run side by side, so deciding on that empty answer would
 * mark the question as asked and it would never appear. Exported for the tests: effects don't run under a server render.
 */
export function shouldAskOnUpgrade({
  joined,
  configLoaded,
  askedBefore,
}: {
  joined: boolean;
  configLoaded: boolean;
  askedBefore: boolean;
}): boolean {
  return joined && configLoaded && !askedBefore;
}

/**
 * After the SP3 update, synced hosts may already use this computer's keys: ask once per computer (spec §7.1), once the
 * config has loaded (`shouldAskOnUpgrade`). "Later" leaves them in the Settings → Sync row.
 */
export function useKeySetupOnUpgrade() {
  const overview = useSyncOverview();
  const config = useHostsQuery();
  const enabled = shouldAskOnUpgrade({
    joined: overview.data?.joined === true,
    configLoaded: config.isSuccess,
    askedBefore: keySetupAskedBefore(),
  });
  const candidates = useKeyCandidates(enabled);
  const setRequest = useUiStore((s) => s.setKeySetup);
  useEffect(() => {
    if (!enabled || !candidates.data) return;
    rememberKeySetupAsked();
    if (keysToAsk(candidates.data, null).length > 0 || reuseChoices(candidates.data, null).length > 0) {
      setRequest({ aliases: null, reason: "upgrade" });
    }
  }, [enabled, candidates.data, setRequest]);
}
