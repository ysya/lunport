import { useState } from "react";
import { Copy } from "lucide-react";
import { toast } from "sonner";

import { errorMessage } from "@/lib/sync";
import type { Tone } from "@/lib/sync-overview";
import { copyText } from "@/lib/clipboard";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/** Text color for a status tone (Settings → Sync rows, space rows). */
export const TONE_TEXT: Record<Tone, string> = {
  ok: "text-muted-foreground",
  busy: "text-muted-foreground",
  warning: "text-amber-700 dark:text-amber-400",
  error: "text-destructive",
};

/** The 24 words, numbered, with a copy button. The words never go into a toast. */
export function WordGrid({ words }: { words: string }) {
  const copy = async () => {
    try {
      await copyText(words);
      toast.success("Sync code copied — clear your clipboard when done");
    } catch (error) {
      toast.error("Clipboard unavailable", { description: errorMessage(error) });
    }
  };
  return (
    <div className="space-y-2">
      <ol className="grid grid-cols-3 gap-x-4 gap-y-1 rounded-md border bg-muted/40 p-3 font-mono text-sm select-text">
        {words.split(" ").map((w, i) => (
          <li key={`${i}-${w}`} className="flex gap-2">
            <span className="w-5 text-right text-muted-foreground tabular-nums">{i + 1}</span>
            {w}
          </li>
        ))}
      </ol>
      <Button type="button" variant="outline" size="sm" className="h-7" onClick={() => void copy()}>
        <Copy className="size-3.5" /> Copy
      </Button>
    </div>
  );
}

const COPY = {
  created: {
    title: "Your sync code",
    description:
      "Enter these 24 words on every other computer you want to sync. Anyone with them can read and change your synced hosts, so keep them in a password manager. Any computer in this sync account can show them again under Settings → Sync.",
    confirm: "I have saved these words somewhere safe",
  },
  changed: {
    title: "Your new sync code",
    description:
      "The old sync code no longer works. Enter these 24 words on each of your other computers (Settings → Sync → Enter the new sync code), and replace the old code in your password manager.",
    confirm: "I have saved the new sync code",
  },
  shown: {
    title: "Sync code",
    description: "Enter these words on another computer under Settings → Sync → Join with a sync code.",
    confirm: null,
  },
} as const;

/**
 * The sync code in a dialog. `created` and `changed` cannot be dismissed until the
 * user confirms they saved the words; `shown` closes freely. Owners keep `words`
 * in component state and set it back to null in `onDone`. `description` replaces the
 * mode's own text when the state calls for another (the old code during a sync code change).
 * `note` is shown under the description, e.g. which synced keys to replace after a sync code change.
 */
export function SyncCodeDialog({
  words,
  mode,
  description,
  note,
  onDone,
}: {
  words: string | null;
  mode: keyof typeof COPY;
  description?: string;
  note?: string;
  onDone: () => void;
}) {
  const [saved, setSaved] = useState(false);
  const copy = COPY[mode];
  const mustConfirm = copy.confirm !== null;
  const finish = () => {
    setSaved(false);
    onDone();
  };
  return (
    <Dialog
      open={words !== null}
      onOpenChange={(open) => {
        if (!open && (!mustConfirm || saved)) finish();
      }}
    >
      <DialogContent
        className="sm:max-w-lg"
        showCloseButton={!mustConfirm}
        onEscapeKeyDown={(e) => {
          if (mustConfirm && !saved) e.preventDefault();
        }}
        onPointerDownOutside={(e) => {
          if (mustConfirm && !saved) e.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle>{copy.title}</DialogTitle>
          <DialogDescription>{description ?? copy.description}</DialogDescription>
        </DialogHeader>
        {note && <p className={cn("text-sm", TONE_TEXT.warning)}>{note}</p>}
        <WordGrid words={words ?? ""} />
        {copy.confirm !== null && (
          <>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={saved} onCheckedChange={(v) => setSaved(v === true)} />
              {copy.confirm}
            </label>
            <DialogFooter>
              <Button type="button" disabled={!saved} onClick={finish}>
                Continue
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
