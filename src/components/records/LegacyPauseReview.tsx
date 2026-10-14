import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
export function LegacyPauseReview({
  saved,
  busy,
  setSaved,
  confirm,
  cancel,
  error,
}: {
  saved: boolean;
  busy: boolean;
  setSaved: (value: boolean) => void;
  confirm: () => void;
  cancel: () => void;
  error: string | null;
}) {
  return (
    <section
      role="alertdialog"
      aria-label="Pause for migration"
      className="mx-auto max-w-lg space-y-4 rounded-md border bg-background p-6"
    >
      <h1 className="text-lg font-semibold">Pause for migration</h1>
      <p className="text-sm text-muted-foreground">
        Save your editor changes first. Pausing stops legacy writers and opens
        the migration landing without changing the saved workspace.
      </p>
      <Label className="flex items-start gap-2">
        <Checkbox
          checked={saved}
          disabled={busy}
          onCheckedChange={(checked) => setSaved(checked === true)}
        />
        <span>I have saved my changes in the legacy editor.</span>
      </Label>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <Button disabled={busy || !saved} onClick={confirm}>
          Pause legacy workspace
        </Button>
        <Button variant="outline" disabled={busy} onClick={cancel}>
          Keep editing
        </Button>
      </div>
    </section>
  );
}
