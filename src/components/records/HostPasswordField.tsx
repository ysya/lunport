import { useEffect, useId, useState } from "react";
import { Eye, EyeOff, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { tauriInvoke } from "@/lib/ipc";

// Kept only in the editor's memory, separate from the host payload and query cache.
export type PasswordChange =
  | { kind: "set"; value: string }
  | { kind: "delete" }
  | null;

export async function saveHostPassword(id: string, change: PasswordChange): Promise<void> {
  if (!change) return;
  try {
    if (change.kind === "set") {
      await tauriInvoke("secrets_set", { alias: id, password: change.value });
    } else {
      await tauriInvoke("secrets_delete", { alias: id });
    }
  } catch {
    // Native failures must not echo the submitted credential into a toast or log.
    throw new Error("Host saved. Couldn’t save the password change on this device. Retry Save changes, or discard the password change.");
  }
}

export function HostPasswordField({ hostId, change, onChange }: {
  hostId: string | null;
  change: PasswordChange;
  onChange: (change: PasswordChange) => void;
}) {
  const id = useId();
  const [saved, setSaved] = useState<boolean | null>(null);
  const [failed, setFailed] = useState(false);
  const [shown, setShown] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setSaved(null);
    setFailed(false);
    if (!hostId) {
      setSaved(false);
      return;
    }
    void tauriInvoke<boolean>("secrets_has", { alias: hostId }).then(
      value => { if (active) setSaved(value); },
      () => { if (active) setFailed(true); },
    );
    return () => { active = false; };
  }, [hostId, retry]);
  useEffect(() => { setShown(false); }, [hostId, change?.kind]);
  return <section className="space-y-3 rounded-lg border bg-muted/20 p-4" aria-label="Host password">
    <div className="flex items-center gap-2 text-sm font-medium">
      <LockKeyhole className="size-4 text-muted-foreground" />Password
    </div>
    <p className="text-xs text-muted-foreground">
      {change?.kind === "set" ? "This password will be saved when you save the host."
        : change?.kind === "delete" ? "The saved password will be removed when you save changes."
        : saved ? "A password is saved on this device."
        : failed ? "Saved password status is unavailable."
        : saved === null ? "Checking this device’s credential store…"
        : "Enter your password in Lunport when you connect."}
    </p>
    {change?.kind === "set" ? <>
      <Label htmlFor={id}>{saved ? "New password" : "Password to save"}</Label>
      <div className="flex gap-2">
        <Input
          id={id}
          type={shown ? "text" : "password"}
          value={change.value}
          autoComplete="new-password"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          onChange={event => onChange({ kind: "set", value: event.target.value })}
        />
        <Button
          type="button" variant="outline" size="icon"
          aria-label={shown ? "Hide password" : "Show password"}
          aria-pressed={shown}
          onClick={() => setShown(value => !value)}
        >
          {shown ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </Button>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={() => onChange(null)}>Cancel password change</Button>
    </> : <div className="flex flex-wrap gap-2">
      {change?.kind === "delete" ? (
        <Button type="button" variant="outline" size="sm" onClick={() => onChange(null)}>Keep saved password</Button>
      ) : <>
        <Button type="button" variant="outline" size="sm" onClick={() => onChange({ kind: "set", value: "" })}>
          {saved ? "Replace password" : "Save password on this device"}
        </Button>
        {saved && (
          <Button type="button" variant="ghost" size="sm" onClick={() => onChange({ kind: "delete" })}>Remove saved password</Button>
        )}
        {failed && (
          <Button type="button" variant="ghost" size="sm" onClick={() => setRetry(value => value + 1)}>Retry status</Button>
        )}
      </>}
    </div>}
    <p className="text-xs text-muted-foreground">Stored in the system credential store on this device. Passwords never sync.</p>
  </section>;
}
