import { useEffect, useId, useRef, useState } from "react";
import { LoaderCircle } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { TaskDialogBody } from "@/components/app/TaskDialog";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { RecordOverview } from "@/lib/records";
import type { StandardPostgresDraft, StandardPostgresProfile } from "@/lib/standard-postgres";
import { DatabaseRouteHostPicker } from "./DatabaseRouteHostPicker";
import { choice, segmented } from "./IapRouteFields";
import { RecordField } from "./form";

const NEW_PROFILE: StandardPostgresDraft = {
  name: "", host: "", port: 5432, database: "postgres", username: "", via_host: null,
};

type Props = {
  initial: StandardPostgresProfile | null;
  overview: RecordOverview;
  busy: boolean;
  error: string | null;
  onDirty: (dirty: boolean) => void;
  onSave: (draft: StandardPostgresDraft, password: string | null, forgetPassword: boolean, expectedRoute?: string) => void;
  onCancel: () => void;
};

export function StandardPostgresEditor({ initial, overview, busy, error, onDirty, onSave, onCancel }: Props) {
  const original = initial ?? NEW_PROFILE;
  const [name, setName] = useState(original.name);
  const [host, setHost] = useState(original.host);
  const [port, setPort] = useState(String(original.port));
  const [database, setDatabase] = useState(original.database);
  const [username, setUsername] = useState(original.username);
  const [viaHost, setViaHost] = useState(original.via_host);
  const [throughHost, setThroughHost] = useState(original.via_host !== null || initial?.route_unavailable === true);
  const [reselectedHost, setReselectedHost] = useState(false);
  const [search, setSearch] = useState("");
  const [remember, setRemember] = useState(initial?.has_password ?? false);
  const [hasPasswordInput, setHasPasswordInput] = useState(false);
  const passwordInput = useRef<HTMLInputElement>(null);
  const passwordId = useId();
  const formId = useId();
  const needsReselection = throughHost && initial?.route_unavailable === true && !reselectedHost;
  const routeReady = !throughHost || !needsReselection && overview.hosts.some((candidate) => candidate.id === viaHost);
  const draft = {
    name, host: host.trim(), port: Number(port), database, username,
    via_host: throughHost ? viaHost : null,
  };
  const connectionChanged = draft.host !== original.host || draft.port !== original.port || draft.database !== original.database ||
    draft.username !== original.username || draft.via_host !== original.via_host || initial?.route_unavailable === true && reselectedHost;
  const hasSavedPassword = initial?.has_password ?? false;
  const dirty = draft.name !== original.name || connectionChanged || throughHost !== (original.via_host !== null || initial?.route_unavailable === true) ||
    remember !== hasSavedPassword || hasPasswordInput;
  useEffect(() => onDirty(dirty), [dirty, onDirty]);
  const requiredPassword = remember && (!hasSavedPassword || connectionChanged);
  const ready = [draft.name, draft.host, draft.database, draft.username].every((value) => value.trim() !== "") && Number.isInteger(draft.port) &&
    draft.port >= 1 && draft.port <= 65535 && routeReady;

  return <>
    <form id={formId} className="min-h-0" onSubmit={(event) => {
      event.preventDefault();
      if (busy || !ready) return;
      const password = remember ? passwordInput.current?.value || null : null;
      if (requiredPassword && password === null) return;
      if (passwordInput.current) passwordInput.current.value = "";
      setHasPasswordInput(false);
      const expectedRoute = reselectedHost && initial?.route_unavailable && draft.via_host === initial.via_host
        ? initial.route_revision ?? undefined : undefined;
      onSave(draft, password, hasSavedPassword && !remember, expectedRoute);
    }}>
      <TaskDialogBody>
        <fieldset disabled={busy} className="min-w-0 space-y-4">
          <RecordField label="Name"><Input value={name} required placeholder="Reporting" onChange={(event) => setName(event.target.value)} /></RecordField>
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_7rem]">
            <RecordField label="Host"><Input value={host} required placeholder="db.example.com" className="font-mono" onChange={(event) => setHost(event.target.value)} /></RecordField>
            <RecordField label="Port"><Input value={port} type="number" min={1} max={65535} required className="font-mono" onChange={(event) => setPort(event.target.value)} /></RecordField>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <RecordField label="Database"><Input value={database} required onChange={(event) => setDatabase(event.target.value)} /></RecordField>
            <RecordField label="Username"><Input value={username} required onChange={(event) => setUsername(event.target.value)} /></RecordField>
          </div>
          <div className="space-y-2">
            <p className="text-sm font-medium">Route</p>
            <RadioGroup.Root aria-label="Route" value={throughHost ? "ssh" : "direct"} disabled={busy} className={segmented}
              onValueChange={(route) => { setThroughHost(route === "ssh"); setSearch(""); }}>
              <RadioGroup.Item value="direct" className={choice}>Direct</RadioGroup.Item>
              <RadioGroup.Item value="ssh" className={choice}>Through an SSH host</RadioGroup.Item>
            </RadioGroup.Root>
            {throughHost && <DatabaseRouteHostPicker overview={overview} selectedId={viaHost} needsReselection={needsReselection} query={search}
              onQuery={setSearch} onSelect={(id) => { setViaHost(id); setReselectedHost(true); }} busy={busy} />}
          </div>
          <div className="space-y-3 border-t pt-4">
            <label className="flex items-start gap-3 text-sm">
              <Switch checked={remember} disabled={busy} onCheckedChange={(checked) => { setRemember(checked); if (!checked) setHasPasswordInput(false); }} />
              <span>Remember password on this device</span>
            </label>
            {remember ? <div className="app-field space-y-2">
              <Label htmlFor={passwordId}>{hasSavedPassword && !connectionChanged ? "New password" : "Password"}</Label>
              <Input id={passwordId} ref={passwordInput} type="password" autoComplete="off" required={requiredPassword}
                onChange={(event) => setHasPasswordInput(event.target.value.length > 0)} />
              {hasSavedPassword && <p className="text-xs text-muted-foreground">{connectionChanged
                ? "Enter the password again to remember it with these connection settings."
                : "Leave blank to keep the saved password."}</p>}
            </div> : <p className="text-xs text-muted-foreground">{hasSavedPassword
              ? "Saving removes the stored password. Lunport will ask when you connect."
              : "Lunport will ask for the password when you connect."}</p>}
          </div>
        </fieldset>
      </TaskDialogBody>
    </form>
    <DialogFooter>
      {error && <p role="alert" className="min-w-0 flex-1 basis-60 self-center text-sm text-destructive">{error}</p>}
      <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>Cancel</Button>
      <Button type="submit" form={formId} disabled={busy || !ready || requiredPassword && !hasPasswordInput}>
        {busy && <LoaderCircle className="size-3 animate-spin" />}Save database
      </Button>
    </DialogFooter>
  </>;
}
