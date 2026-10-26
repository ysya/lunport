import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cloud } from "lucide-react";
import { RadioGroup } from "radix-ui";
import type { GcloudAccountView } from "@/bindings/GcloudAccountView";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import type { RecordOverview } from "@/lib/records";
import {
  fetchOsLoginProfile,
  gcloudAccountsQuery,
  newPamCheck,
  osLoginOutcome,
  pamPlaceholder,
  parseEntitlements,
  routeSynced,
  type PamCheck,
  type TransportKind,
} from "@/lib/transports";
import { changeEditor, type EditorState } from "./editor";
import { RecordField, selectClass } from "./form";
import { routeChange, type RouteDraft, type RouteState, type Via } from "./route";

/*
 * The host editor's Connect via (design 2026-10-26, "Host editor: Connect via"): how the host is reached, at its address or through a
 * Google Cloud IAP route saved with it. The editor owns the draft; these draw it and hand every change back up.
 */

/** Two thirds for the address or the instance, one for the port beside it, so switching keeps both where they were. */
const besidePort = "grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]";
const choice =
  "inline-flex h-7 flex-1 items-center justify-center gap-1.5 rounded-md border border-transparent px-2 text-sm font-medium whitespace-nowrap text-foreground/60 transition-all outline-none hover:text-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 data-[state=checked]:bg-background data-[state=checked]:text-foreground data-[state=checked]:shadow-sm dark:text-muted-foreground dark:data-[state=checked]:border-input dark:data-[state=checked]:bg-input/30 [&_svg]:size-4 [&_svg]:shrink-0";

/**
 * The bordered Connect via block: what the choice means, the choice itself (a radio group), and the fields of the one chosen: the
 * hostname beside the port, or the IAP route with the instance in the hostname's place. `locked` turns off what would change the
 * route, the choice and the IAP fields, while the library's writes are blocked; the hostname and the port stay host fields. No hooks:
 * exported for the tests.
 */
export function ConnectVia({
  draft,
  onDraft,
  description,
  hostname,
  onHostname,
  port,
  disabled,
  locked,
}: {
  draft: RouteDraft;
  onDraft: (next: RouteDraft) => void;
  description: string;
  hostname: string;
  onHostname: (next: string) => void;
  port: ReactNode;
  disabled: boolean;
  locked: boolean;
}) {
  return (
    <div className="space-y-4 rounded-lg border bg-muted/20 p-4">
      <div className="space-y-2">
        <div>
          <p className="text-sm font-medium">Connect via</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <RadioGroup.Root
          aria-label="Connect via"
          value={draft.via}
          disabled={disabled || locked}
          onValueChange={(via) => onDraft({ ...draft, via: via as Via })}
          className="flex w-full gap-0.5 rounded-lg bg-muted p-[3px]"
        >
          <RadioGroup.Item value="address" className={choice}>
            Address
          </RadioGroup.Item>
          <RadioGroup.Item value="iap" className={choice}>
            <Cloud />
            Google Cloud IAP
          </RadioGroup.Item>
        </RadioGroup.Root>
      </div>
      {draft.via === "iap" ? (
        <IapRouteFields kind={draft.iap} onChange={(iap) => onDraft({ ...draft, iap })} disabled={disabled || locked} port={port} />
      ) : (
        <div className={besidePort}>
          <RecordField label="Hostname or IP">
            <Input
              autoComplete="off"
              placeholder="e.g. server.example.com"
              value={hostname}
              disabled={disabled}
              onChange={(e) => onHostname(e.target.value)}
            />
          </RecordField>
          {port}
        </div>
      )}
    </div>
  );
}

/**
 * Where an IAP route is kept, said under Connect via for the save the draft would make: a changed route goes where a new route goes,
 * into the library where it uses central sync (so a route kept on this computer moves in); an unchanged one stays where it is.
 */
export function connectViaDescription(route: RouteState, overview: RecordOverview, hostId: string | null): string {
  if (route.draft.via === "address") return "The hostname or IP address this host is dialed at.";
  const synced =
    routeChange(route.draft, route.saved) === undefined
      ? routeSynced(overview, hostId)
      : overview.central_mode === true && Boolean(overview.account);
  return synced ? "Saved with the host, so it syncs wherever the host does." : "Saved on this computer only.";
}

const accountLabel = (entry: GcloudAccountView) => `${entry.account}${entry.state === "expired" ? " · sign-in expired" : ""}`;

/**
 * The Google Cloud IAP side of Connect via: the instance beside the host's own `port`, the project and zone under them, and the rest
 * folded into Google Cloud options. `kind` is the route as displayed; every change goes up through `onChange`.
 */
export function IapRouteFields({
  kind,
  onChange,
  disabled,
  port,
}: {
  kind: TransportKind;
  onChange: (next: TransportKind) => void;
  disabled: boolean;
  port: ReactNode;
}) {
  const patch = (changes: Partial<TransportKind>) => onChange({ ...kind, ...changes });
  const patchPam = (changes: Partial<PamCheck>) => patch({ pam: { ...(kind.pam ?? newPamCheck()), ...changes } });
  // The Google Cloud page reads the same cache entry.
  const accounts = useQuery(gcloudAccountsQuery).data;
  const summary = [
    kind.account ?? "gcloud's active account",
    kind.os_login ? "OS Login" : null,
    kind.pam ? `PAM: ${kind.pam.entitlements.join(", ") || "no entitlement yet"}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <>
      <div className={besidePort}>
        <RecordField label="Instance">
          <Input value={kind.instance} placeholder="jumpbox" disabled={disabled} onChange={(e) => patch({ instance: e.target.value.trim() })} />
        </RecordField>
        {port}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <RecordField label="Project">
          <Input value={kind.project} placeholder="my-project-123456" disabled={disabled} onChange={(e) => patch({ project: e.target.value.trim() })} />
        </RecordField>
        <RecordField label="Zone">
          <Input value={kind.zone} placeholder="asia-east1-b" disabled={disabled} onChange={(e) => patch({ zone: e.target.value.trim() })} />
        </RecordField>
      </div>
      <details className="rounded-md border bg-background px-3 py-2.5">
        <summary className="cursor-pointer text-sm font-medium">
          Google Cloud options
          <span className="ml-2 text-xs font-normal text-muted-foreground">{summary}</span>
        </summary>
        <div className="mt-4 space-y-4 pb-1">
          <RecordField label="Google account">
            {/* Where gcloud's accounts cannot be read, or gcloud has no folder on this computer, the account is typed instead. */}
            {accounts?.config_found ? (
              <select className={selectClass} value={kind.account ?? ""} disabled={disabled} onChange={(e) => patch({ account: e.target.value || null })}>
                <option value="">{accounts.active ? `gcloud's active account (${accounts.active})` : "gcloud's active account"}</option>
                {accounts.accounts.map((entry) => (
                  <option key={entry.account} value={entry.account}>
                    {accountLabel(entry)}
                  </option>
                ))}
                {kind.account && !accounts.accounts.some((entry) => entry.account === kind.account) && (
                  <option value={kind.account}>{`${kind.account} · not signed in on this computer`}</option>
                )}
              </select>
            ) : (
              <Input
                value={kind.account ?? ""}
                placeholder="gcloud's active account"
                disabled={disabled}
                onChange={(e) => patch({ account: e.target.value.trim() || null })}
              />
            )}
            <p className="text-xs text-muted-foreground">Accounts come from gcloud on this computer; each computer signs in on its own.</p>
          </RecordField>
          <label className="flex items-start gap-3 text-sm">
            <Switch className="mt-0.5" checked={kind.os_login} disabled={disabled} onCheckedChange={(checked) => patch({ os_login: checked })} />
            <span>
              OS Login
              <span className="block text-xs text-muted-foreground">
                Register this host&apos;s key with OS Login and check the username before connecting.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3 text-sm">
            <Switch
              className="mt-0.5"
              checked={kind.pam !== null}
              disabled={disabled}
              onCheckedChange={(checked) => patch({ pam: checked ? newPamCheck() : null })}
            />
            <span>
              Require a Privileged Access Manager grant
              <span className="block text-xs text-muted-foreground">When no grant is active, connecting asks for one first.</span>
            </span>
          </label>
          {kind.pam && (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <RecordField label="Entitlements">
                  <EntitlementsInput value={kind.pam.entitlements} disabled={disabled} onChange={(entitlements) => patchPam({ entitlements })} />
                </RecordField>
              </div>
              <RecordField label="Location">
                <Input value={kind.pam.location} placeholder="global" disabled={disabled} onChange={(e) => patchPam({ location: e.target.value.trim() })} />
              </RecordField>
              <RecordField label="Default grant (minutes)">
                {/* The length a grant requested from Lunport starts from, saved with the route. The request dialog offers what this computer last asked for on the host first; that stays on this computer, not in the route. */}
                <Input
                  type="number"
                  min={1}
                  max={480}
                  step={1}
                  value={Math.round(kind.pam.duration_secs / 60)}
                  disabled={disabled}
                  onChange={(e) => patchPam({ duration_secs: Math.round(Number(e.target.value)) * 60 })}
                />
              </RecordField>
            </div>
          )}
          <RecordField label="Network interface">
            <Input className="max-w-32" value={kind.interface} placeholder="nic0" disabled={disabled} onChange={(e) => patch({ interface: e.target.value.trim() })} />
          </RecordField>
          <p className="text-xs text-muted-foreground">The instance&apos;s firewall must allow 35.235.240.0/20 to this port.</p>
        </div>
      </details>
    </>
  );
}

/**
 * The entitlements, typed as a comma-separated list. The text stays as typed while it reads as the list the route has (a value rebuilt
 * from the list would eat a comma as it is typed); a list changed from outside, as Discard changes does, shows as that list.
 */
function EntitlementsInput({ id, value, onChange, disabled }: { id?: string; value: string[]; onChange: (next: string[]) => void; disabled: boolean }) {
  const [typed, setTyped] = useState(() => value.join(", "));
  const parsed = parseEntitlements(typed);
  const shown = parsed.length === value.length && parsed.every((entry, index) => entry === value[index]) ? typed : value.join(", ");
  return (
    <Input
      id={id}
      value={shown}
      placeholder={pamPlaceholder}
      disabled={disabled}
      onChange={(e) => {
        setTyped(e.target.value);
        onChange(parseEntitlements(e.target.value));
      }}
    />
  );
}

/**
 * Use OS Login username, under Username while the route uses OS Login, with what the last use learned. Off while the host takes its
 * username from its Group, which the field does not decide. No hooks: exported for the tests.
 */
export function OsLoginUsername({ disabled, inherited, note, onUse }: { disabled: boolean; inherited: boolean; note: string | null; onUse: () => void }) {
  return (
    <div className="space-y-1">
      <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" disabled={disabled || inherited} onClick={() => onUse()}>
        Use OS Login username
      </Button>
      {inherited ? (
        <p className="text-xs text-muted-foreground">
          This host takes its username from its Group; change it there, or stop inheriting it in the host editor.
        </p>
      ) : (
        note && <p className="text-xs text-muted-foreground">{note}</p>
      )}
    </div>
  );
}

/**
 * What Use OS Login username does: asks OS Login for the POSIX username of the route's account in the route's project and puts it in
 * the draft's Username field (`update`), saved with the host like any other edit; nothing is written now. Returns the note for under
 * the button: the username, and whether the host's key is registered yet.
 */
export async function applyOsLoginUsername(
  kind: TransportKind,
  keyId: string | null,
  update: (change: (current: EditorState) => EditorState) => void,
): Promise<string> {
  const outcome = osLoginOutcome(await fetchOsLoginProfile(kind.account, kind.project, keyId));
  const username = outcome.username;
  if (!username) throw new Error(outcome.error ?? "OS Login has no username for this account.");
  update((current) => (current.payload.user === username ? current : changeEditor(current, { user: username })));
  return [`OS Login username: ${username}.`, outcome.note].filter(Boolean).join(" ");
}

/** Whether a route edit leaves the last Use OS Login username note stale: it spoke of this account, this project, and OS Login on. */
export const osLoginNoteStale = (previous: TransportKind, next: TransportKind): boolean =>
  previous.account !== next.account || previous.project !== next.project || previous.os_login !== next.os_login;
