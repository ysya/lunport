import { Input } from "@/components/ui/input";
import { pamPlaceholder, transportProblem, type TransportKind } from "@/lib/transports";
import { RecordField } from "./form";

/**
 * The fields of a Google Cloud IAP transport (design 2026-10-25): the instance, the Google account, OS Login and the PAM grant check.
 * `kind` is the value as displayed; every change goes up through `onChange`. The Google Cloud panel wraps this in its editor dialog.
 */
export function TransportFields({ kind, onChange, disabled }: { kind: TransportKind; onChange: (next: TransportKind) => void; disabled: boolean }) {
  const patch = (changes: Partial<TransportKind>) => onChange({ ...kind, ...changes });
  const problem = transportProblem({ host_id: "0000000000000000", ...{ kind } }) ?? null;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <RecordField label="Project">
          <Input value={kind.project} placeholder="my-project-123456" disabled={disabled} onChange={(e) => patch({ project: e.target.value.trim() })} />
        </RecordField>
        <RecordField label="Zone">
          <Input value={kind.zone} placeholder="asia-east1-b" disabled={disabled} onChange={(e) => patch({ zone: e.target.value.trim() })} />
        </RecordField>
        <RecordField label="Instance">
          <Input value={kind.instance} placeholder="jumpbox" disabled={disabled} onChange={(e) => patch({ instance: e.target.value.trim() })} />
        </RecordField>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <RecordField label="Network interface">
          <Input value={kind.interface} placeholder="nic0" disabled={disabled} onChange={(e) => patch({ interface: e.target.value.trim() })} />
        </RecordField>
        <RecordField label="Google account">
          <Input
            value={kind.account ?? ""}
            placeholder="gcloud's active account"
            disabled={disabled}
            onChange={(e) => patch({ account: e.target.value.trim() || null })}
          />
        </RecordField>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={kind.os_login} disabled={disabled} onChange={(e) => patch({ os_login: e.target.checked })} />
        OS Login: register the host&apos;s key and check its username before connecting
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={kind.pam !== null}
          disabled={disabled}
          onChange={(e) => patch({ pam: e.target.checked ? { entitlements: [], location: "global" } : null })}
        />
        Require an active Privileged Access Manager grant
      </label>
      {kind.pam && (
        <div className="grid gap-4 sm:grid-cols-2">
          <RecordField label="Entitlements (comma-separated)">
            <Input
              value={kind.pam.entitlements.join(", ")}
              placeholder={pamPlaceholder}
              disabled={disabled}
              onChange={(e) =>
                patch({
                  pam: {
                    location: kind.pam?.location ?? "global",
                    entitlements: e.target.value.split(",").map((entry) => entry.trim()).filter(Boolean),
                  },
                })
              }
            />
          </RecordField>
          <RecordField label="Location">
            <Input
              value={kind.pam.location}
              placeholder="global"
              disabled={disabled}
              onChange={(e) => patch({ pam: { entitlements: kind.pam?.entitlements ?? [], location: e.target.value.trim() } })}
            />
          </RecordField>
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        The tunnel goes to the host&apos;s port on the instance; the instance&apos;s firewall must allow 35.235.240.0/20. Credentials come from gcloud auth login on this device.
      </p>
      {problem && <p className="text-xs text-destructive">{problem}</p>}
    </div>
  );
}
