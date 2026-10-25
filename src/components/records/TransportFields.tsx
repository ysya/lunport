import { Input } from "@/components/ui/input";
import { FormSection } from "@/components/app/Workflow";
import { newIapTransport, pamPlaceholder, transportProblem, type HostTransport, type TransportKind } from "@/lib/transports";
import { RecordField, selectClass } from "./form";

/**
 * How this device reaches the host: over TCP, or through a Google Cloud IAP tunnel to a Compute Engine instance (design 2026-10-25).
 * `value` is the transport as displayed (`null` = Direct); every change goes up through `onChange`, and the host editor saves it right
 * after the host.
 */
export function TransportSection({
  hostId,
  value,
  onChange,
  disabled,
}: {
  hostId: string | null;
  value: HostTransport | null;
  onChange: (next: HostTransport | null) => void;
  disabled: boolean;
}) {
  const kind = value?.kind ?? null;
  const patch = (changes: Partial<TransportKind>) => {
    if (value) onChange({ ...value, kind: { ...value.kind, ...changes } });
  };
  const problem = value ? transportProblem(value) : null;
  return (
    <FormSection
      title="Connect through"
      description="Reach the host directly, or through a Google Cloud IAP tunnel to a Compute Engine instance using the credentials of gcloud auth login on this device."
    >
      <RecordField label="Connect through">
        <select
          aria-label="Connect through"
          className={selectClass}
          disabled={disabled}
          value={value ? "gcp_iap" : "direct"}
          onChange={(e) => onChange(e.target.value === "gcp_iap" ? value ?? newIapTransport(hostId ?? "") : null)}
        >
          <option value="direct">Direct (TCP)</option>
          <option value="gcp_iap">Google Cloud IAP tunnel</option>
        </select>
      </RecordField>
      {kind && (
        <>
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
            OS Login: register this host&apos;s key and check the username before connecting
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
            The tunnel goes to the host&apos;s port on the instance; its firewall must allow 35.235.240.0/20. This choice is saved on this device only.
          </p>
          {problem && <p className="text-xs text-destructive">{problem}</p>}
        </>
      )}
    </FormSection>
  );
}
