import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { RecordField } from "./form";
import {
  centralDevices,
  centralDevicesKey,
  centralApproveDevice,
  type CentralStatus,
  type CentralDeviceRegistry,
} from "@/lib/central-sync";
import { revealHidden } from "@/lib/sync-approvals";
const stateLabel = {
  approved: "Approved",
  pending: "Pending approval",
  revoked: "Revoked",
  access_blocked: "Cloud access blocked",
};
export function CentralDeviceList({
  registry,
}: {
  registry: CentralDeviceRegistry;
}) {
  return (
    <ul className="space-y-2" aria-label="Account devices">
      {registry.devices.map((device) => (
        <li key={device.id} className="rounded-md border p-3 text-sm">
          <p>
            {revealHidden(device.name)}
            {device.current ? " · This device" : ""}
          </p>
          <p className="text-muted-foreground">{stateLabel[device.state]}</p>
          <code className="block break-all text-xs text-muted-foreground">
            {device.fingerprint}
          </code>
        </li>
      ))}
    </ul>
  );
}
export function CentralDevices({
  status,
  disabled,
  onBusyChange,
  update,
}: {
  status: CentralStatus;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  update: (status: CentralStatus) => void;
}) {
  const client = useQueryClient();
  const queryKey = centralDevicesKey(status);
  const query = useQuery({
    queryKey,
    queryFn: centralDevices,
    retry: false,
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    onBusyChange(busy);
    return () => onBusyChange(false);
  }, [busy, onBusyChange]);
  useEffect(() => {
    const hide = () => {
      if (document.hidden) setCode("");
    };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  const approve = async () => {
    if (inFlight.current || disabled || !code.trim()) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    const submitted = code.trim();
    setCode("");
    try {
      const next = await centralApproveDevice(submitted);
      if (mounted.current) {
        update(next);
        void client.invalidateQueries({ queryKey });
      }
    } catch (error) {
      if (mounted.current)
        setError(
          typeof error === "string"
            ? error
            : "Could not verify this device approval. Refresh the account and retry.",
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <div className="space-y-3">
      <h3 className="font-medium">Devices</h3>
      {query.data && <CentralDeviceList registry={query.data} />}
      {query.isError && (
        <p role="alert" className="text-sm text-destructive">
          Could not verify the current device list. Refresh your account and try
          again.
        </p>
      )}
      <Button
        size="sm"
        variant="outline"
        disabled={disabled || busy || query.isFetching}
        onClick={() => void query.refetch()}
      >
        Refresh devices
      </Button>
      {(status.phase === "enrolled" || status.phase === "active") && (
        <div className="space-y-3">
          <RecordField label="Pairing code from your new device">
            <Textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              disabled={disabled || busy}
              className="font-mono text-xs"
            />
          </RecordField>
          <p className="text-sm text-muted-foreground">
            Only approve a code shown on a device you own. Approval unlocks your
            encrypted library for that device.
          </p>
          <Button
            disabled={disabled || busy || !code.trim()}
            onClick={() => void approve()}
          >
            Approve device
          </Button>
        </div>
      )}
      {error && (
        <p
          role="alert"
          className="text-sm text-destructive whitespace-pre-wrap"
        >
          {revealHidden(error)}
        </p>
      )}
    </div>
  );
}
