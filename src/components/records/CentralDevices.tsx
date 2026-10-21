import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from "@/components/ui/alert-dialog";
import {
  centralDevices,
  centralDevicesKey,
  centralRevokeDevice,
  type CentralDevice,
  type CentralStatus,
  type CentralDeviceRegistry,
} from "@/lib/central-sync";
import { revealHidden } from "@/lib/sync-approvals";
const stateLabel = {
  approved: "Approved",
  pending: "Pending approval",
  revoked: "Revoked",
  access_blocked: "Revocation requested",
};
export function CentralDeviceList({
  registry,
  onRevoke,
  disabled = false,
}: {
  registry: CentralDeviceRegistry;
  onRevoke?: (device: CentralDevice) => void;
  disabled?: boolean;
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
          {onRevoke &&
            !device.current &&
            (device.state === "approved" ||
              device.state === "access_blocked") && (
              <Button
                size="sm"
                variant="outline"
                disabled={disabled}
                onClick={() => onRevoke(device)}
              >
                {device.state === "access_blocked"
                  ? "Finish revocation…"
                  : "Revoke device…"}
              </Button>
            )}
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<{
    device: CentralDevice;
    registry: CentralDeviceRegistry;
  } | null>(null);
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
    setRevoking(null);
  }, [status.membership_head, status.authorization_epoch]);
  const revoke = async () => {
    if (inFlight.current || disabled || !revoking) return;
    const selected = revoking;
    setRevoking(null);
    setNotice(null);
    setError(null);
    setBusy(true);
    inFlight.current = true;
    try {
      const result = await centralRevokeDevice(
        selected.device,
        selected.registry,
      );
      if (mounted.current) {
        update(result.status);
        setNotice(
          result.access_revoked
            ? result.rekey_pending
              ? "Cloud access revoked. Encryption key rotation is still pending."
              : "Cloud access revoked."
            : "Revocation is pending. Keep this device signed in and retry to finish blocking cloud access.",
        );
      }
    } catch (error) {
      if (mounted.current)
        setError(
          typeof error === "string"
            ? error
            : "Revocation could not be confirmed. Refresh the account and retry; your revocation request is retained.",
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        void client.invalidateQueries({ queryKey });
      }
    }
  };
  return (
    <div className="space-y-3">
      <h3 className="font-medium">Devices</h3>
      {query.data && (
        <CentralDeviceList
          registry={query.data}
          disabled={
            disabled ||
            busy ||
            !["enrolled", "active", "rekey"].includes(status.phase)
          }
          onRevoke={(device) => {
            if (query.data) setRevoking({ device, registry: query.data });
          }}
        />
      )}
      <AlertDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) setRevoking(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke this device?</AlertDialogTitle>
            <AlertDialogDescription>
              This blocks future cloud access and requires encryption key
              rotation. Keys or data already saved on the device cannot be
              recalled. Access to your SSH servers requires removing its keys
              from those servers separately.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {revoking && (
            <div className="text-sm">
              <p>{revealHidden(revoking.device.name)}</p>
              <code className="block break-all text-xs">
                {revoking.device.fingerprint}
              </code>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={disabled || busy}
              onClick={() => void revoke()}
            >
              Revoke device
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}
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
      <p className="text-sm text-muted-foreground">
        To connect another device, sign in to the same account and enter your
        sync unlock password on that device.
      </p>
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
