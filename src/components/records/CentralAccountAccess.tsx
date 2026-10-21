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
  centralAccountAccess,
  centralAccountAccessKey,
  centralRevokeAccountDevice,
  type CentralAccountAccess as Registry,
  type CentralAccountDevice,
  type CentralStatus,
} from "@/lib/central-sync";
import { revealHidden } from "@/lib/sync-approvals";
export function CentralAccountAccessList({
  registry,
  onRevoke,
  disabled,
}: {
  registry: Registry;
  onRevoke?: (device: CentralAccountDevice) => void;
  disabled?: boolean;
}) {
  return (
    <ul className="space-y-2" aria-label="Account cloud access devices">
      {registry.devices.map((device) => (
        <li key={device.id} className="rounded-md border p-3 text-sm">
          <p>
            {revealHidden(device.name)}
            {device.current ? " · This device" : ""}
          </p>
          <p className="text-muted-foreground">
            {device.state === "revoked"
              ? registry.barrier_pending
                ? "Revocation pending"
                : "Revoked"
              : device.state === "active"
                ? "Active"
                : "Not yet unlocked"}
          </p>
          <code className="block break-all text-xs text-muted-foreground">
            Device ID: {device.id}
          </code>
          {onRevoke &&
            (device.state !== "revoked" || registry.barrier_pending) && (
              <Button
                variant="outline"
                size="sm"
                disabled={disabled}
                onClick={() => onRevoke(device)}
              >
                {device.state === "revoked"
                  ? "Finish revocation…"
                  : "Revoke device…"}
              </Button>
            )}
        </li>
      ))}
    </ul>
  );
}
export function CentralAccountAccess({
  status,
  disabled,
  update,
  onBusyChange,
}: {
  status: CentralStatus;
  disabled: boolean;
  update: (status: CentralStatus) => void;
  onBusyChange: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const queryKey = centralAccountAccessKey(status);
  const query = useQuery({
    queryKey,
    queryFn: centralAccountAccess,
    retry: false,
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
  const [selection, setSelection] = useState<{
    device: CentralAccountDevice;
    epoch: string;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(false);
  const inFlight = useRef(false);
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
    setSelection(null);
  }, [
    status.account_id,
    status.device_id,
    status.root_fingerprint,
    query.data?.authorization_epoch,
  ]);
  const revoke = async () => {
    if (!selection || disabled || inFlight.current) return;
    const selected = selection;
    setSelection(null);
    setBusy(true);
    setNotice(null);
    setError(null);
    inFlight.current = true;
    try {
      const result = await centralRevokeAccountDevice({
        device: selected.device.id,
        authorization_epoch: selected.epoch,
        created_at_ms: selected.device.created_at_ms,
      });
      if (mounted.current) {
        update(result.status);
        setNotice(
          result.access_revoked
            ? result.rekey_pending
              ? "Cloud access revoked. Encryption key rotation is still pending."
              : "Cloud access revoked."
            : "Revocation is pending. Retry to finish blocking cloud access.",
        );
      }
    } catch (error) {
      if (mounted.current)
        setError(
          typeof error === "string"
            ? error
            : "Device revocation could not be confirmed. Refresh the account device list and retry.",
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
      <h3 className="font-medium">Account access</h3>
      <p className="text-sm text-muted-foreground">
        You can block a device's cloud access by authenticating again in your
        browser. A new device still needs your sync password to unlock the encrypted library.
      </p>
      {query.data && (
        <CentralAccountAccessList
          registry={query.data}
          disabled={disabled || busy}
          onRevoke={(device) => {
            if (query.data)
              setSelection({ device, epoch: query.data.authorization_epoch });
          }}
        />
      )}
      {query.isError && (
        <p role="alert" className="text-sm text-destructive">
          Could not verify account device access. Sign in again or refresh the
          device list.
        </p>
      )}
      <Button
        size="sm"
        variant="outline"
        disabled={disabled || busy || query.isFetching}
        onClick={() => void query.refetch()}
      >
        Refresh account devices
      </Button>
      <AlertDialog
        open={selection !== null}
        onOpenChange={(open) => {
          if (!open) setSelection(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke this device?</AlertDialogTitle>
            <AlertDialogDescription>
              You will authenticate again in your system browser. This blocks
              future cloud access. Keys and data already saved on the device
              cannot be recalled. Remove its public keys from your SSH servers
              separately.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {selection && (
            <div className="text-sm">
              <p>{revealHidden(selection.device.name)}</p>
              <code className="block break-all text-xs">
                {selection.device.id}
              </code>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={disabled || busy}
              onClick={() => void revoke()}
            >
              Authenticate and revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
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
