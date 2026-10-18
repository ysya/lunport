import { CentralRecovery } from "./CentralRecovery";
import { CentralAccountAccess } from "./CentralAccountAccess";
import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CentralDevices } from "./CentralDevices";
import { RecordField } from "./form";
import { revealHidden } from "@/lib/sync-approvals";
import {
  centralPairingCode,
  centralStatus,
  centralStatusKey,
  centralSignIn,
  centralCancelSignIn,
  centralRefresh,
  centralSignOut,
  centralPrepareVault,
  centralRevealRecovery,
  centralConfirmRecovery,
  type CentralStatus,
} from "@/lib/central-sync";

export function CentralAccountSection({
  disabled = false,
  onBusyChange,
}: {
  disabled?: boolean;
  onBusyChange?: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: centralStatusKey,
    queryFn: centralStatus,
    retry: false,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    let disposed = false;
    const pending = listen<CentralStatus>("central://status", ({ payload }) => {
      if (!disposed) client.setQueryData(centralStatusKey, payload);
    });
    return () => {
      disposed = true;
      void pending.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [client]);
  if (!query.data?.available) return null;
  return (
    <CentralAccountPanel
      status={query.data}
      disabled={disabled}
      onBusyChange={onBusyChange}
      update={(status) => client.setQueryData(centralStatusKey, status)}
    />
  );
}
const phaseText: Record<CentralStatus["phase"], string> = {
  setup: "Account signed in. Set up your encrypted Vault to continue.",
  awaiting_approval: "Waiting for approval from a trusted device.",
  backup_required:
    "Save your offline recovery kit before finishing Vault setup.",
  enrolled: "Your device is approved. Library sync is not enabled yet.",
  active: "Your encrypted library is connected.",
  rekey: "Your encrypted library is waiting for key rotation.",
  revoked: "This device no longer has account access.",
  signed_out: "Sign in through your system browser to manage your account.",
};
export function CentralAccountPanel({
  status,
  disabled = false,
  onBusyChange,
  update,
}: {
  status: CentralStatus;
  disabled?: boolean;
  onBusyChange?: (busy: boolean) => void;
  update: (status: CentralStatus) => void;
}) {
  const [service, setService] = useState(status.service ?? "");
  const [busy, setBusy] = useState(false);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [pairing, setPairing] = useState<{
    code: string;
    expires_at_ms: string;
  } | null>(null);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kit, setKit] = useState<{ root: string; kit: string } | null>(null);
  const [saved, setSaved] = useState(false);
  const inFlight = useRef(false);
  const mounted = useRef(false);
  const secretGeneration = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      secretGeneration.current += 1;
    };
  }, []);
  useEffect(() => {
    onBusyChange?.(busy || deviceBusy || recoveryBusy);
    return () => onBusyChange?.(false);
  }, [busy, deviceBusy, recoveryBusy, onBusyChange]);
  useEffect(() => {
    secretGeneration.current += 1;
    setKit(null);
    setPairing(null);
    setSaved(false);
  }, [status.root_fingerprint, status.phase]);
  useEffect(() => {
    const hide = () => {
      if (document.hidden) {
        secretGeneration.current += 1;
        setKit(null);
        setPairing(null);
        setSaved(false);
      }
    };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current || disabled || deviceBusy || recoveryBusy) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (error) {
      if (mounted.current)
        setError(
          typeof error === "string"
            ? error
            : "Could not update this account. Your local data is retained.",
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        setSigningIn(false);
      }
    }
  };
  const updateAfter = async (operation: Promise<CentralStatus>) => {
    const next = await operation;
    if (mounted.current) update(next);
  };
  const blocked = busy || deviceBusy || recoveryBusy || disabled;
  const login = signingIn || status.login_pending;
  const backup = status.phase === "backup_required";
  return (
    <section
      className="app-notice space-y-4"
      aria-label="Central account preview"
    >
      <div>
        <h2 className="font-medium">Central account · Preview</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {phaseText[status.phase]}
        </p>
      </div>
      <RecordField label="Account service">
        <Input
          type="url"
          value={service}
          onChange={(e) => setService(e.target.value)}
          placeholder="https://sync.example.com"
          autoComplete="off"
          spellCheck={false}
          disabled={blocked || status.configured || login}
        />
      </RecordField>
      <div className="flex flex-wrap gap-2">
        {!login && (
          <Button
            disabled={blocked || !service.trim()}
            onClick={() =>
              void run(async () => {
                setSigningIn(true);
                await updateAfter(centralSignIn(service.trim()));
              })
            }
          >
            {status.has_session ? "Sign in again" : "Sign in with browser"}
          </Button>
        )}
        {login && (
          <Button
            variant="outline"
            onClick={() =>
              void centralCancelSignIn()
                .then(centralStatus)
                .then(update)
                .catch(() => setError("Could not cancel sign-in. Try again."))
            }
          >
            Cancel sign-in
          </Button>
        )}
        {status.has_session && !login && (
          <Button
            variant="outline"
            disabled={blocked}
            onClick={() => void run(() => updateAfter(centralRefresh()))}
          >
            Refresh account
          </Button>
        )}
        {status.configured && !login && (
          <Button
            variant="outline"
            disabled={blocked}
            onClick={() =>
              void run(async () => {
                secretGeneration.current += 1;
                setKit(null);
                setPairing(null);
                setSaved(false);
                await updateAfter(centralSignOut());
              })
            }
          >
            Sign out
          </Button>
        )}
      </div>
      {status.phase === "awaiting_approval" && (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            On a trusted device, open the same account and approve this device
            using its pairing code.
          </p>
          <Button
            variant="outline"
            disabled={blocked || !status.has_session}
            onClick={() =>
              void run(async () => {
                const generation = secretGeneration.current;
                const code = await centralPairingCode();
                if (
                  mounted.current &&
                  generation === secretGeneration.current &&
                  !document.hidden
                )
                  setPairing(code);
              })
            }
          >
            Show pairing code
          </Button>
          {pairing && (
            <div className="space-y-2">
              <Textarea
                aria-label="Device pairing code"
                readOnly
                value={pairing.code}
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  secretGeneration.current += 1;
                  setPairing(null);
                }}
              >
                Hide pairing code
              </Button>
            </div>
          )}
        </div>
      )}
      {status.has_session &&
        status.root_fingerprint &&
        ["enrolled", "active", "rekey"].includes(status.phase) && (
          <CentralDevices
            status={status}
            disabled={busy || recoveryBusy || disabled}
            onBusyChange={setDeviceBusy}
            update={update}
          />
        )}
      {status.configured && status.needs_recovery && !status.has_session && (
        <CentralAccountAccess
          status={status}
          disabled={busy || recoveryBusy || disabled || status.login_pending}
          update={update}
          onBusyChange={setDeviceBusy}
        />
      )}
      {status.configured && (
        <CentralRecovery
          status={status}
          disabled={busy || deviceBusy || disabled}
          update={update}
          onBusyChange={setRecoveryBusy}
        />
      )}
      {status.needs_recovery && (
        <p className="text-sm">
          Unlock this Vault with an offline recovery kit or approval from a
          trusted device. Sign-in alone cannot unlock it.
        </p>
      )}
      {status.phase === "setup" && !status.needs_recovery && (
        <Button
          variant="outline"
          disabled={blocked || !status.has_session}
          onClick={() => void run(() => updateAfter(centralPrepareVault()))}
        >
          Set up encrypted Vault
        </Button>
      )}
      {backup && (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Keep your recovery kit somewhere safe outside this device. Anyone
            with the kit can recover your encrypted library.
          </p>
          <Button
            variant="outline"
            disabled={blocked || !status.has_session}
            onClick={() =>
              void run(async () => {
                const generation = secretGeneration.current;
                const revealed = await centralRevealRecovery();
                if (
                  mounted.current &&
                  generation === secretGeneration.current &&
                  !document.hidden &&
                  revealed.root === status.root_fingerprint
                )
                  setKit(revealed);
              })
            }
          >
            Show recovery kit
          </Button>
          {kit && (
            <div className="space-y-2">
              <Textarea
                aria-label="Offline recovery kit"
                value={kit.kit}
                readOnly
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  secretGeneration.current += 1;
                  setKit(null);
                }}
              >
                Hide recovery kit
              </Button>
            </div>
          )}
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={saved}
              disabled={blocked}
              onChange={(e) => setSaved(e.target.checked)}
            />
            I have saved my recovery kit somewhere safe outside this device.
          </label>
          <Button
            disabled={
              blocked ||
              !saved ||
              !status.has_session ||
              !status.root_fingerprint
            }
            onClick={() =>
              void run(async () => {
                if (!status.root_fingerprint) return;
                secretGeneration.current += 1;
                setKit(null);
                await updateAfter(
                  centralConfirmRecovery(status.root_fingerprint),
                );
              })
            }
          >
            Finish Vault setup
          </Button>
        </div>
      )}
      {(status.phase === "setup" ||
        status.phase === "backup_required" ||
        status.phase === "enrolled") && (
        <p className="text-sm text-muted-foreground">
          Your local library is still stored on this device. Library sync
          requires a separate whole-library review.
        </p>
      )}
      {(error || status.error) && (
        <p
          role="alert"
          className="text-sm text-destructive whitespace-pre-wrap"
        >
          {revealHidden(error ?? status.error ?? "")}
        </p>
      )}
    </section>
  );
}
