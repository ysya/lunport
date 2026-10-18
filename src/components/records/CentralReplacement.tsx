import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { centralStatus, type CentralStatus } from "@/lib/central-sync";
import {
  cancelReplacement,
  confirmReplacement,
  continueReplacement,
  replacementKey,
  replacementScope,
  replacementStatus,
  reserveReplacement,
  revealReplacementKit,
  revealReplacementPairing,
  revalidateReplacement,
  startReplacement,
  type ReplacementInvocation,
  type ReplacementProgress,
  type ReplacementRoute,
} from "@/lib/central-replacement";

type Secret = {
  scope: string;
  operation: string;
  phase: string;
  value: string;
} & ({ kind: "kit"; root: string } | { kind: "pairing" });

export function CentralReplacement({
  status,
  disabled,
  update,
  onBusyChange,
  resetGeneration = 0,
}: {
  status: CentralStatus;
  disabled: boolean;
  update: (status: CentralStatus) => void;
  onBusyChange: (busy: boolean) => void;
  resetGeneration?: number;
}) {
  const client = useQueryClient();
  const scope = JSON.stringify([replacementScope(status), resetGeneration]);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const allowedRef = useRef(false);
  allowedRef.current = !disabled && status.phase !== "signed_out";
  const key = replacementKey(status);
  const query = useQuery({
    queryKey: key,
    queryFn: replacementStatus,
    retry: false,
    enabled:
      status.available && status.configured && status.phase !== "signed_out",
    refetchOnWindowFocus: false,
  });
  const progress = query.data;
  const [routeChoice, setRouteChoice] =
    useState<ReplacementRoute>("trusted_device");
  const route = progress?.route ?? routeChoice;
  const [input, setInput] = useState({ scope, value: "" });
  const [secret, setSecret] = useState<Secret | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [paused, setPaused] = useState(false);
  const [visible, setVisible] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(false);
  const inFlight = useRef(false);
  const runEpoch = useRef(0);
  const secretEpoch = useRef(0);
  const invocation = useRef<{
    scope: string;
    value: ReplacementInvocation;
  } | null>(null);
  const live = (requested: string, epoch: number) =>
    mounted.current &&
    allowedRef.current &&
    scopeRef.current === requested &&
    runEpoch.current === epoch &&
    !document.hidden;
  const clearSecrets = () => {
    secretEpoch.current += 1;
    setInput({ scope: scopeRef.current, value: "" });
    setSecret(null);
    setSaved(false);
  };
  const release = () => {
    const old = invocation.current;
    invocation.current = null;
    if (old) void cancelReplacement(old.value).catch(() => {});
  };
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      runEpoch.current += 1;
      secretEpoch.current += 1;
      release();
    };
  }, []);
  useEffect(() => {
    runEpoch.current += 1;
    inFlight.current = false;
    release();
    clearSecrets();
    setBusy(false);
    setPaused(false);
    setError(null);
  }, [scope]);
  useEffect(() => {
    clearSecrets();
  }, [scope, progress?.operation, progress?.phase]);
  useEffect(() => {
    const hide = () => {
      setVisible(!document.hidden);
      if (document.hidden) {
        runEpoch.current += 1;
        inFlight.current = false;
        release();
        clearSecrets();
        setBusy(false);
        setPaused(true);
      }
    };
    hide();
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  useEffect(() => {
    if (disabled || status.phase === "signed_out") {
      runEpoch.current += 1;
      inFlight.current = false;
      release();
      clearSecrets();
      setBusy(false);
    }
  }, [disabled, status.phase]);
  useEffect(() => {
    onBusyChange(busy);
    return () => onBusyChange(false);
  }, [busy, onBusyChange]);

  const ensureInvocation = async (
    epoch: number,
  ): Promise<ReplacementInvocation | null> => {
    if (invocation.current?.scope === scope) return invocation.current.value;
    const reserved = await reserveReplacement(route);
    if (!live(scope, epoch)) {
      await cancelReplacement(reserved).catch(() => {});
      return null;
    }
    invocation.current = { scope, value: reserved };
    return reserved;
  };
  const publish = async (next: ReplacementProgress, epoch: number) => {
    if (!live(scope, epoch)) return;
    client.setQueryData(key, next);
    if (next.phase === "complete") {
      const current = await centralStatus();
      if (live(scope, epoch)) update(current);
    }
  };
  const run = async (
    action: (lease: ReplacementInvocation, epoch: number) => Promise<void>,
  ) => {
    if (
      inFlight.current ||
      disabled ||
      document.hidden ||
      status.phase === "signed_out"
    )
      return;
    const epoch = ++runEpoch.current;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    setPaused(false);
    try {
      const lease = await ensureInvocation(epoch);
      if (lease && live(scope, epoch)) await action(lease, epoch);
    } catch (failure) {
      if (live(scope, epoch)) {
        setError(
          typeof failure === "string"
            ? failure
            : "Device replacement could not finish. Your local data and saved progress are retained.",
        );
        void query.refetch();
      }
    } finally {
      if (
        mounted.current &&
        scopeRef.current === scope &&
        runEpoch.current === epoch
      ) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  };
  const start = () => {
    const kit =
      route === "recovery_kit" && input.scope === scope
        ? input.value.trim() || null
        : null;
    clearSecrets();
    return run(async (lease, epoch) =>
      publish(await startReplacement(lease, kit), epoch),
    );
  };
  const advance = () =>
    run(async (lease, epoch) => {
      if (progress?.operation)
        await publish(
          await continueReplacement(lease, progress.operation),
          epoch,
        );
    });
  const pause = () => {
    runEpoch.current += 1;
    const epoch = runEpoch.current;
    inFlight.current = false;
    clearSecrets();
    setBusy(false);
    setPaused(true);
    setError(null);
    const old = invocation.current;
    invocation.current = null;
    if (old) {
      const requested = scope;
      void cancelReplacement(old.value)
        .then((next) => {
          if (
            mounted.current &&
            scopeRef.current === requested &&
            runEpoch.current === epoch &&
            !invocation.current
          )
            client.setQueryData(key, next);
        })
        .catch(() => {});
    }
  };
  useEffect(() => {
    if (
      !visible ||
      paused ||
      busy ||
      disabled ||
      error ||
      !invocation.current ||
      !["recovering", "reading"].includes(progress?.phase ?? "")
    )
      return;
    const timer = window.setTimeout(() => {
      void advance();
    }, 100);
    return () => window.clearTimeout(timer);
  }, [
    visible,
    paused,
    busy,
    disabled,
    error,
    scope,
    progress?.phase,
    progress?.verified,
    progress?.total,
    query.dataUpdatedAt,
  ]);

  const show = (kind: "kit" | "pairing") => {
    const requestedSecret = ++secretEpoch.current;
    return run(async (lease, epoch) => {
      const operation = progress?.operation;
      if (!operation) return;
      if (kind === "kit") {
        const shown = await revealReplacementKit(lease, operation);
        if (
          live(scope, epoch) &&
          secretEpoch.current === requestedSecret &&
          shown.root === progress.root_fingerprint
        ) {
          setSecret({
            kind,
            scope,
            operation,
            phase: progress.phase,
            root: shown.root,
            value: shown.kit,
          });
        }
      } else {
        const shown = await revealReplacementPairing(lease, operation);
        if (live(scope, epoch) && secretEpoch.current === requestedSecret) {
          setSecret({
            kind,
            scope,
            operation,
            phase: progress.phase,
            value: shown.code,
          });
        }
      }
    });
  };
  // Scope/phase checks hide stale values on the first render, before effects clear their state.
  const shown =
    visible &&
    !disabled &&
    status.phase !== "signed_out" &&
    secret?.scope === scope &&
    secret.operation === progress?.operation &&
    secret.phase === progress.phase
      ? secret
      : null;
  const canConfirm =
    !!progress?.operation &&
    (progress.backup_confirmed ||
      (saved &&
        shown?.kind === "kit" &&
        shown.root === progress.root_fingerprint));
  const blocked =
    disabled ||
    busy ||
    !visible ||
    status.phase === "signed_out" ||
    !(status.has_session || status.needs_recovery) ||
    !progress;
  const needsRepair =
    status.needs_recovery ||
    status.replacement_pending ||
    status.phase === "revoked";
  if (
    !needsRepair &&
    progress?.phase !== "complete" &&
    !progress?.unresolved_archives
  )
    return null;
  return (
    <section
      aria-label="Replace this device"
      className="space-y-3 border-t pt-4"
    >
      <h3 className="font-medium">Repair this device</h3>
      <p className="text-sm text-muted-foreground">
        Keep your local library and authorize a new account identity for this
        device. Use another trusted device or your offline recovery kit. Sign-in
        alone cannot unlock the library.
      </p>
      {!progress && (
        <p className="text-sm">Loading saved replacement progress…</p>
      )}
      {progress?.phase === "complete" ? (
        <p className="text-sm">
          This device now uses its new account identity.
        </p>
      ) : (
        <>
          {!progress?.route && (
            <fieldset
              className="space-y-2 text-sm"
              disabled={blocked || status.replacement_pending}
            >
              <legend>Authorize with</legend>
              <label className="flex gap-2">
                <input
                  type="radio"
                  name="replacement-route"
                  checked={routeChoice === "trusted_device"}
                  onChange={() => {
                    clearSecrets();
                    setRouteChoice("trusted_device");
                  }}
                />
                A trusted device
              </label>
              <label className="flex gap-2">
                <input
                  type="radio"
                  name="replacement-route"
                  checked={routeChoice === "recovery_kit"}
                  onChange={() => {
                    clearSecrets();
                    setRouteChoice("recovery_kit");
                  }}
                />
                An offline recovery kit
              </label>
            </fieldset>
          )}
          {route === "recovery_kit" &&
            (!progress ||
              ["idle", "paused"].includes(progress.phase) ||
              !!error) && (
              <Textarea
                aria-label="Recovery kit for device replacement"
                value={
                  visible &&
                  !disabled &&
                  status.phase !== "signed_out" &&
                  input.scope === scope
                    ? input.value
                    : ""
                }
                onChange={(e) => setInput({ scope, value: e.target.value })}
                disabled={blocked}
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
            )}
          {paused && (
            <p className="text-sm">
              Verification is paused. Local data and saved progress are kept.
            </p>
          )}
          {progress && ["recovering", "reading"].includes(progress.phase) && (
            <div className="space-y-2 text-sm">
              <p>
                Verified {progress.verified} of {progress.total} encrypted
                records.
              </p>
              <progress
                aria-label="Device verification progress"
                value={progress.verified}
                max={Math.max(1, progress.total)}
              />
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            {(paused ||
              !progress ||
              ["idle", "paused", "verification_required"].includes(
                progress.phase,
              )) && (
              <Button
                variant="outline"
                disabled={blocked}
                onClick={() => void start()}
              >
                {status.replacement_pending
                  ? "Resume replacement"
                  : "Replace this device"}
              </Button>
            )}
            {!paused && progress?.phase === "awaiting_approval" && (
              <>
                <Button
                  variant="outline"
                  disabled={blocked}
                  onClick={() => void show("pairing")}
                >
                  Show replacement pairing code
                </Button>
                <Button
                  variant="outline"
                  disabled={blocked}
                  onClick={() => void start()}
                >
                  Check device approval
                </Button>
              </>
            )}
            {!paused && progress?.phase === "backup_required" && (
              <Button
                variant="outline"
                disabled={blocked}
                onClick={() => void show("kit")}
              >
                Show new recovery kit
              </Button>
            )}
            {!paused &&
              progress &&
              ["recovering", "reading"].includes(progress.phase) && (
                <Button
                  variant="outline"
                  disabled={blocked}
                  onClick={() => void advance()}
                >
                  Continue verification
                </Button>
              )}
            {(busy || status.replacement_pending) && (
              <Button variant="ghost" disabled={disabled} onClick={pause}>
                Pause replacement
              </Button>
            )}
          </div>
          {shown && (
            <div className="space-y-2">
              <Textarea
                aria-label={
                  shown.kind === "kit"
                    ? "New replacement recovery kit"
                    : "Replacement pairing code"
                }
                value={shown.value}
                readOnly
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <Button variant="ghost" size="sm" onClick={clearSecrets}>
                Hide {shown.kind === "kit" ? "recovery kit" : "pairing code"}
              </Button>
            </div>
          )}
          {progress &&
            ["backup_required", "submitted", "cleanup_required"].includes(
              progress.phase,
            ) &&
            !paused && (
              <div className="space-y-2 text-sm">
                <p>
                  Recovery removes cloud access for your other devices. It
                  cannot recall copied SSH keys or change remote
                  authorized_keys.
                </p>
                {!progress.backup_confirmed && (
                  <label className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      checked={saved}
                      disabled={blocked || shown?.kind !== "kit"}
                      onChange={(e) => setSaved(e.target.checked)}
                    />
                    I saved the new recovery kit outside this device and
                    understand that my other devices lose cloud access.
                  </label>
                )}
                <Button
                  disabled={blocked || !canConfirm}
                  onClick={() => {
                    clearSecrets();
                    void run(async (lease, epoch) => {
                      if (progress.operation)
                        await publish(
                          await confirmReplacement(lease, progress.operation),
                          epoch,
                        );
                    });
                  }}
                >
                  {progress.phase === "backup_required"
                    ? "Confirm recovery and replace device"
                    : "Resume confirmed recovery"}
                </Button>
              </div>
            )}
          {error &&
            progress?.operation &&
            route === "recovery_kit" &&
            ["backup_required", "submitted"].includes(progress.phase) && (
              <Button
                variant="outline"
                disabled={blocked}
                onClick={() => {
                  const kit =
                    input.scope === scope ? input.value.trim() || null : null;
                  clearSecrets();
                  void run(async (lease, epoch) => {
                    if (progress.operation)
                      await publish(
                        await revalidateReplacement(
                          lease,
                          progress.operation,
                          kit,
                        ),
                        epoch,
                      );
                  });
                }}
              >
                Revalidate saved recovery
              </Button>
            )}
        </>
      )}
      {!!progress?.unresolved_archives && (
        <p className="text-sm">
          Some local changes remain in a protected recovery archive. Uploads
          stay blocked until those changes are reconciled.
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm">
          {error}
        </p>
      )}
      {query.isError && (
        <p role="alert" className="text-sm">
          Could not read saved replacement progress.
        </p>
      )}
    </section>
  );
}
