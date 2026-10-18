import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  centralAdvanceAccountRecovery,
  centralBeginAccountRecovery,
  centralCancelAccountRecovery,
  centralConfirmAccountRecovery,
  centralRecoveryKey,
  centralRecoveryStatus,
  centralRevealNewRecovery,
  centralStatus,
  type CentralRecoveryProgress,
  type CentralStatus,
} from "@/lib/central-sync";

export function recoveryCanConfirm(
  progress: CentralRecoveryProgress,
  saved: boolean,
  revealedRoot: string | null,
) {
  return (
    progress.phase === "backup_required" &&
    saved &&
    !!progress.operation &&
    !!progress.root_fingerprint &&
    revealedRoot === progress.root_fingerprint
  );
}
export function CentralRecovery({
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
  const key = centralRecoveryKey(status);
  const scope = JSON.stringify(key);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const query = useQuery({
    queryKey: key,
    queryFn: centralRecoveryStatus,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const progress = query.data;
  const [input, setInput] = useState("");
  const [revealed, setRevealed] = useState<{
    root: string;
    kit: string;
  } | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [visible, setVisible] = useState(true);
  const mounted = useRef(false);
  const inFlight = useRef(false);
  const cancelling = useRef(false);
  const generation = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
      void centralCancelAccountRecovery().catch(() => {});
    };
  }, []);
  useEffect(() => {
    generation.current += 1;
    setInput("");
    setRevealed(null);
    setSaved(false);
    setError(null);
  }, [scope, progress?.operation, progress?.phase]);
  useEffect(() => {
    const hide = () => {
      setVisible(!document.hidden);
      if (document.hidden) {
        generation.current += 1;
        setInput("");
        setRevealed(null);
        setSaved(false);
      }
    };
    hide();
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  useEffect(() => {
    onBusyChange(busy);
    return () => onBusyChange(false);
  }, [busy, onBusyChange]);
  const run = async (action: () => Promise<void>) => {
    if (inFlight.current || disabled) return;
    const requestedScope = scope;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (failure) {
      if (
        mounted.current &&
        currentScope.current === requestedScope &&
        !cancelling.current
      )
        setError(
          typeof failure === "string"
            ? failure
            : "Recovery could not finish. Your local data and saved recovery operation are retained.",
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        if (cancelling.current) {
          cancelling.current = false;
          void query.refetch();
        }
      }
    }
  };
  const accept = async (pending: Promise<CentralRecoveryProgress>) => {
    const requestedScope = scope;
    const next = await pending;
    if (!mounted.current || currentScope.current !== requestedScope) return;
    client.setQueryData(key, next); // Public progress only.
    if (next.phase === "complete" || next.phase === "cleanup_required") {
      generation.current += 1;
      setInput("");
      setRevealed(null);
      setSaved(false);
      const nextStatus = await centralStatus();
      if (mounted.current && currentScope.current === requestedScope)
        update(nextStatus);
    }
  };
  useEffect(() => {
    if (
      progress?.phase !== "reading" ||
      busy ||
      disabled ||
      !visible ||
      !status.has_session ||
      error
    )
      return;
    const timer = window.setTimeout(() => {
      void run(() => accept(centralAdvanceAccountRecovery()));
    }, 250);
    return () => window.clearTimeout(timer);
  }, [
    progress?.phase,
    progress?.verified,
    progress?.operation,
    busy,
    disabled,
    visible,
    status.has_session,
    error,
    scope,
  ]);
  const blocked = busy || disabled || !visible || status.login_pending;
  if (!progress && query.isError)
    return (
      <div className="space-y-2" role="alert">
        <p className="text-sm">
          Could not read recovery progress. Local data is retained.
        </p>
        <Button
          variant="outline"
          disabled={disabled}
          onClick={() => void query.refetch()}
        >
          Retry recovery status
        </Button>
      </div>
    );
  if (
    !progress ||
    (progress.phase === "idle" && status.phase !== "awaiting_approval")
  )
    return null;
  return (
    <div
      className="space-y-3 rounded-md border p-3"
      aria-label="Offline account recovery"
    >
      {(error || query.isError) && (
        <p role="alert" className="text-sm text-destructive">
          {error ?? "Could not read recovery progress. Local data is retained."}
        </p>
      )}
      {progress.phase === "idle" && (
        <>
          <p className="text-sm">
            Use your offline recovery kit when you no longer have a trusted
            device.
          </p>
          <Textarea
            aria-label="Existing offline recovery kit"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-xs"
            disabled={blocked || !status.has_session}
          />
          <Button
            variant="outline"
            disabled={blocked || !status.has_session || !input.trim()}
            onClick={() => {
              const code = input;
              setInput("");
              void run(() => accept(centralBeginAccountRecovery(code)));
            }}
          >
            Verify recovery kit
          </Button>
        </>
      )}
      {progress.phase === "reading" && (
        <>
          <p className="text-sm" role="status">
            Verifying encrypted history: {progress.verified} / {progress.total}
          </p>
          <Button
            variant="outline"
            disabled={disabled}
            onClick={() => {
              cancelling.current = true;
              generation.current += 1;
              setInput("");
              setRevealed(null);
              setSaved(false);
              void centralCancelAccountRecovery()
                .then(() => {
                  if (!inFlight.current) {
                    cancelling.current = false;
                    return query.refetch();
                  }
                })
                .catch(() =>
                  setError("Could not cancel recovery verification."),
                );
            }}
          >
            Cancel verification
          </Button>
          {error && (
            <Button
              variant="outline"
              disabled={blocked || !status.has_session}
              onClick={() =>
                void run(() => accept(centralAdvanceAccountRecovery()))
              }
            >
              Retry verification
            </Button>
          )}
        </>
      )}
      {progress.phase === "backup_required" && (
        <>
          <p className="text-sm">
            Save the new recovery kit outside this device before finishing.
            Recovery replaces your old kit and removes cloud access for your
            other devices.
          </p>
          <p className="text-sm text-muted-foreground">
            Previously saved keys remain on those devices. Recovery does not
            change remote authorized_keys.
          </p>
          <Button
            variant="outline"
            disabled={blocked || !status.has_session}
            onClick={() =>
              void run(async () => {
                const requestedGeneration = generation.current;
                const requestedScope = scope;
                const next = await centralRevealNewRecovery();
                if (
                  mounted.current &&
                  !document.hidden &&
                  generation.current === requestedGeneration &&
                  currentScope.current === requestedScope &&
                  next.root === progress.root_fingerprint
                )
                  setRevealed(next);
              })
            }
          >
            Show new recovery kit
          </Button>
          {revealed && (
            <div className="space-y-2">
              <Textarea
                aria-label="New offline recovery kit"
                readOnly
                value={revealed.kit}
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  generation.current += 1;
                  setRevealed(null);
                  setSaved(false);
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
              disabled={blocked || !revealed}
              onChange={(event) => setSaved(event.target.checked)}
            />
            I saved the new recovery kit outside this device and want to revoke
            my other devices.
          </label>
          <Button
            disabled={
              blocked ||
              !status.has_session ||
              !recoveryCanConfirm(progress, saved, revealed?.root ?? null)
            }
            onClick={() => {
              const operation = progress.operation;
              if (!operation) return;
              generation.current += 1;
              setRevealed(null);
              setSaved(false);
              void run(() => accept(centralConfirmAccountRecovery(operation)));
            }}
          >
            Recover account
          </Button>
        </>
      )}
      {progress.phase === "submitted" && (
        <>
          <p className="text-sm">
            Recovery is submitted. Finish checking device revocation before
            continuing.
          </p>
          <Button
            variant="outline"
            disabled={blocked || !status.has_session || !progress.operation}
            onClick={() => {
              if (progress.operation)
                void run(() =>
                  accept(centralConfirmAccountRecovery(progress.operation!)),
                );
            }}
          >
            Resume recovery
          </Button>
        </>
      )}
      {progress.phase === "cleanup_required" && (
        <>
          <p className="text-sm">
            Recovery is verified. Finish removing temporary recovery credentials
            to continue.
          </p>
          <Button
            variant="outline"
            disabled={blocked || !progress.operation}
            onClick={() => {
              if (progress.operation)
                void run(() =>
                  accept(centralConfirmAccountRecovery(progress.operation!)),
                );
            }}
          >
            Finish recovery
          </Button>
        </>
      )}
      {progress.phase === "complete" && (
        <p className="text-sm">Account recovery is complete.</p>
      )}
    </div>
  );
}
