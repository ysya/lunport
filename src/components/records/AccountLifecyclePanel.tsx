import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import type { AccountLeaveReceipt, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { RecordField } from "./form";
import {
  clearLifecycleDraft,
  retireLifecycleAttempt,
  submitLifecycleDraft,
  type LifecycleDraft,
} from "./account-lifecycle-actions";
export type LifecycleReviewProps = {
  mode: "leave" | "rotate";
  consent: boolean;
  busy: boolean;
  deviceName: string;
  setConsent: (value: boolean) => void;
  setDeviceName: (name: string) => void;
  confirm: () => void;
  cancel: () => void;
};
export function AccountLifecycleReview({
  mode,
  consent,
  busy,
  deviceName,
  setConsent,
  setDeviceName,
  confirm,
  cancel,
}: LifecycleReviewProps) {
  const leaving = mode === "leave";
  return (
    <section className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {leaving
          ? "Selected space hosts become Local copies with new IDs and updated jump references. Existing Local hosts, keys and passwords stay on this device. Missing or invalid selected spaces must be resolved first. The remote account remains retained; leaving does not delete its data or export private key files."
          : "Future updates use a new sync code. Other devices must rejoin with that code. The source chains are frozen and retained: the old code can still read historical data. Rotation does not revoke access to that history."}
      </p>
      {!leaving && (
        <RecordField label="Device name">
          <Input
            value={deviceName}
            disabled={busy}
            onChange={(event) => setDeviceName(event.target.value)}
          />
        </RecordField>
      )}
      <Label className="flex items-start gap-2">
        <Checkbox
          checked={consent}
          disabled={busy}
          onCheckedChange={(checked) => setConsent(checked === true)}
        />
        <span>
          {leaving
            ? "I understand that selected hosts will be copied to Local and remote sources will remain."
            : "I understand that devices must rejoin and the old code still reads historical data."}
        </span>
      </Label>
      <div className="flex flex-wrap gap-2">
        <Button
          disabled={busy || !consent || (!leaving && !deviceName.trim())}
          onClick={confirm}
        >
          {leaving ? "Leave account" : "Rotate sync code"}
        </Button>
        <Button variant="outline" disabled={busy} onClick={cancel}>
          Cancel
        </Button>
      </div>
    </section>
  );
}
export function AccountLeaveOutcome({
  receipt,
}: {
  receipt: AccountLeaveReceipt;
}) {
  return (
    <section className="space-y-3 rounded-md border p-4" role="status">
      <h2 className="font-medium">
        {receipt.complete ? "Account left" : "Leaving account is pending"}
      </h2>
      <p className="text-sm">{receipt.copied_hosts} hosts copied to Local.</p>
      <p className="break-all font-mono text-xs text-muted-foreground">
        Operation {receipt.operation_id}
      </p>
      {!receipt.complete && (
        <p className="text-sm text-muted-foreground">
          Use Retry sync setup above to continue the existing operation. Closing
          this panel does not undo saved progress.
        </p>
      )}
      {receipt.mappings.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Local host mappings</summary>
          {receipt.mappings.map((mapping) => (
            <p key={mapping.local_host_id} className="mt-2 break-all">
              {revealHidden(mapping.alias)} · {mapping.source_space_id}/
              {mapping.source_host_id} → Local {mapping.local_host_id}
            </p>
          ))}
        </details>
      )}
    </section>
  );
}
export function AccountRotationOutcome({
  words,
  rotation,
  busy,
  clear,
}: {
  words: string;
  rotation: { operation_id: string; complete: boolean } | null;
  busy: boolean;
  clear: () => void;
}) {
  return (
    <section className="space-y-3 rounded-md border p-4" role="status">
      <h2 className="font-medium">
        {rotation
          ? rotation.complete
            ? "Sync code rotated"
            : "Sync code rotation is pending"
          : "Save your new sync code"}
      </h2>
      <p className="text-sm text-muted-foreground">
        Keep the new code private and save it before closing. Devices must
        rejoin for future updates. The old code can still read historical data
        retained in the frozen source chains.
      </p>
      {rotation && (
        <p className="break-all font-mono text-xs text-muted-foreground">
          Operation {rotation.operation_id}
        </p>
      )}
      {rotation && !rotation.complete && (
        <p className="text-sm text-muted-foreground">
          Use Retry sync setup above to continue publication. The new code is
          available here even while setup is pending.
        </p>
      )}
      <Textarea
        aria-label="New rotated sync code"
        autoComplete="off"
        value={words}
        readOnly
        className="font-mono"
      />
      <Button disabled={busy} onClick={clear}>
        I saved the new code
      </Button>
    </section>
  );
}
export function RecordsAccountLifecyclePanel({
  overview,
  disabled = false,
  recoveryVersion = 0,
  onBusyChange,
}: {
  overview: RecordOverview;
  disabled?: boolean;
  recoveryVersion?: number;
  onBusyChange?: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const [state, setState] = useState(clearLifecycleDraft);
  const inFlight = useRef(false);
  const update = (patch: Partial<LifecycleDraft>) =>
    setState((current) => ({ ...current, ...patch }));
  // A successful explicit retry retires the previous attempt's receipt, but does not discard an unsaved new code.
  useEffect(() => {
    setState(retireLifecycleAttempt);
  }, [recoveryVersion]);
  const reset = () => setState(clearLifecycleDraft());
  const blocked =
    disabled ||
    state.busy ||
    !!overview.pending_account ||
    overview.shared_writes_blocked;
  const submit = async () => {
    if (inFlight.current || blocked || !overview.account) return;
    inFlight.current = true;
    onBusyChange?.(true);
    try {
      await submitLifecycleDraft(client, state, update);
    } finally {
      inFlight.current = false;
      onBusyChange?.(false);
    }
  };
  if (!overview.account && !state.leaveReceipt && !state.words) return null;
  return (
    <section className="space-y-4">
      {state.error && (
        <p
          role="alert"
          className="whitespace-pre-wrap text-sm text-destructive"
        >
          {revealHidden(state.error)}
        </p>
      )}
      {state.leaveReceipt && (
        <AccountLeaveOutcome receipt={state.leaveReceipt} />
      )}
      {state.words && (
        <AccountRotationOutcome
          words={state.words}
          rotation={state.rotation}
          busy={state.busy}
          clear={reset}
        />
      )}
      {overview.account && !state.words && (
        <details className="rounded-lg border p-4">
          <summary className="text-sm font-medium">
            Advanced sync actions
          </summary>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={blocked}
              onClick={() => setState(clearLifecycleDraft("leave"))}
            >
              Leave sync account…
            </Button>
            <Button
              variant="outline"
              disabled={blocked}
              onClick={() =>
                setState(
                  clearLifecycleDraft("rotate", overview.account?.device_name),
                )
              }
            >
              Rotate sync code…
            </Button>
          </div>
        </details>
      )}
      <Dialog
        open={state.mode !== null}
        onOpenChange={(open) => {
          if (!open && !state.busy) reset();
        }}
      >
        <DialogContent
          className="sm:max-w-xl"
          showCloseButton={!state.busy}
          onEscapeKeyDown={(event) => {
            if (state.busy) event.preventDefault();
          }}
          onInteractOutside={(event) => {
            if (state.busy) event.preventDefault();
          }}
        >
          <DialogTitle>
            {state.mode === "leave" ? "Leave sync account" : "Rotate sync code"}
          </DialogTitle>
          <DialogDescription>
            Review what will be retained before confirming.
          </DialogDescription>
          {state.mode && (
            <AccountLifecycleReview
              mode={state.mode}
              consent={state.consent}
              busy={blocked}
              deviceName={state.deviceName}
              setConsent={(value) => update({ consent: value })}
              setDeviceName={(name) => update({ deviceName: name })}
              confirm={() => void submit()}
              cancel={reset}
            />
          )}
          {state.error && (
            <p role="alert" className="text-sm text-destructive">
              {revealHidden(state.error)}
            </p>
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
