import { useEffect, useState } from "react";

import type { AgentApprovalAnswer } from "@/bindings/AgentApprovalAnswer";
import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  allowDisabled,
  approvalTitle,
  buildAnswer,
  destination,
  fetchPending,
  onApprovals,
  programChainLine,
  rememberLabel,
  resolveApproval,
} from "@/lib/agent";
import { isImeKey } from "@/lib/ime";

/** One request: what asks, for which key and destination, and the answer. Exported for the markup tests. */
export function ApprovalCard({
  request,
  busy,
  onAnswer,
}: {
  request: AgentApprovalRequest;
  busy: boolean;
  onAnswer: (answer: AgentApprovalAnswer) => void;
}) {
  const [remember, setRemember] = useState(request.rememberable);
  const [passphrase, setPassphrase] = useState("");
  const [rememberPassphrase, setRememberPassphrase] = useState(false);
  const cannotAllow = allowDisabled(request, passphrase, busy);
  const chain = programChainLine(request);
  const answer = (allow: boolean) => onAnswer(buildAnswer(request, allow, { remember, passphrase, rememberPassphrase }));
  return (
    <div className="space-y-3 p-4">
      <h1 className="text-sm font-semibold break-words">{approvalTitle(request)}</h1>
      {chain && <p className="text-xs text-muted-foreground break-all">{chain}</p>}
      {!request.preapproved && <p className="text-sm break-all">{destination(request)}</p>}
      <p className="font-mono text-xs text-muted-foreground break-all">{request.key_fingerprint}</p>
      {request.needs_passphrase && (
        <div className="space-y-2">
          <Input
            type="password"
            autoFocus
            value={passphrase}
            aria-label="Passphrase"
            placeholder="Passphrase"
            onChange={(e) => setPassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (isImeKey(e)) return;
              if (e.key === "Enter" && !cannotAllow) answer(true);
            }}
          />
          {request.passphrase_error && <p className="text-xs text-destructive">{request.passphrase_error}</p>}
          <label className="flex items-center gap-2 text-xs">
            <Checkbox checked={rememberPassphrase} onCheckedChange={(v) => setRememberPassphrase(v === true)} />
            Remember on this computer
          </label>
        </div>
      )}
      {request.rememberable && !request.preapproved && (
        <label className="flex items-center gap-2 text-xs">
          <Checkbox checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
          {rememberLabel(request.remember_minutes)}
        </label>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => answer(false)}>
          {request.preapproved ? "Cancel" : "Deny"}
        </Button>
        <Button type="button" size="sm" disabled={cannotAllow} onClick={() => answer(true)}>
          {request.preapproved ? "Unlock" : "Allow"}
        </Button>
      </div>
    </div>
  );
}

/** The `approval` window (spec §7.4): shows the oldest waiting request; Rust opens and destroys the window. */
export default function AgentApprovalWindow() {
  const [pending, setPending] = useState<AgentApprovalRequest[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let live = true;
    void fetchPending().then((list) => live && setPending(list));
    void onApprovals((list) => setPending(list)).then((u) => {
      if (live) unlisten = u;
      else u();
    });
    return () => {
      live = false;
      unlisten?.();
    };
  }, []);
  const request = pending[0];
  if (!request) return null;
  return (
    <ApprovalCard
      key={request.id}
      request={request}
      busy={busy}
      onAnswer={(answer) => {
        setBusy(true);
        void resolveApproval(request.id, answer).finally(() => setBusy(false));
      }}
    />
  );
}
