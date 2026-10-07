import { useEffect, useState } from "react";

import type { AgentApprovalAnswer } from "@/bindings/AgentApprovalAnswer";
import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  afterFailedAnswer,
  allowDisabled,
  answerRejectedMessage,
  approvalTitle,
  armAfterDelay,
  buildAnswer,
  destination,
  fetchPending,
  isAnswering,
  onApprovals,
  pendingFeed,
  programChainLine,
  rememberLabel,
  resolveApproval,
} from "@/lib/agent";
import { isImeKey } from "@/lib/ime";

/**
 * One request: what asks, for which key and destination, and the answer. `armed` says whether Allow (Unlock) may be pressed yet
 * (`ApprovalCard` arms it after `ALLOW_ARM_DELAY_MS`); Deny (Cancel) never waits. Exported for the markup tests.
 */
export function ApprovalCardView({
  request,
  busy,
  armed,
  onAnswer,
}: {
  request: AgentApprovalRequest;
  busy: boolean;
  armed: boolean;
  onAnswer: (answer: AgentApprovalAnswer) => void;
}) {
  const [remember, setRemember] = useState(request.rememberable);
  const [passphrase, setPassphrase] = useState("");
  const [rememberPassphrase, setRememberPassphrase] = useState(false);
  const cannotAllow = allowDisabled(request, passphrase, busy, armed);
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

/**
 * A request's card. The window keys it by request id, so every request gets a card of its own, and Allow (Unlock) stays off for
 * `ALLOW_ARM_DELAY_MS` after the card mounts. The card that replaces an answered one is therefore never ready for the click
 * that answered the one before it.
 */
export function ApprovalCard({
  request,
  busy,
  onAnswer,
}: {
  request: AgentApprovalRequest;
  busy: boolean;
  onAnswer: (answer: AgentApprovalAnswer) => void;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  return <ApprovalCardView request={request} busy={busy} armed={armed} onAnswer={onAnswer} />;
}

/** The `approval` window (spec §7.4): shows the oldest waiting request; Rust opens and destroys the window. */
export default function AgentApprovalWindow() {
  const [pending, setPending] = useState<AgentApprovalRequest[]>([]);
  // The request the user answered last. Its card stays busy for as long as the hub still lists it (`isAnswering`), whatever the IPC call does.
  const [answeredId, setAnsweredId] = useState<string | null>(null);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let live = true;
    const feed = pendingFeed((list) => {
      if (live) setPending(list);
    });
    void fetchPending().then(feed.fromFetch);
    void onApprovals(feed.fromEvent).then((u) => {
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
      busy={isAnswering(answeredId, request)}
      onAnswer={(answer) => {
        setAnsweredId(request.id);
        // A rejected answer (the call failed, or the request was already gone) leaves the card as it was, so the user can answer again.
        // The console says which request and why; the line is built from the id and the error only, never from the answer.
        void resolveApproval(request.id, answer).catch((error: unknown) => {
          console.warn(answerRejectedMessage(request.id, error));
          setAnsweredId((current) => afterFailedAnswer(current, request.id));
        });
      }}
    />
  );
}
