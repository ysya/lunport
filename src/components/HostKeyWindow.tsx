import { useEffect, useState } from "react";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { Button } from "@/components/ui/button";
import {
  answerRejectedMessage,
  armAfterDelay,
  buildHostKeyAnswer,
  fetchPending,
  hostKeyBody,
  hostKeyButtons,
  hostKeyTitle,
  onHostKeyRequests,
  pendingFeed,
  resolveHostKey,
} from "@/lib/hostkey";
import { revealHidden } from "@/lib/sync-approvals";

/** One question: the texts of spec §14 and the two buttons. `armed` says whether the trust button may be pressed yet. Exported for tests. */
export function HostKeyCardView({
  request,
  busy,
  armed,
  onAnswer,
}: {
  request: HostKeyRequest;
  busy: boolean;
  armed: boolean;
  onAnswer: (answer: HostKeyAnswer) => void;
}) {
  const buttons = hostKeyButtons(request);
  return (
    <div className="space-y-3 p-4">
      <h1 className="text-sm font-semibold break-words">{hostKeyTitle(request)}</h1>
      <p className="text-sm break-words">{hostKeyBody(request)}</p>
      {request.changed !== null && (
        <p className="font-mono text-xs text-muted-foreground break-all">
          {revealHidden(request.algorithm)} {revealHidden(request.fingerprint)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => onAnswer(buildHostKeyAnswer(request, false))}>
          {buttons.refuse}
        </Button>
        <Button
          type="button"
          size="sm"
          variant={request.changed === null ? "default" : "destructive"}
          disabled={busy || !armed}
          onClick={() => onAnswer(buildHostKeyAnswer(request, true))}
        >
          {buttons.trust}
        </Button>
      </div>
    </div>
  );
}

/** A question's card: keyed by the question id, so every question gets a card of its own, and its trust button stays off for a moment. */
export function HostKeyCard({ request, busy, onAnswer }: { request: HostKeyRequest; busy: boolean; onAnswer: (answer: HostKeyAnswer) => void }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  return <HostKeyCardView request={request} busy={busy} armed={armed} onAnswer={onAnswer} />;
}

/** The `hostkey` window: the oldest question; Rust opens and destroys the window. */
export default function HostKeyWindow() {
  const [pending, setPending] = useState<HostKeyRequest[]>([]);
  const [answeredId, setAnsweredId] = useState<string | null>(null);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let live = true;
    const feed = pendingFeed((list) => {
      if (live) setPending(list);
    });
    void fetchPending().then(feed.fromFetch);
    void onHostKeyRequests(feed.fromEvent).then((u) => {
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
    <HostKeyCard
      key={request.id}
      request={request}
      busy={answeredId === request.id}
      onAnswer={(answer) => {
        setAnsweredId(request.id);
        void resolveHostKey(request.id, answer).catch((error: unknown) => {
          console.warn(answerRejectedMessage(request.id, error));
          setAnsweredId((current) => (current === request.id ? null : current));
        });
      }}
    />
  );
}
