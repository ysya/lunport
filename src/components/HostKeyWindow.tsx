import { useEffect, useState } from "react";
import { Check, Copy, KeyRound, ShieldAlert } from "lucide-react";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { Button } from "@/components/ui/button";
import { DecisionLayout } from "@/components/app/DecisionLayout";
import {
  answerRejectedMessage,
  armAfterDelay,
  buildHostKeyAnswer,
  fetchPending,
  followPending,
  hostKeyBody,
  hostKeyButtons,
  hostKeyTitle,
  hostKeyEndpoint,
  pinnedOn,
  resolveHostKey,
} from "@/lib/hostkey";
import { revealHidden } from "@/lib/sync-approvals";
import { copyText } from "@/lib/clipboard";
import { useApplyTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

/** One server identity question. `armed` says whether the trust button may be pressed yet. Exported for tests. */
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
  const changed = request.changed !== null;
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);
  const copy = async () => {
    setCopyError(false);
    try {
      await copyText(request.fingerprint);
      setCopied(true);
    } catch {
      setCopyError(true);
    }
  };
  return (
    <DecisionLayout
      title={hostKeyTitle(request)}
      description={revealHidden(request.alias)}
      icon={changed ? <ShieldAlert className="size-5" /> : <KeyRound className="size-5" />}
      danger={changed}
      actions={<>
        <Button
          type="button"
          variant="outline"
          size="sm"
          autoFocus
          disabled={busy}
          onClick={() => onAnswer(buildHostKeyAnswer(request, false))}
        >
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
      </>}
    >
        {changed && (
          <p role="alert" className="text-xs leading-relaxed text-destructive">
            {hostKeyBody(request)}
          </p>
        )}
        <div className="flex items-start justify-between gap-4 text-xs">
          <div className="min-w-0 space-y-1">
            <p className="text-muted-foreground">Server</p>
            <p className="break-all font-mono">{`${request.user ? `${revealHidden(request.user)}@` : ""}${hostKeyEndpoint(request)}`}</p>
          </div>
          <div className="shrink-0 space-y-1 text-right">
            <p className="text-muted-foreground">Key type</p>
            <p className="font-mono">{revealHidden(request.algorithm)}</p>
          </div>
        </div>
        <section
          aria-label="Server fingerprint"
          className={cn(
            "rounded-lg border bg-muted/40 px-3 py-2",
            changed && "border-destructive/30",
          )}
        >
          <div className="mb-1 flex items-center justify-between gap-2">
            <h2 className="text-xs font-medium">
              {changed ? "Presented fingerprint" : "SHA-256 fingerprint"}
            </h2>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label="Copy server fingerprint"
              onClick={() => void copy()}
            >
              {copied ? <Check /> : <Copy />}
            </Button>
          </div>
          <p className="select-text break-all font-mono text-xs leading-relaxed">
            {revealHidden(request.fingerprint)}
          </p>
        </section>
        {request.changed && (
          <section
            aria-label="Saved fingerprint"
            className="space-y-1 text-xs text-muted-foreground"
          >
            <h2 className="font-medium">
              Saved fingerprint · {pinnedOn(request.changed.pinned_at_ms)}
            </h2>
            <p className="select-text break-all font-mono">
              {revealHidden(request.changed.fingerprint)}
            </p>
          </section>
        )}
        {!changed && (
          <p className="text-xs leading-relaxed text-muted-foreground">
            {hostKeyBody(request)}
          </p>
        )}
        {copied && (
          <p role="status" className="sr-only">
            Fingerprint copied
          </p>
        )}
        {copyError && (
          <p role="status" className="text-xs text-muted-foreground">
            Could not copy. Select the fingerprint and copy it manually.
          </p>
        )}
    </DecisionLayout>
  );
}

/** A question's card: keyed by the question id, so every question gets a card of its own, and its trust button stays off for a moment. */
export function HostKeyCard({
  request,
  busy,
  onAnswer,
}: {
  request: HostKeyRequest;
  busy: boolean;
  onAnswer: (answer: HostKeyAnswer) => void;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  return (
    <HostKeyCardView
      request={request}
      busy={busy}
      armed={armed}
      onAnswer={onAnswer}
    />
  );
}

/** The `hostkey` window: the oldest question; Rust opens and destroys the window. */
export default function HostKeyWindow() {
  useApplyTheme();
  const [pending, setPending] = useState<HostKeyRequest[]>([]);
  const [answeredId, setAnsweredId] = useState<string | null>(null);
  // The listener first, then the fetch (`followPending`): no change can fall between the two.
  useEffect(() => followPending(setPending), []);
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
          // The question may have left the list before the window heard of it: the list as it is now.
          void fetchPending().then(setPending);
        });
      }}
    />
  );
}
