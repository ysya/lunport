import { useEffect, useId, useRef, useState } from "react";
import { KeyRound } from "lucide-react";
import { DecisionLayout } from "@/components/app/DecisionLayout";

import type { AuthRequest } from "@/bindings/AuthRequest";
import { armAfterDelay } from "@/lib/hostkey";
import {
  authRemaining,
  receiveAuthQuestion,
  sampleClock,
  takeAuthAnswer,
  type ClockSample,
} from "@/lib/mcp-flow";
import {
  followAuthentication,
  resolveAuthentication,
  type AuthenticationSnapshot,
} from "@/lib/authentication";
import { revealHidden } from "@/lib/sync-approvals";
import { useApplyTheme } from "@/lib/theme";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export type AuthenticationCardViewProps = {
  request: AuthRequest;
  busy: boolean;
  armed: boolean;
  remainingMs: number;
  answer: string;
  abandoned?: boolean;
  error?: string | null;
  onChange: (value: string) => void;
  onAnswer: (value: string | null) => void;
};

export function AuthenticationCardView({
  request, busy, armed, remainingMs, answer, abandoned = false, error, onChange, onAnswer,
}: AuthenticationCardViewProps) {
  const cancel = useRef<HTMLButtonElement>(null);
  const answerId = useId();
  useEffect(() => { cancel.current?.focus(); }, [request.id]);
  const expired = remainingMs <= 0;
  const inactive = expired || abandoned;
  const cannotSubmit = busy || !armed || inactive;

  return (
    <DecisionLayout
      title="SSH authentication"
      icon={<KeyRound className="size-5" />}
      meta={`${Math.ceil(Math.max(0, remainingMs) / 1000)}s`}
      actions={<>
        <Button autoFocus ref={cancel} variant="outline" disabled={busy} onClick={() => onAnswer(null)}>Cancel</Button>
        <Button disabled={cannotSubmit} onClick={() => onAnswer(answer)}>{busy ? "Sending…" : "Submit"}</Button>
      </>}
      response={
      <section aria-label="Authentication response" className="space-y-2 text-xs">
        {inactive ? (
          <p role="alert" className={busy ? "text-muted-foreground" : "text-destructive"}>
            {expired ? "This question expired. Previous input was cleared. Start a fresh connection request to retry."
              : busy ? "Answer cleared. Waiting for the server…"
              : "This answer was abandoned. Previous input was cleared. Start a fresh connection request to retry."}
          </p>
        ) : (
          <>
          <Label htmlFor={answerId}>Authentication answer</Label>
          <Input
            id={answerId}
            aria-label="Authentication answer"
            type={request.echo ? "text" : "password"}
            value={answer}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            disabled={busy}
            onChange={event => onChange(event.target.value)}
            onKeyDown={event => {
              if (event.key !== "Enter") return;
              event.preventDefault();
              if (!event.nativeEvent.isComposing && !cannotSubmit) onAnswer(answer);
            }}
          />
          </>
        )}
        {error && <p role="alert" className="text-destructive">{error}</p>}
      </section>
      }
    >
        <section aria-label="Connection context" className="space-y-1 text-sm">
          {request.hop ? (
            <>
              <p className="font-medium">{revealHidden(request.hop.alias)}</p>
              <p className="break-all font-mono text-xs text-muted-foreground">{revealHidden(request.hop.user)}@{revealHidden(request.hop.hostname)}:{request.hop.port}</p>
            </>
          ) : <p>Server context: Unknown</p>}
        </section>
        <div>
          <p className="mb-1 text-muted-foreground">Server prompt · {revealHidden(request.kind)}</p>
          <pre className="whitespace-pre-wrap break-all font-sans">{revealHidden(request.text)}</pre>
        </div>
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Connection details</summary>
          <div className="mt-2 space-y-1 break-all font-mono">
            <p>Request: {revealHidden(request.request_id)}</p>
            <p>Question: {revealHidden(request.id)}</p>
            {request.hop && <p>Host ID: {revealHidden(request.hop.host_id)}</p>}
          </div>
        </details>
    </DecisionLayout>
  );
}

/** Native window keys this by question ID so a new challenge starts with no old input. */
export function AuthenticationCard({ request, receivedAt, onResolve = resolveAuthentication }: {
  request: AuthRequest;
  receivedAt?: ClockSample;
  onResolve?: (requestId: string, value: string | null) => Promise<void>;
}) {
  const initialReceipt = useRef(receivedAt ?? sampleClock()).current;
  const receipt = receivedAt ?? initialReceipt;
  const [state, setState] = useState(() => receiveAuthQuestion(request, receipt));
  const stateRef = useRef(state);
  stateRef.current = state;
  const [now, setNow] = useState(sampleClock);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const answering = useRef(false);

  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  useEffect(() => {
    setState(previous => receiveAuthQuestion(request, receipt, previous));
  }, [request, receipt.wall, receipt.monotonic]);
  useEffect(() => {
    const timer = setInterval(() => {
      const clock = sampleClock();
      setNow(clock);
      if (authRemaining(stateRef.current, clock) === 0) {
        setState(previous => ({ ...previous, answer: "", abandoned: true }));
      }
    }, 100);
    return () => {
      clearInterval(timer);
      stateRef.current.answer = "";
    };
  }, []);

  const answer = async (value: string | null) => {
    if (answering.current) return;
    const current = stateRef.current;
    if (value !== null && (!armed || current.abandoned || authRemaining(current, sampleClock()) === 0)) return;
    // Consume only the current input, and clear before crossing IPC. Errors never include its value.
    const submitted = value === null ? null : takeAuthAnswer(current, sampleClock());
    current.answer = "";
    current.abandoned = true;
    setState({ ...current });
    answering.current = true;
    setBusy(true);
    setError(null);
    try {
      await onResolve(current.request.id, submitted);
    } catch {
      setError("Could not submit this question. Input was cleared; start a fresh connection request.");
    } finally {
      answering.current = false;
      setBusy(false);
    }
  };

  return (
    <AuthenticationCardView
      request={state.request}
      busy={busy}
      armed={armed}
      remainingMs={authRemaining(state, now)}
      answer={state.answer}
      abandoned={state.abandoned}
      error={error}
      onChange={value => {
        if (!stateRef.current.abandoned && authRemaining(stateRef.current, sampleClock()) > 0) {
          setState(previous => ({ ...previous, answer: value }));
        }
      }}
      onAnswer={value => void answer(value)}
    />
  );
}

export default function AuthenticationWindow() {
  useApplyTheme();
  const [pending, setPending] = useState<AuthenticationSnapshot[]>([]);
  const [error, setError] = useState(false);
  useEffect(() => followAuthentication(list => {
    setError(false);
    setPending(list);
  }, () => setError(true)), []);
  const question = pending[0];
  return question ? (
    <AuthenticationCard key={question.request.id} request={question.request} receivedAt={question.receivedAt} />
  ) : (
    <div className="app-shell flex h-full items-center justify-center p-5 text-center text-sm text-muted-foreground">
      {error ? "Authentication questions are unavailable. Close this window and start a fresh connection." : "Waiting for an authentication question…"}
    </div>
  );
}
