import { useEffect, useRef, useState } from "react";
import { KeyRound } from "lucide-react";

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
  useEffect(() => { cancel.current?.focus(); }, [request.id]);
  const expired = remainingMs <= 0;
  const inactive = expired || abandoned;
  const cannotSubmit = busy || !armed || inactive;

  return (
    <div className="app-shell flex h-full min-h-0 flex-col overflow-hidden">
      <header className="flex shrink-0 items-center gap-2 px-5 pt-4 pb-2">
        <KeyRound className="size-5 shrink-0 text-primary" />
        <h1 className="text-sm font-semibold">SSH authentication</h1>
        <span className="ml-auto text-xs text-muted-foreground">
          {Math.ceil(Math.max(0, remainingMs) / 1000)}s
        </span>
      </header>
      <main className="min-h-0 flex-1 space-y-2 overflow-y-auto break-all px-5 pb-3 text-xs">
        <div className="space-y-1 rounded-lg border bg-muted/30 p-2">
          <p>Request: {revealHidden(request.request_id)} · Question: {revealHidden(request.id)}</p>
          {request.hop ? (
            <>
              <p>Server: {revealHidden(request.hop.alias)} · ID: {revealHidden(request.hop.host_id)}</p>
              <p>{revealHidden(request.hop.user)}@{revealHidden(request.hop.hostname)}:{request.hop.port}</p>
            </>
          ) : <p>Server context: Unknown</p>}
        </div>
        <div>
          <p className="mb-1 text-muted-foreground">Server prompt · {revealHidden(request.kind)}</p>
          <pre className="whitespace-pre-wrap break-all font-sans">{revealHidden(request.text)}</pre>
        </div>
      </main>
      <section aria-label="Authentication response" className="shrink-0 space-y-2 px-5 pb-3 text-xs">
        {inactive ? (
          <p role="alert" className={busy ? "text-muted-foreground" : "text-destructive"}>
            {expired ? "This question expired. Previous input was cleared. Start a fresh connection request to retry."
              : busy ? "Answer cleared. Waiting for the server…"
              : "This answer was abandoned. Previous input was cleared. Start a fresh connection request to retry."}
          </p>
        ) : (
          <Input
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
        )}
        {error && <p role="alert" className="text-destructive">{error}</p>}
      </section>
      <footer className="flex shrink-0 justify-end gap-2 border-t px-5 py-3">
        <Button autoFocus ref={cancel} variant="outline" disabled={busy} onClick={() => onAnswer(null)}>Cancel</Button>
        <Button disabled={cannotSubmit} onClick={() => onAnswer(answer)}>{busy ? "Sending…" : "Submit"}</Button>
      </footer>
    </div>
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
