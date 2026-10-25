import type { ApprovalMode } from "@/bindings/ApprovalMode";
import type { AuthRequest } from "@/bindings/AuthRequest";

export type ClockSample = { wall: number; monotonic: number };
export const sampleClock = (): ClockSample => ({
  wall: Date.now(),
  monotonic: performance.now(),
});
export type AuthQuestionState = {
  request: AuthRequest;
  wallDeadline: number;
  monotonicDeadline: number;
  answer: string;
  abandoned: boolean;
};

/** Returns true when a risk confirmation must be opened, without applying a mode. */
export function chooseMcpMode(
  mode: ApprovalMode,
  acknowledged: boolean,
  apply: (mode: ApprovalMode, acknowledged: boolean) => void,
): boolean {
  if (mode === "auto_log" && !acknowledged) return true;
  apply(mode, mode === "auto_log" && acknowledged);
  return false;
}

/** How long a question may wait: a server's two minutes; a grant request (design 2026-10-25, PAM grant requests) five. */
export const SERVER_QUESTION_MS = 120000;
export const GRANT_QUESTION_MS = 300000;
/** The longest grant the form lets a person ask for, in minutes (the broker refuses more; the entitlement may allow less). */
export const MAX_GRANT_MINUTES = 480;
const MAX_GRANT_JUSTIFICATION_CHARS = 512;

/** Both fields of a grant form travel in the one answer string a question carries, as `<minutes>\n<justification>` (the broker decodes the same). */
export function encodeGrantAnswer(minutes: string, justification: string): string {
  return `${minutes}\n${justification}`;
}

export function grantFields(answer: string): { minutes: string; justification: string } {
  const at = answer.indexOf("\n");
  return at < 0 ? { minutes: answer, justification: "" } : { minutes: answer.slice(0, at), justification: answer.slice(at + 1) };
}

/** A justification the broker accepts: something in it, one line, no control characters, at most 512 characters (the same rule as `GrantAnswer::decode`). */
export function justificationAcceptable(justification: string): boolean {
  const words = justification.trim().length;
  return words > 0 && words <= MAX_GRANT_JUSTIFICATION_CHARS && !/[\u0000-\u001f\u007f]/.test(justification.trim());
}

/** Whether Request may go: whole minutes from 1 to the limit, and a justification the broker accepts. */
export function grantAnswerReady(answer: string): boolean {
  const { minutes, justification } = grantFields(answer);
  const whole = /^\d+$/.test(minutes.trim()) ? Number(minutes.trim()) : NaN;
  return whole >= 1 && whole <= MAX_GRANT_MINUTES && justificationAcceptable(justification);
}

/** A grant form starts from the transport's stored duration and last justification; every other question starts empty. */
function initialAnswer(request: AuthRequest): string {
  return request.kind === "grant" && request.grant
    ? encodeGrantAnswer(String(request.grant.minutes), request.grant.justification ?? "")
    : "";
}

/** Keep both clock bounds. Repeated snapshots can shorten but never renew a question. */
export function receiveAuthQuestion(
  request: AuthRequest,
  now: ClockSample,
  previous?: AuthQuestionState,
): AuthQuestionState {
  const same = previous?.request.id === request.id;
  const cap = request.kind === "grant" ? GRANT_QUESTION_MS : SERVER_QUESTION_MS;
  const remaining = Math.max(0, Math.min(cap, request.remaining_ms));
  const state = {
    request,
    wallDeadline: Math.min(now.wall + remaining, same ? previous.wallDeadline : Infinity),
    monotonicDeadline: Math.min(now.monotonic + remaining, same ? previous.monotonicDeadline : Infinity),
    answer: same ? previous.answer : initialAnswer(request),
    abandoned: same ? previous.abandoned : false,
  };
  if (authRemaining(state, now) === 0) {
    state.answer = "";
    state.abandoned = true;
  }
  return state;
}

export function authRemaining(state: AuthQuestionState, now: ClockSample): number {
  return Math.max(0, Math.min(state.wallDeadline - now.wall, state.monotonicDeadline - now.monotonic));
}

/** Consume only once, clear before invoking native code, and never replay after a failure. */
export function takeAuthAnswer(state: AuthQuestionState, now: ClockSample): string | null {
  const answer = state.abandoned || authRemaining(state, now) === 0 ? null : state.answer;
  state.answer = "";
  state.abandoned = true;
  return answer;
}
