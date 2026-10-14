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

/** Keep both clock bounds. Repeated snapshots can shorten but never renew a question. */
export function receiveAuthQuestion(
  request: AuthRequest,
  now: ClockSample,
  previous?: AuthQuestionState,
): AuthQuestionState {
  const same = previous?.request.id === request.id;
  const remaining = Math.max(0, Math.min(120000, request.remaining_ms));
  const state = {
    request,
    wallDeadline: Math.min(now.wall + remaining, same ? previous.wallDeadline : Infinity),
    monotonicDeadline: Math.min(now.monotonic + remaining, same ? previous.monotonicDeadline : Infinity),
    answer: same ? previous.answer : "",
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
