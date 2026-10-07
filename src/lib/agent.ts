import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { toast } from "sonner";

import type { AgentApprovalAnswer } from "@/bindings/AgentApprovalAnswer";
import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import type { AgentProblem } from "@/bindings/AgentProblem";
import { tauriInvoke } from "@/lib/ipc";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * SSHelter's SSH agent (key vault spec §5.3, §7.4): the approval window's requests and answers. Names come from other
 * programs and servers, so every one of them is shown through `revealHidden`.
 */

export const APPROVALS_EVENT = "agent://approvals";
/** Emitted with the host alias when ssh asked a Connect's one-shot key channel for the key after its one-minute window (`oneshot::CONNECT_EXPIRED_EVENT`). */
export const CONNECT_EXPIRED_EVENT = "agent://connect-expired";

export function fetchPending(): Promise<AgentApprovalRequest[]> {
  return tauriInvoke<AgentApprovalRequest[]>("agent_pending");
}

export function resolveApproval(requestId: string, answer: AgentApprovalAnswer): Promise<void> {
  return tauriInvoke<void>("agent_resolve", { requestId, answer });
}

export function onApprovals(handler: (pending: AgentApprovalRequest[]) => void): Promise<UnlistenFn> {
  return listen<AgentApprovalRequest[]>(APPROVALS_EVENT, (event) => handler(event.payload));
}

export function rememberLabel(minutes: number): string {
  switch (minutes) {
    case 15:
      return "Remember for 15 minutes";
    case 60:
      return "Remember for 1 hour";
    case 720:
      return "Remember for 12 hours";
    default:
      return "Remember for 4 hours";
  }
}

export function programName(r: AgentApprovalRequest): string {
  return r.program_chain.length > 0 ? revealHidden(r.program_chain[0]) : "an unknown program";
}

/** "claude → zsh → ssh"; null when there is nothing beyond the program itself. */
export function programChainLine(r: AgentApprovalRequest): string | null {
  return r.program_chain.length > 1 ? r.program_chain.map(revealHidden).join(" → ") : null;
}

export function destination(r: AgentApprovalRequest): string {
  const host = r.host === null ? "an unknown host" : revealHidden(r.host);
  return r.user === null ? host : `${revealHidden(r.user)}@${host}`;
}

export function approvalTitle(r: AgentApprovalRequest): string {
  const key = revealHidden(r.key_name);
  return r.preapproved ? `Unlock ${key} to connect to ${destination(r)}` : `Allow ${programName(r)} to use ${key}?`;
}

/**
 * The answer for a button press. A denial carries nothing. An approval remembers only what the window offered (never for a
 * Connect unlock, which is already approved) and sends the passphrase only when the request asked for one.
 */
export function buildAnswer(
  r: AgentApprovalRequest,
  allow: boolean,
  picked: { remember: boolean; passphrase: string; rememberPassphrase: boolean },
): AgentApprovalAnswer {
  return {
    allow,
    remember: allow && r.rememberable && !r.preapproved && picked.remember,
    passphrase: allow && r.needs_passphrase ? picked.passphrase : null,
    remember_passphrase: allow && r.needs_passphrase && picked.rememberPassphrase,
  };
}

/**
 * How long a new approval card keeps Allow (and Unlock) off after it mounts. The next queued request replaces the answered one
 * within milliseconds, so without this a double click, or a quick second click, would answer a request the user never saw: another
 * program or host, remembered for hours. Longer than a double click (500 ms by default on macOS and Windows), short enough not to
 * be in the way. Deny and Cancel are never held back: they fail closed.
 */
export const ALLOW_ARM_DELAY_MS = 700;

/** Calls `arm` once `ALLOW_ARM_DELAY_MS` has passed. Returns the function that cancels it, for a card that goes away first. */
export function armAfterDelay(arm: () => void): () => void {
  const timer = setTimeout(arm, ALLOW_ARM_DELAY_MS);
  return () => clearTimeout(timer);
}

/**
 * Allow (or Unlock) stays off until the card is armed (`ALLOW_ARM_DELAY_MS`), while an answer is on its way and while a needed
 * passphrase is still empty. The passphrase field's Enter goes through the same check.
 */
export function allowDisabled(r: AgentApprovalRequest, passphrase: string, busy: boolean, armed: boolean): boolean {
  return !armed || busy || (r.needs_passphrase && passphrase.length === 0);
}

/**
 * Whether the card on screen is the request the user already answered: its answer is on the way, or the hub has not dropped it
 * yet. It follows the request, not the IPC call. Once the hub drops the answered request, the next one heads the list as a card
 * of its own, and that card is not busy (it is unarmed instead, `ALLOW_ARM_DELAY_MS`).
 */
export function isAnswering(answeredId: string | null, head: AgentApprovalRequest | undefined): boolean {
  return head !== undefined && head.id === answeredId;
}

/** The answered id once the answer for `failedId` was rejected: cleared so the user can answer again, unless another request was answered since. */
export function afterFailedAnswer(answeredId: string | null, failedId: string): string | null {
  return answeredId === failedId ? null : answeredId;
}

/**
 * The pending list reaches the window two ways: one `fetchPending()` when it opens, and an `agent://approvals` event for every
 * change after that, each carrying the whole list. A fetch still in flight may have read the list before the change an event
 * reports, and would put an older list back, so once an event has arrived the fetch's result is ignored.
 */
export function pendingFeed(set: (list: AgentApprovalRequest[]) => void): {
  fromFetch: (list: AgentApprovalRequest[]) => void;
  fromEvent: (list: AgentApprovalRequest[]) => void;
} {
  let sawEvent = false;
  return {
    fromFetch: (list) => {
      if (!sawEvent) set(list);
    },
    fromEvent: (list) => {
      sawEvent = true;
      set(list);
    },
  };
}

/** Under ["config"], so every sync overview mutation and config change refreshes it. */
export const agentProblemKey = ["config", "agentProblem"] as const;

export function useAgentProblem(enabled: boolean) {
  return useQuery<AgentProblem | null>({
    queryKey: agentProblemKey,
    queryFn: () => tauriInvoke<AgentProblem | null>("agent_problem"),
    enabled,
  });
}

/** Fix: put the Include line back first in ~/.ssh/config (key vault spec §6). */
export function useFixAgentInclude() {
  const queryClient = useQueryClient();
  return useMutation<AgentProblem | null, unknown, void>({
    mutationFn: () => tauriInvoke<AgentProblem | null>("agent_fix_include"),
    onSuccess: (problem) => {
      queryClient.setQueryData(agentProblemKey, problem);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (error) => toast.error("Could not fix ~/.ssh/config", { description: errorMessage(error) }),
  });
}

export function agentProblemText(problem: AgentProblem): string {
  switch (problem.kind) {
    case "not_running":
      return `SSHelter's agent isn't running: ${problem.reason}`;
    case "include_missing":
      return "Hosts that use keys in SSHelter can't reach its agent.";
  }
}

/** ssh asked the one-shot key channel for `alias` for the key after its one-minute window, so it was not offered (key vault spec §5.6, §11). */
export function connectExpiredMessage(alias: string): { title: string; description: string } {
  return {
    title: `Connect to ${revealHidden(alias)} again`,
    description:
      "SSHelter offers the key for one minute after Connect, and ssh asked for it later (a new host's fingerprint question may have been open).",
  };
}
