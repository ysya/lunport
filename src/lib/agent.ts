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
/** Emitted with the host alias when a Connect's one-shot key channel closed before ssh used it (`oneshot::CONNECT_EXPIRED_EVENT`). */
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

/** Allow (or Unlock) stays off while an answer is on its way and while a needed passphrase is still empty. */
export function allowDisabled(r: AgentApprovalRequest, passphrase: string, busy: boolean): boolean {
  return busy || (r.needs_passphrase && passphrase.length === 0);
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

/** The one-shot key channel for `alias` closed before ssh asked for the key (key vault spec §5.6, §11). */
export function connectExpiredMessage(alias: string): { title: string; description: string } {
  return {
    title: `Connect to ${revealHidden(alias)} again`,
    description:
      "ssh didn't ask SSHelter for the key within a minute (a new host's fingerprint question may still be open), so SSHelter stopped offering it.",
  };
}
