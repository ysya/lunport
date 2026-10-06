import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type { AgentApprovalAnswer } from "@/bindings/AgentApprovalAnswer";
import type { AgentApprovalRequest } from "@/bindings/AgentApprovalRequest";
import { tauriInvoke } from "@/lib/ipc";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * SSHelter's SSH agent (key vault spec §5.3, §7.4): the approval window's requests and answers. Names come from other
 * programs and servers, so every one of them is shown through `revealHidden`.
 */

export const APPROVALS_EVENT = "agent://approvals";

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
