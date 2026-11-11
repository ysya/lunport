import type { AiAsker } from "@/bindings/AiAsker";
import { revealHidden } from "@/lib/reveal-hidden";

/** Who asked, when an AI client's request opened the window. The client's name is
 *  what Lunport observed, shown through `revealHidden` like every other outside string. */
export function askedBy(ai: AiAsker): string {
  return `Asked by ${revealHidden(ai.client)}, an AI client using Lunport AI access.`;
}

/** Which window the person agrees in: the host key window, the Request-a-grant form, or a server's question (password, passphrase,
 *  keyboard-interactive). */
export type AgreeingIn = "hostkey" | "grant" | "question";

/** What goes ahead without per-command review once the person agrees in this window (Auto-log); `null` in Ask mode and for a
 *  verification, where nothing runs unreviewed. */
export function unreviewedNote(ai: AiAsker, window: AgreeingIn): string | null {
  if (ai.unreviewed === null) return null;
  const once = window === "hostkey" ? "once you trust this key" : window === "grant" ? "once the grant is active" : "once you answer";
  if (ai.unreviewed === "tunnel") return `Auto-log is on: ${once}, the tunnel the AI client asked for starts right away, without review.`;
  if (ai.unreviewed === "database") return `Auto-log is on: ${once}, the database the AI client asked for starts right away, without review.`;
  if (ai.unreviewed === "transfer") return `Auto-log is on: ${once}, the AI client’s file transfer starts right away, without review.`;
  if (window === "grant") return "Auto-log is on: while the grant lasts, the AI client’s commands run without per-command review.";
  return `Auto-log is on: ${once}, the AI client’s command runs right away, without per-command review.`;
}
