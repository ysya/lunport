import type { TerminalStatus } from "./terminal-session";
import { revealHidden } from "./sync-approvals";

/** The broker's existing host-error sentences distinguish unavailable key
 * material from network/authentication errors without changing its protocol. */
export function terminalRecoveryMessage(status: TerminalStatus) {
  const keyProblems: Record<string, string> = {
    "The saved SSH private key does not match this key reference.": "SSH key identity mismatch",
    "The saved private key differs from the encrypted account copy.": "SSH key sync required",
    "The saved SSH private key could not be parsed.": "SSH private key unreadable",
    "The saved private key's passphrase state does not match this key reference.": "SSH key metadata mismatch",
  };
  const problem = status.kind === "error" && status.failureKind === "host" && Object.prototype.hasOwnProperty.call(keyProblems, status.text) ? keyProblems[status.text] : undefined;
  if (problem) return {
    title: problem,
    text: status.text,
    hint: "Open Keys to review the fingerprint, sync state and the host’s selected key. The saved private key has been retained.",
    needsKey: true,
  };
  const key = status.kind === "error" && status.failureKind === "host"
    ? /^(.+) needs key [a-f0-9]{32}(?: material)? on this device\.$/.exec(status.text)
    : null;
  if (key) return {
    title: "SSH private key unavailable",
    text: `The SSH private key for “${revealHidden(key[1])}” is unavailable on this device.`,
    hint: "Open Keys to review this host’s key and set up automatic encrypted sync. If you import the matching private key, select it for this host before retrying.",
    needsKey: true,
  };
  return {
    title: status.retry ? "Reconnecting automatically" : status.kind === "error" ? "Connection failed" : "Session ended",
    text: status.retry ? `Attempt ${status.retry} of 5 · Enter to retry now` : revealHidden(status.text),
    hint: status.kind === "error" ? "Review the error above, then try again." : "Previous output stays here. Reconnect opens a new shell.",
    needsKey: false,
  };
}
