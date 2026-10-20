import type { TerminalStatus } from "./terminal-session";
import { revealHidden } from "./sync-approvals";

/** The broker's existing host-error sentences distinguish unavailable key
 * material from network/authentication errors without changing its protocol. */
export function terminalRecoveryMessage(status: TerminalStatus) {
  const key = status.kind === "error" && status.failureKind === "host"
    ? /^(.+) needs key [a-f0-9]{32}(?: material)? on this device\.$/.exec(status.text)
    : null;
  if (key) return {
    title: "SSH private key unavailable",
    text: `The SSH private key for “${revealHidden(key[1])}” is unavailable on this device.`,
    hint: "Open Keys to download the synced key or import the matching private key, then try again.",
    needsKey: true,
  };
  return {
    title: status.retry ? "Reconnecting automatically" : status.kind === "error" ? "Connection failed" : "Session ended",
    text: status.retry ? `Attempt ${status.retry} of 5 · Enter to retry now` : revealHidden(status.text),
    hint: status.kind === "error" ? "Review the error above, then try again." : "Previous output stays here. Reconnect opens a new shell.",
    needsKey: false,
  };
}
