import { describe, expect, it } from "vitest";
import { terminalRecoveryMessage } from "./terminal-recovery";

describe("terminal recovery messages", () => {
  it.each(["", " material"])("explains unavailable key%s without exposing its internal ID", material => {
    const message = terminalRecoveryMessage({
      kind: "error", failureKind: "host", autoReconnect: true,
      text: `simple needs key fc3f11fff708a1229b4e877f447dbf7f${material} on this device.`,
    });
    expect(message.title).toBe("SSH private key unavailable");
    expect(message.needsKey).toBe(true);
    expect(message.text).toContain("“simple”");
    expect(message.hint).toContain("set up automatic encrypted sync");
    expect(JSON.stringify(message)).not.toContain("fc3f11fff708a1229b4e877f447dbf7f");
    expect(message.hint).not.toContain("new shell");
  });
  it("distinguishes existing mismatched private material from an absent private key", () => {
    const message = terminalRecoveryMessage({ kind: "error", failureKind: "host", autoReconnect: true,
      text: "The saved SSH private key does not match this key reference." });
    expect(message.title).toBe("SSH key identity mismatch");
    expect(message.needsKey).toBe(true);
    expect(message.hint).toContain("fingerprint");
    expect(message.hint).not.toContain("import");
    expect(message.hint).toContain("retained");
  });
  it("reports safe material failures and keeps malformed protocol text out of this recovery path", () => {
    for (const text of ["The saved private key differs from the encrypted account copy.", "The saved SSH private key could not be parsed.", "The saved private key's passphrase state does not match this key reference."]) {
      const message = terminalRecoveryMessage({ kind: "error", failureKind: "host", text, autoReconnect: true });
      expect(message.needsKey).toBe(true);
      expect(message.title).not.toBe("SSH private key unavailable");
    }
    for (const text of ["toString", "__proto__"]) {
      expect(terminalRecoveryMessage({ kind: "error", failureKind: "host", text, autoReconnect: true }).needsKey).toBe(false);
    }
  });
  it("keeps network, fingerprint, authentication and unrelated host failures distinct from missing keys", () => {
    for (const failureKind of ["connect", "host_key", "auth", undefined]) {
      const message = terminalRecoveryMessage({ kind: "error", failureKind, autoReconnect: true,
        text: "simple needs key fc3f11fff708a1229b4e877f447dbf7f material on this device." });
      expect(message.needsKey).toBe(false);
      expect(message.title).toBe("Connection failed");
    }
    expect(terminalRecoveryMessage({ kind: "error", failureKind: "host", text: "Host not found", autoReconnect: true }).needsKey).toBe(false);
  });
  it("retains normal shell-exit and automatic reconnect guidance", () => {
    const ended = terminalRecoveryMessage({ kind: "ended", text: "Shell exited (0)", autoReconnect: true });
    expect(ended).toMatchObject({ title: "Session ended", text: "Shell exited (0)", needsKey: false });
    expect(ended.hint).toContain("Reconnect opens a new shell");
    expect(terminalRecoveryMessage({ kind: "connecting", text: "Waiting", retry: 2, autoReconnect: true })).toMatchObject({
      title: "Reconnecting automatically", text: "Attempt 2 of 5 · Enter to retry now", needsKey: false,
    });
  });
});
