import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import { isValidSlotName } from "@/lib/key-slots";
import { keySlot, SLOT_FINGERPRINT, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import {
  attachText,
  formatDay,
  hasKeyHere,
  KEY_TYPES,
  keyNameOfPath,
  keychainSlots,
  launchHintNeeded,
  moveBannerText,
  moveCount,
  needsAttention,
  otherKeyFiles,
  passphraseFact,
  slotBadges,
  slotPublicPath,
} from "./keychain";

const needsKey = { kind: "needs_key" as const, waiting_for_sync: false };

function keyFile(name: string, overrides: Partial<KeyInfo> = {}): KeyInfo {
  return {
    name,
    private_path: `/home/f/.ssh/${name}`,
    public_path: `/home/f/.ssh/${name}.pub`,
    key_type: "ED25519",
    bits: 256,
    fingerprint_sha256: `SHA256:${name}`,
    comment: null,
    in_agent: false,
    hosts: [],
    ...overrides,
  };
}

describe("the In SSHelter list", () => {
  it("puts the slots that need something done here first, then sorts by name", () => {
    const slots = [
      keySlot({ id: "a".repeat(32), name: "zeta" }),
      keySlot({ id: "b".repeat(32), name: "work", status: { kind: "error", message: "boom" } }),
      keySlot({ id: "c".repeat(32), name: "alpha" }),
      keySlot({ id: "d".repeat(32), name: "mac", status: needsKey }),
      keySlot({ id: "e".repeat(32), name: "beta", status: { kind: "needs_key", waiting_for_sync: true } }),
    ];
    expect(keychainSlots(slots, "").map((s) => s.name)).toEqual(["mac", "work", "alpha", "beta", "zeta"]);
  });

  it("finds a slot by name, type or fingerprint, ignoring case", () => {
    const slots = [
      keySlot({ id: "a".repeat(32), name: "id_mac" }),
      keySlot({ id: "b".repeat(32), name: "work", key_type: "ecdsa-sha2-nistp256", fingerprint: "SHA256:other" }),
    ];
    expect(keychainSlots(slots, "MAC").map((s) => s.name)).toEqual(["id_mac"]);
    expect(keychainSlots(slots, "ecdsa").map((s) => s.name)).toEqual(["work"]);
    expect(keychainSlots(slots, SLOT_FINGERPRINT.slice(7, 20)).map((s) => s.name)).toEqual(["id_mac"]);
    expect(keychainSlots(slots, "  ").map((s) => s.name)).toEqual(["id_mac", "work"]);
  });

  it("marks how each slot is shared and what needs doing", () => {
    expect(slotBadges(keySlot()).map((b) => b.label)).toEqual(["Synced"]);
    expect(slotBadges(keySlot({ mode: "own", status: needsKey })).map((b) => b.label)).toEqual(["Own key on each computer", "Needs a key"]);
    expect(slotBadges(keySlot({ status: { kind: "error", message: "boom" } }))).toEqual([
      { label: "Synced", tone: "plain" },
      { label: "Error", tone: "error" },
    ]);
    expect(slotBadges(keySlot({ in_account: false, file_for_now: true })).map((b) => b.label)).toEqual([
      "Synced",
      "Not in your sync account",
      "File for now",
    ]);
    // A synced key on its way needs nothing done here.
    expect(slotBadges(keySlot({ status: { kind: "needs_key", waiting_for_sync: true } })).map((b) => b.label)).toEqual(["Synced"]);
    expect(needsAttention(keySlot({ file_for_now: true }))).toBe(false);
  });

  it("gives a key only on this computer one badge for how it is shared", () => {
    const local = keySlot({ local_only: true, in_account: false, mode: "own" });
    expect(slotBadges(local).map((b) => b.label)).toEqual(["This computer only"]);
    expect(slotBadges({ ...local, status: { kind: "error", message: "gone" } }).map((b) => b.label)).toEqual(["This computer only", "Error"]);
  });
});

describe("a key's facts", () => {
  it("shows a day as YYYY-MM-DD, and whether the key has a passphrase", () => {
    expect(formatDay(1_700_049_600_000)).toBe("2023-11-15");
    expect(passphraseFact(keySlot({ vault_has_passphrase: true, has_passphrase: false }))).toBe("Yes");
    expect(passphraseFact(keySlot({ vault_has_passphrase: null, has_passphrase: false }))).toBe("No");
    expect(passphraseFact(keySlot({ vault_has_passphrase: null, has_passphrase: null }))).toBeNull();
  });
});

describe("Generate key's kinds", () => {
  it("offers Ed25519, RSA 3072, RSA 4096 and ECDSA P-256, each with the name it suggests", () => {
    expect(KEY_TYPES).toEqual([
      { algorithm: "ed25519", label: "Ed25519", name: "id_ed25519" },
      { algorithm: "rsa3072", label: "RSA 3072", name: "id_rsa" },
      { algorithm: "rsa4096", label: "RSA 4096", name: "id_rsa" },
      { algorithm: "ecdsa_p256", label: "ECDSA P-256", name: "id_ecdsa" },
    ]);
  });

  it("suggests only names a key can have", () => {
    for (const { name } of KEY_TYPES) expect(isValidSlotName(name), name).toBe(true);
  });
});

describe("other key files in ~/.ssh", () => {
  it("leaves out a file a slot still serves, and lists one a slot only copied into SSHelter", () => {
    const keys = [keyFile("id_mac"), keyFile("id_work"), keyFile("id_old")];
    const slots = [
      keySlot({ status: { kind: "ready", file: "/home/f/.ssh/id_mac", synced_copy: false, fingerprint: null } }),
      keySlot({ id: "b".repeat(32), in_vault: true, status: { kind: "ready", file: "/home/f/.ssh/id_work", synced_copy: false, fingerprint: null } }),
    ];
    expect(otherKeyFiles(keys, slots, "").map((k) => k.name)).toEqual(["id_work", "id_old"]);
  });

  it("compares Windows paths without regard to case or separator", () => {
    const keys = [keyFile("id_win", { private_path: "C:\\Users\\Frank\\.ssh\\id_win" })];
    const slots = [keySlot({ status: { kind: "ready", file: "c:/users/frank/.ssh/ID_WIN", synced_copy: false, fingerprint: null } })];
    expect(otherKeyFiles(keys, slots, "")).toEqual([]);
  });

  it("finds a file by name, type or fingerprint", () => {
    const keys = [keyFile("id_mac"), keyFile("deploy", { key_type: "RSA", fingerprint_sha256: "SHA256:XyZ" })];
    expect(otherKeyFiles(keys, [], "rsa").map((k) => k.name)).toEqual(["deploy"]);
    expect(otherKeyFiles(keys, [], "xyz").map((k) => k.name)).toEqual(["deploy"]);
  });
});

describe("the banners", () => {
  it("count the keys that can move into SSHelter", () => {
    expect(moveCount([keySlot(), keySlot({ file_for_now: true }), keySlot({ file_for_now: true, in_account: false })])).toBe(2);
    expect(moveBannerText(1)).toBe("1 key can move into SSHelter");
    expect(moveBannerText(3)).toBe("3 keys can move into SSHelter");
  });

  it("suggest launching at login once a key is in SSHelter and nothing keeps SSHelter running", () => {
    const base = { anyInVault: true, launchAtLogin: false, closeToTray: false, dismissed: false };
    expect(launchHintNeeded(base)).toBe(true);
    expect(launchHintNeeded({ ...base, anyInVault: false })).toBe(false);
    expect(launchHintNeeded({ ...base, launchAtLogin: true })).toBe(false);
    expect(launchHintNeeded({ ...base, closeToTray: true })).toBe(false);
    expect(launchHintNeeded({ ...base, dismissed: true })).toBe(false);
    // Unknown until the OS answers: no hint yet.
    expect(launchHintNeeded({ ...base, launchAtLogin: null })).toBe(false);
  });
});

describe("Export to host", () => {
  const HOME = "/home/f";
  const KEY = "/home/f/.ssh/sshelter/keys/id_mac-3fa2c1d9";

  it("says which keys the host stops using", () => {
    expect(attachText("web", "id_mac", ["~/.ssh/id_rsa", "\"/home/f/.ssh/id work\""], KEY, HOME)).toBe(
      "web will use id_mac instead of id_rsa and id work",
    );
    expect(attachText("web", "id_mac", [], KEY, HOME)).toBe("web will use id_mac");
  });

  it("says nothing when the host already uses only this key, and leaves this key out of the old ones", () => {
    expect(attachText("web", "id_mac", ["~/.ssh/sshelter/keys/id_mac-3fa2c1d9"], KEY, HOME)).toBeNull();
    expect(attachText("web", "id_mac", ["%d/.ssh/sshelter/keys/id_mac-3fa2c1d9", "~/.ssh/id_rsa"], KEY, HOME)).toBe(
      "web will use id_mac instead of id_rsa",
    );
  });

  it("reveals hidden characters in the host, the key and the old keys", () => {
    expect(attachText(SPOOFED_NAME, SPOOFED_NAME, [`~/.ssh/${SPOOFED_NAME}`], KEY, HOME)).toBe(
      `${SPOOFED_NAME_SHOWN} will use ${SPOOFED_NAME_SHOWN} instead of ${SPOOFED_NAME_SHOWN}`,
    );
  });

  it("says nothing while the home isn't known: a host already on this key would read as leaving it", () => {
    const file = "/home/f/.ssh/id_ed25519";
    // The home is what lets a `~/` value be matched against the key's path.
    expect(attachText("web", "id_ed25519", ["~/.ssh/id_ed25519"], file, HOME)).toBeNull();
    expect(attachText("web", "id_ed25519", ["~/.ssh/id_ed25519"], file, null)).toBeNull();
    expect(attachText("web", "id_mac", ["~/.ssh/id_rsa"], KEY, null)).toBeNull();
    expect(attachText("web", "id_mac", [], KEY, null)).toBeNull();
  });

  it("names a key by the last part of its path", () => {
    expect(keyNameOfPath("~/.ssh/id_rsa")).toBe("id_rsa");
    expect(keyNameOfPath("\"C:\\Users\\f\\.ssh\\id work\"")).toBe("id work");
  });

  it("finds a slot's public key under the home, once the home is known", () => {
    expect(slotPublicPath(keySlot(), HOME)).toBe("/home/f/.ssh/sshelter/keys/id_mac-3fa2c1d9.pub");
    expect(slotPublicPath(keySlot(), "C:\\Users\\f\\")).toBe("C:\\Users\\f/.ssh/sshelter/keys/id_mac-3fa2c1d9.pub");
    expect(slotPublicPath(keySlot(), null)).toBeNull();
  });

  it("copies or exports a slot's public key only while this computer has the key", () => {
    expect(hasKeyHere(keySlot())).toBe(true);
    expect(hasKeyHere(keySlot({ status: { kind: "not_in_use", file: "/f" } }))).toBe(true);
    expect(hasKeyHere(keySlot({ status: needsKey }))).toBe(false);
    expect(hasKeyHere(keySlot({ status: { kind: "error", message: "boom" } }))).toBe(false);
    expect(hasKeyHere(keySlot({ status: { kind: "not_used_here" } }))).toBe(false);
  });
});
