import { describe, expect, it } from "vitest";
import type { KeyInfo } from "@/bindings/KeyInfo";
import { pickDefaultPublicKey } from "./deploy-key-select";

function key(name: string, pub: string | null): KeyInfo {
  return {
    name,
    private_path: `/home/f/.ssh/${name}`,
    public_path: pub,
    key_type: "ED25519",
    bits: 256,
    fingerprint_sha256: "SHA256:x",
    comment: null,
    in_agent: false,
  };
}

describe("pickDefaultPublicKey", () => {
  it("prefers the host's IdentityFile when it has a sibling .pub", () => {
    const keys = [
      key("id_ed25519", "/home/f/.ssh/id_ed25519.pub"),
      key("work", "/home/f/.ssh/work.pub"),
    ];
    expect(pickDefaultPublicKey(["/home/f/.ssh/work"], keys)).toBe(
      "/home/f/.ssh/work.pub",
    );
  });

  it("falls back to the only key when the host has no IdentityFile", () => {
    const keys = [key("id_ed25519", "/home/f/.ssh/id_ed25519.pub")];
    expect(pickDefaultPublicKey([], keys)).toBe("/home/f/.ssh/id_ed25519.pub");
  });

  it("returns null when several keys exist and none is indicated", () => {
    const keys = [
      key("a", "/home/f/.ssh/a.pub"),
      key("b", "/home/f/.ssh/b.pub"),
    ];
    expect(pickDefaultPublicKey([], keys)).toBeNull();
  });

  it("ignores keys that have no .pub — they cannot be deployed", () => {
    const keys = [key("a", null), key("b", "/home/f/.ssh/b.pub")];
    expect(pickDefaultPublicKey([], keys)).toBe("/home/f/.ssh/b.pub");
  });

  it("ignores an IdentityFile whose key has no .pub and falls back", () => {
    const keys = [key("a", null), key("b", "/home/f/.ssh/b.pub")];
    expect(pickDefaultPublicKey(["/home/f/.ssh/a"], keys)).toBe(
      "/home/f/.ssh/b.pub",
    );
  });

  it("returns null when there are no keys at all", () => {
    expect(pickDefaultPublicKey([], [])).toBeNull();
  });

  // ssh_config keeps IdentityFile verbatim (`~/.ssh/work`), while keys_list
  // reports absolute paths — the two must still match.
  it("matches a ~-prefixed IdentityFile against the key's absolute path", () => {
    const keys = [
      key("id_ed25519", "/home/f/.ssh/id_ed25519.pub"),
      key("work", "/home/f/.ssh/work.pub"),
    ];
    expect(pickDefaultPublicKey(["~/.ssh/work"], keys)).toBe(
      "/home/f/.ssh/work.pub",
    );
  });

  it("does not let a ~-prefixed IdentityFile match a mere name suffix", () => {
    // `~/.ssh/work` must not match `/home/f/.ssh/notwork`.
    const keys = [key("notwork", "/home/f/.ssh/notwork.pub")];
    expect(pickDefaultPublicKey(["~/.ssh/work"], keys)).toBe(
      // Falls back to the only deployable key, NOT via the identity match.
      "/home/f/.ssh/notwork.pub",
    );
  });
});
