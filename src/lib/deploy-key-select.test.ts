import { describe, expect, it } from "vitest";
import type { KeyInfo } from "@/bindings/KeyInfo";
import { pickDefaultPublicKey } from "./deploy-key-select";

const HOME = "/home/f";

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
    expect(pickDefaultPublicKey(["/home/f/.ssh/work"], keys, HOME)).toBe(
      "/home/f/.ssh/work.pub",
    );
  });

  it("falls back to the only key when the host has no IdentityFile", () => {
    const keys = [key("id_ed25519", "/home/f/.ssh/id_ed25519.pub")];
    expect(pickDefaultPublicKey([], keys, HOME)).toBe("/home/f/.ssh/id_ed25519.pub");
  });

  it("returns null when several keys exist and none is indicated", () => {
    const keys = [
      key("a", "/home/f/.ssh/a.pub"),
      key("b", "/home/f/.ssh/b.pub"),
    ];
    expect(pickDefaultPublicKey([], keys, HOME)).toBeNull();
  });

  it("ignores keys that have no .pub — they cannot be deployed", () => {
    const keys = [key("a", null), key("b", "/home/f/.ssh/b.pub")];
    expect(pickDefaultPublicKey([], keys, HOME)).toBe("/home/f/.ssh/b.pub");
  });

  it("ignores an IdentityFile whose key has no .pub and falls back", () => {
    const keys = [key("a", null), key("b", "/home/f/.ssh/b.pub")];
    expect(pickDefaultPublicKey(["/home/f/.ssh/a"], keys, HOME)).toBe(
      "/home/f/.ssh/b.pub",
    );
  });

  it("returns null when there are no keys at all", () => {
    expect(pickDefaultPublicKey([], [], HOME)).toBeNull();
  });

  // ssh_config keeps IdentityFile verbatim (`~/.ssh/work`), while keys_list
  // reports absolute paths — the two must still match.
  it("matches a ~-prefixed IdentityFile against the key's absolute path", () => {
    const keys = [
      key("id_ed25519", "/home/f/.ssh/id_ed25519.pub"),
      key("work", "/home/f/.ssh/work.pub"),
    ];
    expect(pickDefaultPublicKey(["~/.ssh/work"], keys, HOME)).toBe(
      "/home/f/.ssh/work.pub",
    );
  });

  it("does not let a ~-prefixed IdentityFile match a mere name suffix", () => {
    // `~/.ssh/work` must not match `/home/f/.ssh/notwork`.
    const keys = [key("notwork", "/home/f/.ssh/notwork.pub")];
    expect(pickDefaultPublicKey(["~/.ssh/work"], keys, HOME)).toBe(
      // Falls back to the only deployable key, NOT via the identity match.
      "/home/f/.ssh/notwork.pub",
    );
  });

  it("matches ~/.ssh IdentityFiles against Windows key paths in the home", () => {
    const win: KeyInfo = { ...key("id_win", "C:\\Users\\frank\\.ssh\\id_win.pub"), private_path: "C:\\Users\\frank\\.ssh\\id_win" };
    expect(pickDefaultPublicKey(["~/.ssh/id_win"], [win, key("other", "/home/f/.ssh/other.pub")], "C:\\Users\\frank")).toBe(
      "C:\\Users\\frank\\.ssh\\id_win.pub",
    );
  });

  it("does not take a key in another .ssh directory for the home's ~/.ssh key", () => {
    // `~/.ssh/id_win` is the key in the user's home, not a backup on another drive or in WSL.
    const elsewhere: KeyInfo[] = [
      { ...key("id_win", "D:\\backup\\.ssh\\id_win.pub"), private_path: "D:\\backup\\.ssh\\id_win" },
      { ...key("id_win", "\\\\wsl.localhost\\Ubuntu\\home\\me\\.ssh\\id_win.pub"), private_path: "\\\\wsl.localhost\\Ubuntu\\home\\me\\.ssh\\id_win" },
    ];
    expect(pickDefaultPublicKey(["~/.ssh/id_win"], elsewhere, "C:\\Users\\frank")).toBeNull();
  });

  it("matches a ~ IdentityFile only once the home directory is known", () => {
    const keys = [key("a", "/home/f/.ssh/a.pub"), key("work", "/home/f/.ssh/work.pub")];
    expect(pickDefaultPublicKey(["~/.ssh/work"], keys, null)).toBeNull();
    expect(pickDefaultPublicKey(["/home/f/.ssh/work"], keys, null)).toBe("/home/f/.ssh/work.pub");
  });
});
