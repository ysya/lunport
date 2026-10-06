import { describe, expect, it } from "vitest";
import { identityFileAction, toTildeSshPath } from "./identity-file";

describe("toTildeSshPath", () => {
  it("rewrites paths under a .ssh directory to the ~ form", () => {
    expect(toTildeSshPath("/home/f/.ssh/work")).toBe("~/.ssh/work");
    expect(toTildeSshPath("/Users/frank/.ssh/sub/key")).toBe("~/.ssh/sub/key");
  });

  it("leaves paths outside .ssh untouched", () => {
    expect(toTildeSshPath("/opt/keys/deploy")).toBe("/opt/keys/deploy");
    expect(toTildeSshPath("relative/path")).toBe("relative/path");
  });

  it("writes Windows paths under .ssh in the portable ~/.ssh/ form", () => {
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\id_win")).toBe("~/.ssh/id_win");
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\sub\\key")).toBe("~/.ssh/sub/key");
    expect(toTildeSshPath("D:\\keys\\deploy")).toBe("D:\\keys\\deploy");
  });
});

describe("identityFileAction", () => {
  const deployed = "/home/f/.ssh/work";

  it("writes when the host has no IdentityFile at all", () => {
    expect(identityFileAction([], deployed)).toBe("write");
  });

  it("recognizes an absolute entry pointing at the deployed key", () => {
    expect(identityFileAction(["/home/f/.ssh/work"], deployed)).toBe("already");
  });

  it("recognizes a ~-prefixed entry pointing at the deployed key", () => {
    expect(identityFileAction(["~/.ssh/work"], deployed)).toBe("already");
  });

  it("offers (never auto-replaces) when a different IdentityFile exists", () => {
    expect(identityFileAction(["~/.ssh/other"], deployed)).toBe("offer");
  });

  it("does not let a suffix match a longer key name", () => {
    // `~/.ssh/work` must not be treated as pointing at `/home/f/.ssh/notwork`.
    expect(identityFileAction(["~/.ssh/work"], "/home/f/.ssh/notwork")).toBe(
      "offer",
    );
  });

  it("is already when ANY of several entries matches the deployed key", () => {
    expect(identityFileAction(["~/.ssh/other", "~/.ssh/work"], deployed)).toBe(
      "already",
    );
  });

  it("matches a ~/.ssh entry against a Windows path", () => {
    expect(identityFileAction(["~/.ssh/id_win"], "C:\\Users\\frank\\.ssh\\id_win")).toBe("already");
  });
});
