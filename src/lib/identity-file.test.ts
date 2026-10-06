import { describe, expect, it } from "vitest";
import { identityFileAction, identityPointsAt, toTildeSshPath } from "./identity-file";

const MAC_HOME = "/Users/frank";
const WIN_HOME = "C:\\Users\\frank";

describe("toTildeSshPath", () => {
  it("rewrites paths inside the home's .ssh directory to the ~ form", () => {
    expect(toTildeSshPath("/home/f/.ssh/work", "/home/f")).toBe("~/.ssh/work");
    expect(toTildeSshPath("/Users/frank/.ssh/sub/key", MAC_HOME)).toBe("~/.ssh/sub/key");
    expect(toTildeSshPath("/Users/frank/.ssh/key", "/Users/frank/")).toBe("~/.ssh/key");
  });

  it("leaves paths outside the home's .ssh untouched", () => {
    expect(toTildeSshPath("/opt/keys/deploy", MAC_HOME)).toBe("/opt/keys/deploy");
    expect(toTildeSshPath("relative/path", MAC_HOME)).toBe("relative/path");
    // Another disk's .ssh is not this user's ~/.ssh.
    expect(toTildeSshPath("/Volumes/Backup/.ssh/id", MAC_HOME)).toBe("/Volumes/Backup/.ssh/id");
    // A sibling of the home, or a directory that only starts like .ssh.
    expect(toTildeSshPath("/Users/frankie/.ssh/id", MAC_HOME)).toBe("/Users/frankie/.ssh/id");
    expect(toTildeSshPath("/Users/frank/.sshx/id", MAC_HOME)).toBe("/Users/frank/.sshx/id");
    // Unix paths keep their case: another spelling is left as given.
    expect(toTildeSshPath("/users/frank/.ssh/id", MAC_HOME)).toBe("/users/frank/.ssh/id");
  });

  it("writes Windows paths inside the home's .ssh in the portable ~/.ssh/ form, whatever the separator or case", () => {
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\id_win", WIN_HOME)).toBe("~/.ssh/id_win");
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\sub\\key", WIN_HOME)).toBe("~/.ssh/sub/key");
    expect(toTildeSshPath("C:/Users/frank/.ssh/id_win", WIN_HOME)).toBe("~/.ssh/id_win");
    expect(toTildeSshPath("c:\\users\\FRANK\\.SSH\\id_win", WIN_HOME)).toBe("~/.ssh/id_win");
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\sshelter\\keys\\id_mac-3fa2c1d9", WIN_HOME)).toBe("~/.ssh/sshelter/keys/id_mac-3fa2c1d9");
  });

  it("keeps Windows paths outside the home's .ssh as given: another drive, a WSL or network share", () => {
    expect(toTildeSshPath("D:\\keys\\deploy", WIN_HOME)).toBe("D:\\keys\\deploy");
    expect(toTildeSshPath("D:\\backup\\.ssh\\x", WIN_HOME)).toBe("D:\\backup\\.ssh\\x");
    expect(toTildeSshPath("\\\\wsl.localhost\\Ubuntu\\home\\me\\.ssh\\id_ed25519", WIN_HOME)).toBe("\\\\wsl.localhost\\Ubuntu\\home\\me\\.ssh\\id_ed25519");
    expect(toTildeSshPath("\\\\server\\share\\.ssh\\id", WIN_HOME)).toBe("\\\\server\\share\\.ssh\\id");
  });

  it("writes every path as given while the home directory is not known", () => {
    expect(toTildeSshPath("/home/f/.ssh/work", null)).toBe("/home/f/.ssh/work");
    expect(toTildeSshPath("C:\\Users\\frank\\.ssh\\id_win", null)).toBe("C:\\Users\\frank\\.ssh\\id_win");
  });

  it("leaves ~/.ssh values exactly as they are, so a slot value stays a slot value", () => {
    for (const home of [MAC_HOME, WIN_HOME, null]) {
      expect(toTildeSshPath("~/.ssh/sshelter/keys/id_mac-3fa2c1d9", home)).toBe("~/.ssh/sshelter/keys/id_mac-3fa2c1d9");
      expect(toTildeSshPath("~/.ssh/work", home)).toBe("~/.ssh/work");
    }
    const once = toTildeSshPath("C:\\Users\\frank\\.ssh\\id_win", WIN_HOME);
    expect(toTildeSshPath(once, WIN_HOME)).toBe(once);
  });
});

describe("identityPointsAt", () => {
  it("expands ~ to the home only, never to any .ssh directory", () => {
    expect(identityPointsAt("~/.ssh/id_win", "C:\\Users\\frank\\.ssh\\id_win", WIN_HOME)).toBe(true);
    expect(identityPointsAt("~/.ssh/id_win", "D:\\backup\\.ssh\\id_win", WIN_HOME)).toBe(false);
    expect(identityPointsAt("~/.ssh/id_ed25519", "\\\\wsl.localhost\\Ubuntu\\home\\me\\.ssh\\id_ed25519", WIN_HOME)).toBe(false);
    expect(identityPointsAt("~/.ssh/id", "/Volumes/Backup/.ssh/id", MAC_HOME)).toBe(false);
    expect(identityPointsAt("~/.ssh/id", "/Users/frank/.ssh/id", MAC_HOME)).toBe(true);
  });

  it("compares separators loosely, case only on Windows, and reads quoted and %d values", () => {
    expect(identityPointsAt("~\\.ssh\\id_win", "C:/Users/frank/.ssh/id_win", WIN_HOME)).toBe(true);
    expect(identityPointsAt("~/.ssh/ID_WIN", "C:\\Users\\frank\\.ssh\\id_win", WIN_HOME)).toBe(true);
    expect(identityPointsAt("~/.ssh/ID", "/Users/frank/.ssh/id", MAC_HOME)).toBe(false);
    expect(identityPointsAt("\"~/.ssh/my key\"", "/Users/frank/.ssh/my key", MAC_HOME)).toBe(true);
    expect(identityPointsAt("%d/.ssh/id", "/Users/frank/.ssh/id", MAC_HOME)).toBe(true);
    expect(identityPointsAt("C:\\Users\\frank\\.ssh\\id_win", "c:/users/frank/.ssh/id_win", WIN_HOME)).toBe(true);
  });

  it("matches only the same absolute path while the home directory is not known", () => {
    expect(identityPointsAt("/home/f/.ssh/work", "/home/f/.ssh/work", null)).toBe(true);
    expect(identityPointsAt("~/.ssh/work", "/home/f/.ssh/work", null)).toBe(false);
  });
});

describe("identityFileAction", () => {
  const deployed = "/home/f/.ssh/work";
  const home = "/home/f";

  it("writes when the host has no IdentityFile at all", () => {
    expect(identityFileAction([], deployed, home)).toBe("write");
  });

  it("recognizes an absolute entry pointing at the deployed key", () => {
    expect(identityFileAction(["/home/f/.ssh/work"], deployed, home)).toBe("already");
  });

  it("recognizes a ~-prefixed entry pointing at the deployed key", () => {
    expect(identityFileAction(["~/.ssh/work"], deployed, home)).toBe("already");
  });

  it("offers (never auto-replaces) when a different IdentityFile exists", () => {
    expect(identityFileAction(["~/.ssh/other"], deployed, home)).toBe("offer");
  });

  it("does not let a suffix match a longer key name", () => {
    // `~/.ssh/work` must not be treated as pointing at `/home/f/.ssh/notwork`.
    expect(identityFileAction(["~/.ssh/work"], "/home/f/.ssh/notwork", home)).toBe("offer");
  });

  it("is already when ANY of several entries matches the deployed key", () => {
    expect(identityFileAction(["~/.ssh/other", "~/.ssh/work"], deployed, home)).toBe("already");
  });

  it("matches a ~/.ssh entry against a Windows path in the home, but not one on another drive", () => {
    expect(identityFileAction(["~/.ssh/id_win"], "C:\\Users\\frank\\.ssh\\id_win", WIN_HOME)).toBe("already");
    expect(identityFileAction(["~/.ssh/id_win"], "D:\\backup\\.ssh\\id_win", WIN_HOME)).toBe("offer");
  });

  it("offers rather than claims a match while the home directory is not known", () => {
    expect(identityFileAction(["~/.ssh/work"], deployed, null)).toBe("offer");
  });
});
