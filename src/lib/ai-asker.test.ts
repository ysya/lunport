import { describe, expect, it } from "vitest";
import { unreviewedNote } from "./ai-asker";

describe("Auto-log database notice", () => {
  it("names a direct query instead of a database port start", () => {
    expect(unreviewedNote({ client: "Codex", unreviewed: "database_query" }, "grant"))
      .toBe("Auto-log is on: once the grant is active, the AI client's read-only database query runs without per-query review.");
  });
  it("names the database in every window the person agrees in", () => {
    const ai = { client: "Codex", unreviewed: "database" } as const;
    expect(unreviewedNote(ai, "hostkey"))
      .toBe("Auto-log is on: once you trust this key, the database the AI client asked for starts right away, without review.");
    expect(unreviewedNote(ai, "grant"))
      .toBe("Auto-log is on: once the grant is active, the database the AI client asked for starts right away, without review.");
    expect(unreviewedNote(ai, "question"))
      .toBe("Auto-log is on: once you answer, the database the AI client asked for starts right away, without review.");
  });
});

describe("Auto-log transfer notice", () => {
  it("names the file transfer after native authentication", () => {
    expect(unreviewedNote({ client: "Codex", unreviewed: "transfer" }, "question"))
      .toBe("Auto-log is on: once you answer, the AI client’s file transfer starts right away, without review.");
  });
});
