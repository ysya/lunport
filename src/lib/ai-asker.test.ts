import { describe, expect, it } from "vitest";
import { unreviewedNote } from "./ai-asker";

describe("Auto-log transfer notice", () => {
  it("names the file transfer after native authentication", () => {
    expect(unreviewedNote({ client: "Codex", unreviewed: "transfer" }, "question"))
      .toBe("Auto-log is on: once you answer, the AI client’s file transfer starts right away, without review.");
  });
});
