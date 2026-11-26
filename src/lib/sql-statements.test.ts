import { describe, expect, it } from "vitest";
import { splitStatements, statementsToRun } from "./sql-statements";

const texts = (doc: string) => splitStatements(doc).map((range) => range.text);

describe("splitStatements", () => {
  it("splits on semicolons and keeps each terminator", () => {
    expect(texts("SELECT 1; SELECT 2;")).toEqual(["SELECT 1;", "SELECT 2;"]);
  });
  it("ignores a semicolon inside a string", () => {
    expect(texts("SELECT ';' AS a;")).toHaveLength(1);
  });
  it("ignores a semicolon inside an escape string", () => {
    expect(texts("SELECT E'it\\'s;';")).toHaveLength(1);
  });
  it("keeps a dollar-quoted body whole", () => {
    expect(texts("CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END $$ LANGUAGE plpgsql;")).toHaveLength(1);
    expect(texts("CREATE FUNCTION f() RETURNS int AS $body$ BEGIN RETURN 1; END $body$ LANGUAGE plpgsql;")).toHaveLength(1);
  });
  it("ignores a semicolon inside comments", () => {
    expect(texts("SELECT 1 -- a; b\n;")).toHaveLength(1);
    expect(texts("/* x; y */ SELECT 1;")).toHaveLength(1);
  });
  it("drops a trailing comment", () => {
    expect(texts("SELECT 1;\n-- trailing note\n")).toEqual(["SELECT 1;"]);
  });
  it("keeps a last statement that has no semicolon", () => {
    expect(texts("SELECT 1;\nSELECT 2")).toEqual(["SELECT 1;", "SELECT 2"]);
  });
  it("answers nothing for an empty or comment-only document", () => {
    expect(splitStatements("")).toEqual([]);
    expect(splitStatements("-- nothing here\n/* nor here */")).toEqual([]);
  });
  it("gives ranges in document positions, shifted by the offset", () => {
    const doc = "SELECT 1; SELECT 2;";
    expect(splitStatements(doc)[1]).toEqual({ from: 10, to: 19, text: "SELECT 2;" });
    expect(splitStatements(doc, 100)[1]).toEqual({ from: 110, to: 119, text: "SELECT 2;" });
  });
});

describe("statementsToRun", () => {
  const doc = "SELECT 1;\n\nSELECT 2;";
  const at = (cursor: number, all = false, to = cursor) => statementsToRun(doc, { from: cursor, to }, all);

  it("asks for a cursor in a statement when the cursor is on a blank line", () => {
    expect(at(10)).toBe("Place the cursor in a statement.");
  });
  it("runs the statement the cursor is inside", () => {
    expect(at(3)).toEqual([{ from: 0, to: 9, text: "SELECT 1;" }]);
  });
  it("runs the statement that ends right at the cursor", () => {
    expect(at(9)).toEqual([{ from: 0, to: 9, text: "SELECT 1;" }]);
  });
  it("runs the last statement that ends earlier on the cursor's line", () => {
    const spaced = "SELECT 1;   \nSELECT 2;";
    expect(statementsToRun(spaced, { from: 11, to: 11 }, false)).toEqual([{ from: 0, to: 9, text: "SELECT 1;" }]);
  });
  it("runs the statement that starts after the cursor on the same line", () => {
    expect(statementsToRun("  SELECT 1;", { from: 0, to: 0 }, false)).toEqual([{ from: 2, to: 11, text: "SELECT 1;" }]);
  });
  it("prefers the statement that ends at or before the cursor over one after it on the line", () => {
    const line = "SELECT 1;  SELECT 2;";
    expect(statementsToRun(line, { from: 10, to: 10 }, false)).toEqual([{ from: 0, to: 9, text: "SELECT 1;" }]);
  });
  it("runs both statements of a selection at their document offsets", () => {
    expect(at(0, false, doc.length)).toEqual([
      { from: 0, to: 9, text: "SELECT 1;" },
      { from: 11, to: 20, text: "SELECT 2;" },
    ]);
  });
  it("runs every statement for run all", () => {
    expect(at(10, true)).toHaveLength(2);
  });
  it("refuses run all past 50 statements", () => {
    const many = Array.from({ length: 51 }, (_, index) => `SELECT ${index};`).join("\n");
    expect(statementsToRun(many, { from: 0, to: 0 }, true)).toBe("Run all runs at most 50 statements. Select fewer and run them.");
  });
  it("accepts exactly 50 statements", () => {
    const fifty = Array.from({ length: 50 }, (_, index) => `SELECT ${index};`).join("\n");
    expect(statementsToRun(fifty, { from: 0, to: 0 }, true)).toHaveLength(50);
  });
});
