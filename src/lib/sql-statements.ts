import { PostgreSQL } from "@codemirror/lang-sql";
import { MAX_RUN_ALL } from "@/lib/database-console";

export type StatementRange = { from: number; to: number; text: string };

type TreeNode = { name: string; firstChild: TreeNode | null; nextSibling: TreeNode | null };

const COMMENTS = new Set(["LineComment", "BlockComment"]);

/**
 * Splits a script into statements with the PostgreSQL grammar, so a semicolon inside a string, a
 * comment or a dollar-quoted body never ends one. Ranges are positions in `doc` plus `offset`.
 * A statement holding only comments is dropped.
 */
export function splitStatements(doc: string, offset = 0): StatementRange[] {
  const ranges: StatementRange[] = [];
  const cursor = PostgreSQL.language.parser.parse(doc).topNode.cursor();
  if (!cursor.firstChild()) return ranges;
  do {
    if (cursor.name !== "Statement") continue;
    if (!holdsCode(cursor.node)) continue;
    ranges.push({ from: cursor.from + offset, to: cursor.to + offset, text: doc.slice(cursor.from, cursor.to) });
  } while (cursor.nextSibling());
  return ranges;
}

function holdsCode(statement: TreeNode): boolean {
  for (let child = statement.firstChild; child; child = child.nextSibling) {
    if (!COMMENTS.has(child.name) && child.name !== ";") return true;
  }
  return false;
}

export const NO_STATEMENT = "Place the cursor in a statement.";
export const TOO_MANY_STATEMENTS = `Run all runs at most ${MAX_RUN_ALL} statements. Select fewer and run them.`;

/** The statements a Run or Run all would start, or the sentence saying why there are none. */
export function statementsToRun(
  doc: string,
  selection: { from: number; to: number },
  all: boolean,
): StatementRange[] | string {
  let found: StatementRange[];
  if (all) {
    found = splitStatements(doc);
  } else if (selection.from !== selection.to) {
    found = splitStatements(doc.slice(selection.from, selection.to), selection.from);
  } else {
    const at = statementAt(splitStatements(doc), doc, selection.from);
    found = at ? [at] : [];
  }
  if (found.length === 0) return NO_STATEMENT;
  if (found.length > MAX_RUN_ALL) return TOO_MANY_STATEMENTS;
  return found;
}

function statementAt(statements: StatementRange[], doc: string, cursor: number): StatementRange | null {
  const inside = statements.find((range) => range.from <= cursor && cursor <= range.to);
  if (inside) return inside;
  let before: StatementRange | null = null;
  for (const range of statements) {
    if (range.to <= cursor && !doc.slice(range.to, cursor).includes("\n")) before = range;
  }
  if (before) return before;
  return statements.find((range) => range.from > cursor && !doc.slice(cursor, range.to).includes("\n")) ?? null;
}
