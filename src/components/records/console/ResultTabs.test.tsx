import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ResultTab } from "@/lib/database-console-session";
import { DISABLED, buttonTag, text } from "@/components/keychain/test-markup";
import { ResultTabs, cellText } from "./ResultTabs";

type Rows = Extract<ConsoleRun, { kind: "rows" }>;
const statement = { from: 0, to: 21, text: "SELECT * FROM orders;" };
const page = (count: number, offset = 0) => Array.from({ length: count }, (_, index) => [String(offset + index + 1), "pending"]);
const rows = (patch: Partial<Rows> = {}): Rows => ({
  kind: "rows",
  result_id: 1,
  columns: [
    { name: "id", type_name: "int8" },
    { name: "status", type_name: "text" },
  ],
  row_count: 450,
  truncated: null,
  elapsed_ms: 84,
  first_page: page(200),
  ...patch,
});
const result = (index: number, run: ConsoleRun | null, offset = 0): ResultTab => ({
  key: `run-1-${index}`,
  title: `Result ${index}`,
  statement,
  run,
  page: run?.kind === "rows" ? run.first_page : [],
  offset,
});

function render(results: ResultTab[], { messages = [] as string[], active = results[0]?.key ?? null, live = true } = {}) {
  return renderToStaticMarkup(
    <ResultTabs results={results} messages={messages} activeResult={active} live={live} onSelect={vi.fn()} onPage={vi.fn()} onExport={vi.fn()} />,
  );
}

describe("ResultTabs", () => {
  it("a_page_of_a_longer_result_says_which_rows_it_shows", () => {
    const html = render([result(1, rows())]);
    expect(text(html)).toContain("Rows 1–200 of 450");
    expect(text(html)).toContain("Result 1 450 rows · 84 ms");
    expect(buttonTag(html, "Previous")).toContain(DISABLED);
    expect(buttonTag(html, "Next")).not.toContain(DISABLED);
  });

  it("a_later_page_counts_from_its_offset", () => {
    const later = { ...result(1, rows()), page: page(50, 400), offset: 400 };
    const html = render([later]);
    expect(text(html)).toContain("Rows 401–450 of 450");
    expect(buttonTag(html, "Next")).toContain(DISABLED);
    expect(html).toContain('<td title="401"><span class="console-cell">401</span></td>');
  });

  it("the_grid_numbers_rows_and_names_column_types", () => {
    const html = render([result(1, rows())]);
    expect(html).toMatch(/<th[^>]*>#<\/th>/);
    expect(html).toContain('title="int8"');
    expect(html).toContain('title="text"');
  });

  it("null_is_a_muted_null_and_an_empty_string_an_empty_cell", () => {
    const html = render([result(1, rows({ row_count: 2, first_page: [["1", null], ["2", ""]] }))]);
    expect(html).toContain('<td><span class="console-null">NULL</span></td>');
    expect(html).toContain("<td></td>");
    expect(html).toContain('<td title="1"><span class="console-cell">1</span></td>');
  });

  it("a_result_cut_at_the_row_limit_says_so", () => {
    const html = render([result(1, rows({ row_count: 10_000, truncated: "rows" }))]);
    expect(text(html)).toContain("Rows 1–200 of 10,000");
    expect(text(html)).toContain("Lunport kept the first 10,000 rows.");
  });

  it("a_result_cut_at_the_byte_limit_says_how_many_rows_it_kept", () => {
    const html = render([result(1, rows({ row_count: 1_234, truncated: "bytes" }))]);
    expect(text(html)).toContain("Rows 1–200 of 1,234");
    expect(text(html)).toContain("Lunport kept the first 1,234 rows, as many as fit in its memory limit.");
    expect(text(html)).not.toContain("16 MiB");
  });

  it("a_result_with_no_row_that_fits_the_byte_limit_says_none_was_kept", () => {
    const html = render([result(1, rows({ row_count: 0, truncated: "bytes", first_page: [] }))]);
    expect(text(html)).toContain("Rows 0–0 of 0");
    expect(text(html)).toContain("Lunport kept no rows: this result does not fit in its memory limit.");
  });

  it("a_long_value_draws_its_first_2000_characters", () => {
    const long = "a".repeat(5_000);
    const html = render([result(1, rows({ row_count: 1, first_page: [["1", long]] }))]);
    const shown = `${"a".repeat(2_000)}…`;
    expect(html).toContain(`<td title="${shown}"><span class="console-cell">${shown}</span></td>`);
    expect(html).not.toContain("a".repeat(2_001));
  });

  it("a_cut_value_never_ends_between_the_halves_of_a_character", () => {
    expect(cellText(`${"a".repeat(1_999)}😀b`)).toBe(`${"a".repeat(1_999)}…`);
    expect(cellText("a".repeat(2_000))).toBe("a".repeat(2_000));
  });

  it("a_statement_not_run_yet_says_so", () => {
    const html = render([result(1, rows()), result(2, null)]);
    expect(text(html)).toContain("Result 2 not run");
    expect(text(html)).toContain("Messages");
  });

  it("failed_and_canceled_statements_say_so", () => {
    const failed: ConsoleRun = { kind: "failed", message: 'relation "nope" does not exist', sqlstate: "42P01", position: 15, elapsed_ms: 2 };
    const canceled: ConsoleRun = { kind: "canceled", elapsed_ms: 3 };
    const html = render([result(1, failed), result(2, canceled)]);
    expect(text(html)).toContain("Result 1 failed");
    expect(text(html)).toContain("Result 2 canceled");
    expect(text(html)).toContain('42P01 relation "nope" does not exist');
  });

  it("a_failed_statement_shows_its_sqlstate_line_in_messages", () => {
    const failed: ConsoleRun = { kind: "failed", message: 'relation "nope" does not exist', sqlstate: "42P01", position: 15, elapsed_ms: 2 };
    const line = 'Result 2 · 42P01 relation "nope" does not exist';
    const html = render([result(1, rows()), result(2, failed)], { messages: [line], active: "messages" });
    expect(text(html)).toContain(line);
    expect(text(html)).not.toContain("Rows 1–200");
  });

  it("pages_and_export_wait_for_an_open_session", () => {
    const html = render([result(1, rows())], { live: false });
    expect(buttonTag(html, "Next")).toContain(DISABLED);
    expect(buttonTag(html, "Export")).toContain(DISABLED);
  });
});
