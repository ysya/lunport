import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ExportFormat } from "@/bindings/ExportFormat";
import { PAGE_ROWS } from "@/lib/database-console";
import type { ResultTab } from "@/lib/database-console-session";
import { revealHidden } from "@/lib/reveal-hidden";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

type Rows = Extract<ConsoleRun, { kind: "rows" }>;
const count = (value: number) => value.toLocaleString("en-US");

/** What a result tab says beside its title. */
export function resultSummary(run: ConsoleRun | null): string {
  if (run === null) return "not run";
  switch (run.kind) {
    case "rows":
      return `${count(run.row_count)} rows · ${count(run.elapsed_ms)} ms`;
    case "done":
      return `${run.command_tag} · ${count(run.elapsed_ms)} ms`;
    case "failed":
      return "failed";
    case "canceled":
      return "canceled";
  }
}

function truncation(run: Rows): string | null {
  if (run.truncated === "rows") return `Lunport kept the first ${count(run.row_count)} rows.`;
  if (run.truncated === "bytes") return "Lunport kept the first 16 MiB.";
  return null;
}

function Grid({ run, page, offset }: { run: Rows; page: (string | null)[][]; offset: number }) {
  return <div className="console-grid">
    <table>
      <thead>
        <tr>
          <th className="console-row-number">#</th>
          {run.columns.map((column, index) => <th key={index} title={revealHidden(column.type_name)}>{revealHidden(column.name)}</th>)}
        </tr>
      </thead>
      <tbody>
        {page.map((row, rowIndex) => <tr key={offset + rowIndex}>
          <td className="console-row-number">{offset + rowIndex + 1}</td>
          {row.map((cell, index) => cell === null
            ? <td key={index}><span className="console-null">NULL</span></td>
            : cell === ""
              ? <td key={index} />
              : <td key={index} title={cell}><span className="console-cell">{cell}</span></td>)}
        </tr>)}
      </tbody>
    </table>
  </div>;
}

function Pager({ result, live, onPage, onExport }: {
  result: ResultTab & { run: Rows };
  live: boolean;
  onPage: (offset: number) => void;
  onExport: (format: ExportFormat) => void;
}) {
  const { run, offset, page } = result;
  const first = run.row_count === 0 ? 0 : offset + 1;
  const kept = truncation(run);
  return <div className="console-pager">
    <span>{`Rows ${count(first)}–${count(offset + page.length)} of ${count(run.row_count)}`}</span>
    {kept && <span>{kept}</span>}
    <span className="console-spacer" />
    <Button size="xs" variant="ghost" disabled={!live || offset === 0} onClick={() => onPage(Math.max(0, offset - PAGE_ROWS))}>
      <ChevronLeft aria-hidden="true" />Previous
    </Button>
    <Button size="xs" variant="ghost" disabled={!live || offset + PAGE_ROWS >= run.row_count} onClick={() => onPage(offset + PAGE_ROWS)}>
      Next<ChevronRight aria-hidden="true" />
    </Button>
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="xs" variant="ghost" disabled={!live}><Download aria-hidden="true" />Export</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {run.truncated && <DropdownMenuLabel className="font-normal text-muted-foreground">{`Exports the ${count(run.row_count)} rows Lunport kept.`}</DropdownMenuLabel>}
        <DropdownMenuItem onSelect={() => onExport("csv")}>CSV</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onExport("json")}>JSON</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  </div>;
}

/** What a result that has no rows says in its body. */
function outcome(run: ConsoleRun): string | null {
  switch (run.kind) {
    case "rows":
      return null;
    case "done":
      return `${run.command_tag} · ${count(run.elapsed_ms)} ms`;
    case "failed":
      return `${run.sqlstate ? `${run.sqlstate} ` : ""}${run.message}`;
    case "canceled":
      return "Canceled";
  }
}

/**
 * The results of the last Run: a tab for each statement, then Messages. A rows result shows one page of its rows, the pager and Export.
 * `live` is whether the session is open: pages and exports read rows the backend keeps, which go when the session does.
 */
export function ResultTabs({ results, messages, activeResult, live, onSelect, onPage, onExport }: {
  results: ResultTab[];
  messages: string[];
  activeResult: string | null;
  live: boolean;
  onSelect: (key: string) => void;
  onPage: (key: string, offset: number) => void;
  onExport: (result: ResultTab, index: number, format: ExportFormat) => void;
}) {
  if (results.length === 0 && messages.length === 0) return <section className="console-results" aria-label="Results" />;
  const index = results.findIndex((result) => result.key === activeResult);
  const active = index >= 0 ? results[index] : null;
  const run = active?.run ?? null;
  const said = run ? outcome(run) : null;
  return <section className="console-results" aria-label="Results">
    <div className="console-result-tabs" role="tablist" aria-label="Result sets">
      {results.map((result) => <button key={result.key} type="button" role="tab" aria-selected={result.key === activeResult} className="console-result-tab" onClick={() => onSelect(result.key)}>
        {result.title}<span className="console-result-summary">{resultSummary(result.run)}</span>
      </button>)}
      <button type="button" role="tab" aria-selected={activeResult === "messages"} className="console-result-tab" onClick={() => onSelect("messages")}>Messages</button>
    </div>
    {activeResult === "messages"
      ? <ul className="console-messages">{messages.map((line, lineIndex) => <li key={lineIndex}>{revealHidden(line)}</li>)}</ul>
      : run?.kind === "rows" && active
        ? <>
          <Grid run={run} page={active.page} offset={active.offset} />
          <Pager result={{ ...active, run }} live={live} onPage={(offset) => onPage(active.key, offset)} onExport={(format) => onExport(active, index, format)} />
        </>
        : <p className="console-outcome" data-kind={run?.kind}>{said ? revealHidden(said) : null}</p>}
  </section>;
}
