import { useId, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ExportFormat } from "@/bindings/ExportFormat";
import { PAGE_ROWS } from "@/lib/database-console";
import type { ResultTab } from "@/lib/database-console-session";
import { revealHidden } from "@/lib/reveal-hidden";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { cellText, RecordDetails } from "./RecordDetails";

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
  if (run.truncated === "bytes") {
    return run.row_count === 0
      ? "Lunport kept no rows: this result does not fit in its memory limit."
      : `Lunport kept the first ${count(run.row_count)} rows, as many as fit in its memory limit.`;
  }
  return null;
}

function Cell({ value }: { value: string }) {
  const shown = cellText(value);
  return <td title={shown}><span className="console-cell">{shown}</span></td>;
}

function Grid({ run, page, offset }: { run: Rows; page: (string | null)[][]; offset: number }) {
  const [selectedRow, setSelectedRow] = useState<number | null>(null);
  const selectedButton = useRef<HTMLButtonElement>(null);
  const id = useId();
  const record = selectedRow === null ? null : page[selectedRow];
  function closeDetails() {
    selectedButton.current?.focus();
    setSelectedRow(null);
  }

  return <div className="console-result-content">
    <div className="console-grid">
      <table>
        <thead>
          <tr>
            <th className="console-row-number">#</th>
            {run.columns.map((column, index) => <th key={index} scope="col" title={revealHidden(column.type_name)}>{revealHidden(column.name)}</th>)}
          </tr>
        </thead>
        <tbody>
          {page.map((row, rowIndex) => {
            const rowNumber = offset + rowIndex + 1;
            const selected = rowIndex === selectedRow;
            return <tr key={rowNumber} data-selected={selected} onClick={(event) => {
              // Dragging across cells to select text should keep the grid in place.
              const selection = event.currentTarget.ownerDocument.getSelection();
              if (event.detail !== 0 && selection && !selection.isCollapsed && event.currentTarget.contains(selection.anchorNode)) return;
              setSelectedRow(rowIndex);
            }}>
              <td className="console-row-number">
                <button
                  type="button"
                  className="console-row-detail-button"
                  aria-label={"Inspect row " + rowNumber}
                  title="Inspect row"
                  aria-expanded={selected}
                  aria-controls={selected ? id : undefined}
                  ref={selected ? selectedButton : undefined}
                >{rowNumber}</button>
              </td>
              {row.map((cell, index) => cell === null
                ? <td key={index}><span className="console-null">NULL</span></td>
                : cell === ""
                  ? <td key={index} />
                  : <Cell key={index} value={cell} />)}
            </tr>;
          })}
        </tbody>
      </table>
    </div>
    {selectedRow !== null && record && <RecordDetails
      key={selectedRow}
      id={id}
      rowNumber={offset + selectedRow + 1}
      columns={run.columns}
      row={record}
      onClose={closeDetails}
    />}
  </div>;
}

function Pager({ result, live, preview, onPage, onExport }: {
  result: ResultTab & { run: Rows };
  live: boolean;
  preview: boolean;
  onPage: (offset: number) => void;
  onExport: (format: ExportFormat) => void;
}) {
  const { run, offset, page } = result;
  const first = run.row_count === 0 ? 0 : offset + 1;
  const kept = truncation(run);
  return <div className="console-pager">
    <span>{preview ? `${count(run.row_count)} ${run.row_count === 1 ? "row" : "rows"} in preview` : `Rows ${count(first)}–${count(offset + page.length)} of ${count(run.row_count)}`}</span>
    {kept && <span>{kept}</span>}
    <span className="console-spacer" />
    {!preview && <>
      <Button size="xs" variant="ghost" disabled={!live || offset === 0} onClick={() => onPage(Math.max(0, offset - PAGE_ROWS))}>
        <ChevronLeft aria-hidden="true" />Previous
      </Button>
      <Button size="xs" variant="ghost" disabled={!live || offset + PAGE_ROWS >= run.row_count} onClick={() => onPage(offset + PAGE_ROWS)}>
        Next<ChevronRight aria-hidden="true" />
      </Button>
    </>}
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
export function ResultTabs({ results, messages, activeResult, live, preview = false, busy = false, onSelect, onPage, onExport }: {
  results: ResultTab[];
  messages: string[];
  activeResult: string | null;
  live: boolean;
  preview?: boolean;
  busy?: boolean;
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
    {(!preview || messages.length > 0) && <div className="console-result-tabs" role="tablist" aria-label="Result sets">
      {results.map((result) => <button key={result.key} type="button" role="tab" aria-selected={result.key === activeResult} className="console-result-tab" onClick={() => onSelect(result.key)}>
        {result.title}<span className="console-result-summary">{resultSummary(result.run)}</span>
      </button>)}
      <button type="button" role="tab" aria-selected={activeResult === "messages"} className="console-result-tab" onClick={() => onSelect("messages")}>Messages</button>
    </div>}
    {activeResult === "messages"
      ? <ul className="console-messages">{messages.map((line, lineIndex) => <li key={lineIndex}>{revealHidden(line)}</li>)}</ul>
      : run?.kind === "rows" && active
        ? <>
          {run.row_count === 0 && run.truncated === null && <p className="console-outcome">No rows.</p>}
          <Grid key={active.key + ":" + active.offset} run={run} page={active.page} offset={active.offset} />
          <Pager result={{ ...active, run }} live={live} preview={preview} onPage={(offset) => onPage(active.key, offset)} onExport={(format) => onExport(active, index, format)} />
        </>
        : <p className="console-outcome" data-kind={run?.kind}>{said ? revealHidden(said) : preview && busy ? "Loading rows…" : null}</p>}
  </section>;
}
