import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, X } from "lucide-react";
import { toast } from "sonner";
import type { ConsoleColumn } from "@/bindings/ConsoleColumn";
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/clipboard";
import { revealHidden } from "@/lib/reveal-hidden";

const CELL_CHARS = 2_000;
const JSON_FORMAT_CHARS = 65_536;

/** Keep the grid and field previews bounded without splitting a surrogate pair. */
export function cellText(value: string): string {
  if (value.length <= CELL_CHARS) return value;
  const last = value.charCodeAt(CELL_CHARS - 1);
  const end = last >= 0xd800 && last <= 0xdbff ? CELL_CHARS - 1 : CELL_CHARS;
  return value.slice(0, end) + "…";
}

/** Indent JSON tokens without coercing numbers or dropping duplicate object keys. */
export function formatJson(value: string): string {
  if (value.length > JSON_FORMAT_CHARS) return value;
  try {
    JSON.parse(value);
  } catch {
    return value;
  }
  const tokens = value.match(/"(?:[^"\\]|\\[\s\S])*"|[{}\[\],:]|[^"{}\[\],: \t\r\n]+/g) ?? [];
  let depth = 0;
  let previous = "";
  let formatted = "";
  for (const token of tokens) {
    const closing = token === "}" || token === "]";
    const afterOpening = previous === "{" || previous === "[";
    if (closing) depth--;
    const lineBreak = closing ? !afterOpening : afterOpening || previous === ",";
    if (lineBreak) {
      formatted += "\n" + "  ".repeat(Math.min(depth, 20));
    } else if (previous === ":") {
      formatted += " ";
    }
    formatted += token;
    if (token === "{" || token === "[") depth++;
    previous = token;
  }
  return formatted;
}

export function RecordDetails({ id, rowNumber, columns, row, onClose }: {
  id: string;
  rowNumber: number;
  columns: ConsoleColumn[];
  row: (string | null)[];
  onClose: () => void;
}) {
  const [expanded, setExpanded] = useState<{ row: number; column: number } | null>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => closeButton.current?.focus({ preventScroll: true }), []);
  const formatted = useMemo(() => columns.map((column, index) => {
    const value = row[index] ?? null;
    return value !== null && (column.type_name === "json" || column.type_name === "jsonb") ? formatJson(value) : value;
  }), [columns, row]);

  function copyValue(value: string) {
    void copyText(value).then(
      () => toast.success("Value copied"),
      () => toast.error("Could not copy value"),
    );
  }

  return <aside
    id={id}
    className="console-record-details"
    aria-label="Row details"
    onKeyDown={(event) => {
      if (event.key === "Escape" && !event.defaultPrevented) {
        event.stopPropagation();
        onClose();
      }
    }}
  >
    <div className="console-record-header">
      <h3>Row {rowNumber.toLocaleString("en-US")}</h3>
      <button ref={closeButton} type="button" className="console-icon-button" aria-label="Close row details" title="Close row details" onClick={onClose}>
        <X className="size-4" aria-hidden="true" />
      </button>
    </div>
    <dl className="console-record-fields">
      {columns.map((column, index) => {
        const name = revealHidden(column.name);
        const value = row[index] ?? null;
        const display = formatted[index];
        const full = expanded?.row === rowNumber && expanded.column === index;
        return <div key={index} className="console-record-field">
          <dt>
            <span className="console-record-name">{name}</span>
            <span className="console-record-type">{revealHidden(column.type_name)}</span>
            {value !== null && <button type="button" className="console-icon-button" aria-label={"Copy " + name} title="Copy value" onClick={() => copyValue(value)}>
              <Copy className="size-3.5" aria-hidden="true" />
            </button>}
          </dt>
          <dd>
            {display === null ? <span className="console-null">NULL</span>
              : display === "" ? <span className="console-null">Empty string</span>
                : <pre tabIndex={full ? 0 : undefined}>{full ? display : cellText(display)}</pre>}
            {display !== null && display.length > CELL_CHARS && <Button
              type="button"
              size="xs"
              variant="outline"
              aria-expanded={full}
              onClick={() => setExpanded(full ? null : { row: rowNumber, column: index })}
            >{full ? "Show less" : "Show full value"}</Button>}
          </dd>
        </div>;
      })}
    </dl>
  </aside>;
}
