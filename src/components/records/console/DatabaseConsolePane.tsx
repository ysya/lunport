import "./database-console.css";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type MutableRefObject, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";
import type { EditorView } from "@codemirror/view";
import { Code, LoaderCircle, LockKeyhole, Play, Square } from "lucide-react";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { ExportFormat } from "@/bindings/ExportFormat";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import { Button } from "@/components/ui/button";
import { exportResult, PAGE_ROWS } from "@/lib/database-console";
import { ConsoleSession, type ConsoleState, type ResultTab, type TablePreview } from "@/lib/database-console-session";
import { databaseGrantLine, databasePamStatusQuery, databasesQuery, routeSummary, type SavedDatabase } from "@/lib/databases";
import { useRecordsStatus } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { statementsToRun } from "@/lib/sql-statements";
import { useNow } from "@/lib/use-now";
import { errorMessage } from "@/lib/utils";
import { useTerminalStore, type DatabaseTab, type TerminalState } from "@/stores/terminals";
import { ConsoleStatusBar, readOnlyLabel } from "./ConsoleStatusBar";
import { ResultTabs } from "./ResultTabs";
import { SchemaTree } from "./SchemaTree";
import { SqlEditor } from "./SqlEditor";

const LOCK_OFFER = "You can open it read-only without the lock: Lunport sets default_transaction_read_only, which a statement in the session could turn off.";

/** The tab state the workspace shows for each console status. */
const TAB_STATES: Record<ConsoleState["status"], TerminalState> = {
  opening: "connecting",
  open: "open",
  ended: "ended",
  error: "error",
  lock_unsupported: "error",
};

export type ConsoleActions = {
  run: (all: boolean) => void;
  browse: (schema: string, relation: string) => void;
  cancel: () => void;
  reconnect: () => void;
  openNotLocked: () => void;
  close: () => void;
  refreshSchema: () => void;
  showResult: (key: string) => void;
  showPage: (key: string, offset: number) => void;
  exportResult: (result: ResultTab, index: number, format: ExportFormat) => void;
};

function Banner({ state, actions }: { state: ConsoleState; actions: ConsoleActions }) {
  if (state.status === "lock_unsupported") {
    return <div className="console-banner" role="alert">
      {state.message && <p>{revealHidden(state.message)}</p>}
      <p>{LOCK_OFFER}</p>
      <div className="console-banner-actions">
        <Button size="sm" onClick={actions.openNotLocked}>Open read-only (not locked)</Button>
        <Button size="sm" variant="outline" onClick={actions.close}>Close</Button>
      </div>
    </div>;
  }
  if (state.status === "ended" || state.status === "error") {
    return <div className="console-banner" role="alert">
      {state.message && <p>{revealHidden(state.message)}</p>}
      <div className="console-banner-actions">
        <Button size="sm" onClick={actions.reconnect}>Reconnect</Button>
      </div>
    </div>;
  }
  return null;
}

function TableColumns({ tree, preview }: { tree: ConsoleState["schema"]; preview: TablePreview }) {
  const schema = tree?.schemas.find((schema) => schema.name === preview.schema);
  const relation = schema?.relations.find((relation) => relation.name === preview.relation);
  if (!relation) return <p className="console-outcome">Column metadata is unavailable.</p>;
  if (relation.columns.length === 0) return <p className="console-outcome">No columns.</p>;
  return <div className="console-grid console-preview-columns">
    <table aria-label="Table columns">
      <thead><tr><th scope="col">Column</th><th scope="col">Type</th><th scope="col">Key</th></tr></thead>
      <tbody>{relation.columns.map((column) => <tr key={column.name}>
        <td>{revealHidden(column.name)}</td>
        <td>{revealHidden(column.type_name)}</td>
        <td>{column.primary_key ? "Primary key" : ""}</td>
      </tr>)}</tbody>
    </table>
  </div>;
}

/** The console keeps the editor mounted when browsing data or reconnecting. */
export function ConsoleView({ tab, state, mac, notice, viewRef, statusBar, actions }: {
  tab: DatabaseTab;
  state: ConsoleState;
  /** Whether the keys read as macOS keys. */
  mac: boolean;
  /** Why the last Run or Export did nothing. */
  notice: string | null;
  viewRef: MutableRefObject<EditorView | null>;
  statusBar: ReactNode;
  actions: ConsoleActions;
}) {
  const [showSqlEditor, setShowSqlEditor] = useState(false);
  const [previewPane, setPreviewPane] = useState<"data" | "columns">("data");
  const open = state.status === "open";
  const canRun = open && !state.running;
  const mode = state.opened?.read_only ?? tab.readOnly;
  const preview = state.preview;
  const editorVisible = !preview || showSqlEditor;
  const previewName = preview ? revealHidden(preview.schema + "." + preview.relation) : null;

  useEffect(() => {
    if (!editorVisible) return;
    viewRef.current?.requestMeasure();
    if (showSqlEditor) viewRef.current?.focus();
  }, [editorVisible, showSqlEditor, viewRef]);

  function browse(schema: string, relation: string) {
    setShowSqlEditor(false);
    setPreviewPane("data");
    actions.browse(schema, relation);
  }

  return <div className="console-pane">
    <div className="console-body">
      <SchemaTree
        tree={state.schema}
        error={state.schemaError}
        canRefresh={open}
        onRefresh={actions.refreshSchema}
        canBrowse={canRun}
        onBrowse={browse}
        preview={preview}
      />
      <section className="console-main" aria-label="Query">
        <div className="console-toolbar">
          {preview && <Button size="sm" variant="outline" aria-expanded={editorVisible} onClick={() => setShowSqlEditor(!editorVisible)}>
            <Code className="size-3.5" aria-hidden="true" />SQL editor
          </Button>}
          {editorVisible && <>
            <Button size="sm" disabled={!canRun} onClick={() => actions.run(false)}>
              <Play className="size-3" aria-hidden="true" />Run<kbd>{mac ? "⌘↩" : "Ctrl+↩"}</kbd>
            </Button>
            <Button size="sm" variant="outline" disabled={!canRun} onClick={() => actions.run(true)}>
              Run all<kbd>{mac ? "⇧⌘↩" : "Shift+Ctrl+↩"}</kbd>
            </Button>
          </>}
          {(editorVisible || state.running) && <Button size="sm" variant="outline" disabled={!state.running} onClick={actions.cancel}>
            <Square className="size-3" aria-hidden="true" />Cancel
          </Button>}
          {(state.status === "opening" || state.running) && <LoaderCircle className="size-4 text-muted-foreground motion-safe:animate-spin" aria-label={state.running ? "Running" : "Connecting"} />}
          {notice && <span className="console-notice" role="status">{revealHidden(notice)}</span>}
          <span className="console-spacer" />
          <span className="console-read-only" data-mode={mode}><LockKeyhole className="size-3" aria-hidden="true" />{readOnlyLabel(mode)}</span>
        </div>
        <Banner state={state} actions={actions} />
        <SqlEditor viewRef={viewRef} schema={state.schema} hidden={!editorVisible} running={state.running} onRun={actions.run} onCancel={actions.cancel} />
        {previewName !== null && <div className="console-preview-header">
          <h2 className="console-preview-title" title={previewName}>{previewName}</h2>
          <div className="console-preview-views" role="group" aria-label="Table view">
            <Button size="sm" variant={previewPane === "data" ? "secondary" : "ghost"} aria-pressed={previewPane === "data"} onClick={() => setPreviewPane("data")}>Data</Button>
            <Button size="sm" variant={previewPane === "columns" ? "secondary" : "ghost"} aria-pressed={previewPane === "columns"} onClick={() => setPreviewPane("columns")}>Columns</Button>
          </div>
          {previewPane === "data" && <span className="console-preview-limit">Preview · up to {PAGE_ROWS} rows</span>}
        </div>}
        {preview && previewPane === "columns" ? <TableColumns tree={state.schema} preview={preview} /> : <ResultTabs
          results={state.results}
          messages={state.messages}
          activeResult={state.activeResult}
          live={open}
          preview={preview !== null}
          busy={state.running}
          onSelect={actions.showResult}
          onPage={actions.showPage}
          onExport={actions.exportResult}
        />}
      </section>
    </div>
    {statusBar}
  </div>;
}

/** The status bar with what the library knows of the database: its route, and its grant when it has a grant check. */
function ConsoleFooter({ environment, database, iamUser, readOnly }: {
  environment: DatabaseEnvironment;
  database: SavedDatabase | null;
  iamUser: string | null;
  readOnly: ReadOnlyMode;
}) {
  const overview = useRecordsStatus().data?.overview ?? null;
  const pam = database?.pam ?? null;
  const read = useQuery({ ...databasePamStatusQuery(database?.id ?? ""), enabled: pam !== null });
  const now = useNow(1000);
  const route = database && overview ? routeSummary(overview, database) : { alias: null, iap: false };
  const grant = pam && read.data && !read.isError ? databaseGrantLine(read.data, pam, now) : null;
  return <ConsoleStatusBar environment={environment} database={database} route={route} iamUser={iamUser} readOnly={readOnly} grant={grant} />;
}

/**
 * The console of a database tab. It holds one session for the tab, opened when the pane mounts and closed when it unmounts, and keeps
 * the tab's state in the workspace in step with the session's.
 */
export function DatabaseConsolePane({ tab, active }: { tab: DatabaseTab; active: boolean }) {
  const [session] = useState(() => new ConsoleSession(tab.id, tab.databaseId));
  const subscribe = useCallback((listener: () => void) => session.subscribe(listener), [session]);
  const state = useSyncExternalStore(subscribe, () => session.state);
  const viewRef = useRef<EditorView | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform);
  const database = useQuery({ ...databasesQuery, select: (rows) => rows.find((row) => row.database.id === tab.databaseId)?.database ?? null }).data ?? null;

  // The close waits a turn: StrictMode unmounts and mounts a pane again at once, and that mount keeps the session it already opened
  // rather than closing it and opening the same tab id a second time.
  const firstReadOnly = useRef(tab.readOnly);
  const closing = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (closing.current !== null) {
      clearTimeout(closing.current);
      closing.current = null;
    } else {
      void session.open(firstReadOnly.current);
    }
    return () => {
      closing.current = setTimeout(() => {
        closing.current = null;
        void session.close();
      });
    };
  }, [session]);

  useEffect(() => {
    useTerminalStore.getState().updateState(tab.id, TAB_STATES[state.status]);
  }, [tab.id, state.status]);

  useEffect(() => {
    if (!active) return;
    viewRef.current?.requestMeasure();
    viewRef.current?.focus();
  }, [active]);

  useEffect(() => {
    if (!active || !state.preview || !state.running) return;
    const cancelPreview = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented || event.repeat || event.isComposing || viewRef.current?.hasFocus) return;
      if (event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"], [role="menu"]')) return;
      event.preventDefault();
      void session.cancel();
    };
    window.addEventListener("keydown", cancelPreview);
    return () => window.removeEventListener("keydown", cancelPreview);
  }, [active, session, state.preview, state.running]);

  // A statement that failed at a position puts the cursor there, once.
  const placed = useRef(new Set<string>());
  useEffect(() => {
    const view = viewRef.current;
    if (!view || state.preview) return;
    for (const result of state.results) {
      if (result.run?.kind !== "failed" || result.run.position === null || placed.current.has(result.key)) continue;
      placed.current.add(result.key);
      const at = Math.min(Math.max(0, result.statement.from + result.run.position - 1), view.state.doc.length);
      view.dispatch({ selection: { anchor: at }, scrollIntoView: true });
      view.focus();
    }
  }, [state.preview, state.results]);

  const exportTo = async (result: ResultTab, index: number, format: ExportFormat) => {
    if (result.run?.kind !== "rows") return;
    const resultId = result.run.result_id;
    try {
      // A name holding a path separator would make the default a path into another folder.
      const name = (database?.name ?? tab.name).replace(/[/\\:]/g, "-");
      const path = await save({ defaultPath: `${name}-result-${index + 1}.${format}`, filters: [{ name: format.toUpperCase(), extensions: [format] }] });
      if (!path) return;
      await exportResult(tab.id, resultId, format, path);
      setNotice(null);
    } catch (error) {
      setNotice(errorMessage(error));
    }
  };

  const actions: ConsoleActions = {
    run: (all) => {
      const view = viewRef.current;
      const current = session.state;
      if (!view || current.status !== "open" || current.running) return;
      const found = statementsToRun(view.state.doc.toString(), view.state.selection.main, all);
      if (typeof found === "string") {
        setNotice(found);
        return;
      }
      setNotice(null);
      void session.run(found);
    },
    browse: (schema, relation) => {
      setNotice(null);
      void session.browse(schema, relation);
    },
    cancel: () => void session.cancel(),
    reconnect: () => {
      setNotice(null);
      void session.reconnect();
    },
    openNotLocked: () => {
      useTerminalStore.getState().setReadOnly(tab.id, "not_locked");
      void session.open("not_locked");
    },
    close: () => useTerminalStore.getState().close(tab.id),
    refreshSchema: () => void session.refreshSchema(),
    showResult: (key) => session.showResult(key),
    showPage: (key, offset) => void session.showPage(key, offset),
    exportResult: (result, index, format) => void exportTo(result, index, format),
  };

  const mode = state.opened?.read_only ?? tab.readOnly;
  return <ConsoleView
    tab={tab}
    state={state}
    mac={mac}
    notice={notice}
    viewRef={viewRef}
    actions={actions}
    statusBar={<ConsoleFooter environment={tab.environment} database={database} iamUser={state.opened?.iam_user ?? null} readOnly={mode} />}
  />;
}

export default DatabaseConsolePane;
