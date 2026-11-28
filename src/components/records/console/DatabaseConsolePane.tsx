import "./database-console.css";
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, useSyncExternalStore, type MutableRefObject, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";
import type { EditorView } from "@codemirror/view";
import { Code, LoaderCircle, PanelLeftClose, PanelLeftOpen, Play, RotateCw, Square } from "lucide-react";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { ExportFormat } from "@/bindings/ExportFormat";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { exportResult, POSTGRES_CONNECTION_CHANGED } from "@/lib/database-console";
import { ConsoleSession, type ConsoleState, type ResultTab, type TablePreview } from "@/lib/database-console-session";
import { databaseGrantLine, databasePamStatusQuery, databasesQuery, routeSummary, type SavedDatabase } from "@/lib/databases";
import { useRecordsStatus } from "@/lib/records";
import { postgresAddress, standardPostgresQuery } from "@/lib/standard-postgres";
import { revealHidden } from "@/lib/reveal-hidden";
import { statementsToRun } from "@/lib/sql-statements";
import { useNow } from "@/lib/use-now";
import { errorMessage } from "@/lib/utils";
import { useTerminalStore, type DatabaseTab, type TerminalState } from "@/stores/terminals";
import { ConsoleStatusBar } from "./ConsoleStatusBar";
import { ResultTabs } from "./ResultTabs";
import { SchemaTree } from "./SchemaTree";
import { SqlEditor } from "./SqlEditor";
import { SQL_DOCUMENT, type RelationDocument } from "./use-database-workspace";

const LOCK_OFFER = "You can open it read-only without the lock: Lunport sets default_transaction_read_only, which a statement in the session could turn off.";

/** The tab state the workspace shows for each console status. */
const TAB_STATES: Record<ConsoleState["status"], TerminalState> = {
  opening: "connecting",
  open: "open",
  ended: "ended",
  error: "error",
  lock_unsupported: "error",
  password_required: "connecting",
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
    const profileChanged = state.message === POSTGRES_CONNECTION_CHANGED;
    return <div className="console-banner" role="alert">
      {state.message && <p>{revealHidden(state.message)}</p>}
      <div className="console-banner-actions">
        {profileChanged ? <Button size="sm" onClick={actions.close}>Close console</Button>
          : <Button size="sm" onClick={actions.reconnect}>Reconnect</Button>}
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
export function ConsoleView({ state, mac, notice, viewRef, connectionStatus, actions, workspace }: {
  state: ConsoleState;
  /** Whether the keys read as macOS keys. */
  mac: boolean;
  /** Why the last Run or Export did nothing. */
  notice: string | null;
  viewRef: MutableRefObject<EditorView | null>;
  connectionStatus: ReactNode;
  actions: ConsoleActions;
  workspace?: { document?: RelationDocument; openQuery: () => void; runningHere?: boolean };
}) {
  const [showSqlEditor, setShowSqlEditor] = useState(false);
  const [schemaHidden, setSchemaHidden] = useState(false);
  const schemaId = useId();
  const [previewView, setPreviewView] = useState<{ id: string | undefined; pane: "data" | "columns" }>({ id: undefined, pane: "data" });
  const previewPane = previewView.id === workspace?.document?.id ? previewView.pane : "data";
  const open = state.status === "open";
  const canRun = open && !state.running;
  const runningHere = state.running && (workspace?.runningHere ?? true);
  const preview = state.preview;
  const editorVisible = !preview || (!workspace && showSqlEditor);
  const previewName = preview ? revealHidden(preview.schema + "." + preview.relation) : null;

  useEffect(() => {
    if (!editorVisible) return;
    viewRef.current?.requestMeasure();
    if (showSqlEditor) viewRef.current?.focus();
  }, [editorVisible, showSqlEditor, viewRef]);

  function browse(schema: string, relation: string) {
    setShowSqlEditor(false);
    setPreviewView({ id: undefined, pane: "data" });
    actions.browse(schema, relation);
  }

  const cancel = runningHere && <Button size="sm" variant="outline" onClick={actions.cancel}>
    <Square className="size-3" aria-hidden="true" />Cancel
  </Button>;
  const runControls = <>
    <Button size="sm" disabled={!canRun} onClick={() => actions.run(false)}>
      <Play className="size-3" aria-hidden="true" />Run<kbd>{mac ? "⌘↩" : "Ctrl+↩"}</kbd>
    </Button>
    <Button size="sm" variant="outline" disabled={!canRun} onClick={() => actions.run(true)}>
      Run all<kbd>{mac ? "⇧⌘↩" : "Shift+Ctrl+↩"}</kbd>
    </Button>
    {cancel}
  </>;

  return <div className="console-pane">
    <div className="console-body">
      {!workspace && <SchemaTree
        id={schemaId}
        hidden={schemaHidden}
        tree={state.schema}
        error={state.schemaError}
        canRefresh={open}
        onRefresh={actions.refreshSchema}
        canBrowse={canRun}
        onBrowse={browse}
        preview={preview}
      />}
      <section className="console-main" aria-label="Query">
        <div className="console-toolbar">
          {!workspace && <button
            type="button"
            className="console-icon-button"
            aria-label={schemaHidden ? "Show schema" : "Hide schema"}
            title={schemaHidden ? "Show schema" : "Hide schema"}
            aria-controls={schemaId}
            aria-expanded={!schemaHidden}
            onClick={() => setSchemaHidden(!schemaHidden)}
          >
            {schemaHidden ? <PanelLeftOpen className="size-4" aria-hidden="true" /> : <PanelLeftClose className="size-4" aria-hidden="true" />}
          </button>}
          {previewName !== null ? <>
            <h2 className="console-preview-title" title={previewName}>{previewName}</h2>
            <div className="console-preview-views" role="group" aria-label="Table view">
              <Button size="sm" variant={previewPane === "data" ? "secondary" : "ghost"} aria-pressed={previewPane === "data"} onClick={() => setPreviewView({ id: workspace?.document?.id, pane: "data" })}>Data</Button>
              <Button size="sm" variant={previewPane === "columns" ? "secondary" : "ghost"} aria-pressed={previewPane === "columns"} onClick={() => setPreviewView({ id: workspace?.document?.id, pane: "columns" })}>Columns</Button>
            </div>
            {workspace && preview && <Button size="sm" variant="ghost" disabled={!canRun} onClick={() => actions.browse(preview.schema, preview.relation)}>
              <RotateCw className="size-3.5" aria-hidden="true" />Refresh data
            </Button>}
            <Button size="sm" variant="outline" aria-expanded={workspace ? undefined : editorVisible} onClick={() => workspace ? workspace.openQuery() : setShowSqlEditor(!editorVisible)}>
              <Code className="size-3.5" aria-hidden="true" />SQL editor
            </Button>
            {!editorVisible && cancel}
          </> : runControls}
          {(state.status === "opening" || state.running) && <LoaderCircle className="size-4 text-muted-foreground motion-safe:animate-spin"
            aria-label={state.running ? runningHere ? "Running" : "Running in another tab" : "Connecting"} />}
          {connectionStatus}
        </div>
        {notice && <p className="console-notice" role="status">{revealHidden(notice)}</p>}
        <Banner state={state} actions={actions} />
        {preview && editorVisible && <div className="console-run-toolbar">{runControls}</div>}
        <SqlEditor viewRef={viewRef} schema={state.schema} hidden={!editorVisible} running={runningHere} onRun={actions.run} onCancel={actions.cancel} />
        {preview && previewPane === "columns" ? <TableColumns tree={state.schema} preview={preview} /> : <ResultTabs
          key={workspace?.document?.id ?? SQL_DOCUMENT}
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
  </div>;
}

/** Cloud SQL connection details from the saved database and its current IAM grant. */
function ConsoleConnection({ environment, database, username, readOnly }: {
  environment: DatabaseEnvironment;
  database: SavedDatabase | null;
  username: string | null;
  readOnly: ReadOnlyMode | null;
}) {
  const overview = useRecordsStatus().data?.overview ?? null;
  const pam = database?.pam ?? null;
  const read = useQuery({ ...databasePamStatusQuery(database?.id ?? ""), enabled: pam !== null });
  const now = useNow(1000);
  const route = database && overview ? routeSummary(overview, database) : { alias: null, iap: false };
  const grant = pam && read.data && !read.isError ? databaseGrantLine(read.data, pam, now) : null;
  return <ConsoleStatusBar environment={environment} database={database} route={route} username={username} readOnly={readOnly} grant={grant} />;
}

/** An unsaved credential lasts only until the current open attempt. */
function PostgresPasswordDialog({ databaseId, revision, connect, cancel }: {
  databaseId: string; revision: string; connect: (password: string) => void; cancel: () => void;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const query = useQuery({ ...standardPostgresQuery, refetchOnMount: "always", select: (rows) => rows.find((row) => row.id === databaseId) ?? null });
  const profile = query.data;
  const changed = !!profile && profile.revision !== revision;
  const ready = !query.isFetching && !query.isError && !!profile && !changed;
  // A fresh profile revision must not inherit the input for the previous endpoint.
  const formKey = profile ? `${profile.id}:${profile.revision}` : undefined;
  useEffect(() => { if (ready) input.current?.focus(); }, [ready, formKey]);
  return <Dialog open onOpenChange={(open) => { if (!open) cancel(); }}>
    <DialogContent onCloseAutoFocus={(event) => event.preventDefault()}>
      <DialogTitle>{ready ? `Connect to ${revealHidden(profile.name)}` : "Connect to PostgreSQL"}</DialogTitle>
      <DialogDescription>{ready
        ? `Enter the password for ${revealHidden(profile.username)} on ${revealHidden(postgresAddress(profile))} · ${revealHidden(profile.database)}.`
        : query.isPending || query.isFetching ? "Loading connection details…"
        : query.isError ? revealHidden(errorMessage(query.error))
        : changed ? POSTGRES_CONNECTION_CHANGED : "This PostgreSQL profile is unavailable."}</DialogDescription>
      <form key={formKey} className="space-y-4" onSubmit={(event) => {
        event.preventDefault();
        if (!ready || !input.current?.value) return;
        const password = input.current.value;
        input.current.value = "";
        connect(password);
      }}>
        {ready && <div className="space-y-2">
          <Label htmlFor={id}>Password</Label>
          <Input ref={input} id={id} type="password" autoComplete="off" required />
        </div>}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={cancel}>{changed ? "Close console" : "Cancel"}</Button>
          {ready && <Button type="submit">Connect</Button>}
          {query.isError && <Button type="button" onClick={() => void query.refetch()}>Retry</Button>}
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}

/**
 * The console of a database tab. It holds one session for the tab, opened when the pane mounts and closed when it unmounts, and keeps
 * the tab's state in the workspace in step with the session's.
 */
export function DatabaseConsolePane({ tab, active, workspace }: { tab: DatabaseTab; active: boolean; workspace?: {
  document?: RelationDocument;
  openQuery: () => void;
  register: (id: string, session: ConsoleSession) => () => void;
} }) {
  const [session] = useState(() => new ConsoleSession(tab.id, tab.databaseId, tab.postgresRevision));
  const subscribe = useCallback((listener: () => void) => session.subscribe(listener), [session]);
  const state = useSyncExternalStore(subscribe, () => session.state);
  const viewRef = useRef<EditorView | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform);
  const { environment } = tab;
  const postgres = environment === null;
  const databaseResult = useQuery({ ...databasesQuery, enabled: !postgres, select: (rows) => rows.find((row) => row.database.id === tab.databaseId)?.database ?? null });
  const database = postgres ? null : databaseResult.data ?? null;
  const register = workspace?.register;
  const documentView = workspace?.document;
  const workspaceMode = !!workspace;

  useLayoutEffect(() => {
    if (workspaceMode) session.showDocument(documentView?.id ?? SQL_DOCUMENT, documentView ?? null);
  }, [session, workspaceMode, documentView]);
  useEffect(() => register?.(tab.id, session), [register, tab.id, session]);

  useEffect(() => {
    if (!active || !documentView || state.status !== "open" || state.running || state.results.length || state.messages.length) return;
    if (state.preview?.schema !== documentView.schema || state.preview.relation !== documentView.relation) return;
    void session.browse(documentView.schema, documentView.relation);
  }, [active, documentView, session, state]);

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
    if (!active || documentView) return;
    viewRef.current?.requestMeasure();
    viewRef.current?.focus();
  }, [active, documentView]);

  useEffect(() => {
    if (!active || !state.preview || !state.running) return;
    const cancelPreview = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented || event.repeat || event.isComposing || viewRef.current?.hasFocus) return;
      if (event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"], [role="menu"]')) return;
      if (!session.runningHere || !(event.target instanceof Node) || !viewRef.current?.dom.closest(".console-pane")?.contains(event.target)) return;
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
    cancel: () => { if (session.runningHere) void session.cancel(); },
    reconnect: () => {
      setNotice(null);
      void session.reconnect();
    },
    openNotLocked: () => {
      if (postgres) return;
      useTerminalStore.getState().setReadOnly(tab.id, "not_locked");
      void session.open("not_locked");
    },
    close: () => useTerminalStore.getState().close(tab.id),
    refreshSchema: () => void session.refreshSchema(),
    showResult: (key) => session.showResult(key),
    showPage: (key, offset) => void session.showPage(key, offset),
    exportResult: (result, index, format) => void exportTo(result, index, format),
  };

  const mode = state.status === "open" ? state.opened?.read_only ?? null : null;
  return <>
    <ConsoleView
      state={state}
      mac={mac}
      notice={notice}
      viewRef={viewRef}
      actions={actions}
      workspace={workspace && { ...workspace, runningHere: session.runningHere }}
      connectionStatus={environment === null
        ? <ConsoleStatusBar environment={null} database={null} route={{ alias: null, iap: false }} username={state.opened?.iam_user ?? null} readOnly={mode} grant={null} />
        : <ConsoleConnection environment={environment} database={database} username={state.opened?.iam_user ?? null} readOnly={mode} />}
    />
    {active && tab.environment === null && state.status === "password_required" && <PostgresPasswordDialog databaseId={tab.databaseId} revision={tab.postgresRevision}
      connect={(password) => void session.open("standard", password)} cancel={actions.close} />}
  </>;
}

export default DatabaseConsolePane;
