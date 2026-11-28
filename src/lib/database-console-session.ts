import { Channel } from "@tauri-apps/api/core";
import type { ConsoleEvent } from "@/bindings/ConsoleEvent";
import type { ConsoleOpened } from "@/bindings/ConsoleOpened";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import type { SchemaTree } from "@/bindings/SchemaTree";
import {
  cancelStatement,
  closeConsole,
  discardConsoleDocument,
  openConsole,
  PAGE_ROWS,
  readSchema,
  resultPage,
  runStatement,
} from "@/lib/database-console";
import type { StatementRange } from "@/lib/sql-statements";

export type ResultTab = {
  key: string;
  title: string;
  statement: StatementRange;
  /** null: not run */
  run: ConsoleRun | null;
  page: (string | null)[][];
  offset: number;
};

export type TablePreview = { schema: string; relation: string };

export type ConsoleState = {
  status: "opening" | "open" | "lock_unsupported" | "password_required" | "ended" | "error";
  /** The sentence for lock_unsupported, ended and error. */
  message: string | null;
  opened: ConsoleOpened | null;
  running: boolean;
  preview: TablePreview | null;
  results: ResultTab[];
  /** Lines such as `Result 2 · 42P01 relation "nope" does not exist` or `SET · 3 ms`. */
  messages: string[];
  /** A ResultTab key or "messages". */
  activeResult: string | null;
  schema: SchemaTree | null;
  schemaError: string | null;
};

const PASSWORD_REQUIRED = "Enter the PostgreSQL password to connect.";
const ENDED_SENTENCE = "The connection ended. Reconnect to go on.";

type DocumentResults = Pick<ConsoleState, "preview" | "results" | "messages" | "activeResult">;
const emptyDocument = (preview: TablePreview | null = null): DocumentResults => ({
  preview, results: [], messages: [], activeResult: null,
});

const initialState = (): ConsoleState => ({
  status: "opening",
  message: null,
  opened: null,
  running: false,
  ...emptyDocument(),
  schema: null,
  schemaError: null,
});

function sentence(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

export class ConsoleSession {
  private current: ConsoleState = initialState();
  private readonly listeners = new Set<() => void>();
  private readOnly: ReadOnlyMode = "locked";
  /** Counts opens, reconnects and closes. Anything started under an earlier count is ignored. */
  private generation = 0;
  private runs = 0;
  private document: string | undefined;
  private readonly documents = new Map<string, DocumentResults>();
  private pending: { document: string | undefined; discarded: boolean } | null = null;

  constructor(
    private readonly tabId: string,
    private readonly databaseId: string,
    private readonly expectedRevision?: string,
  ) {}

  get state(): ConsoleState {
    return this.current;
  }

  get runningHere(): boolean {
    return this.pending !== null && !this.pending.discarded && this.pending.document === this.document && this.current.running;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private update(change: Partial<ConsoleState>) {
    this.current = { ...this.current, ...change };
    for (const listener of [...this.listeners]) listener();
  }

  showDocument(id: string, preview: TablePreview | null): void {
    if (this.document === id) return;
    const results = this.documents.get(id) ?? emptyDocument(preview);
    this.documents.set(id, results);
    this.document = id;
    this.update(results);
  }

  closeDocument(id: string): void {
    this.documents.delete(id);
    if (this.pending?.document === id) this.pending.discarded = true;
    else void this.discard(id);
  }

  private async discard(id: string): Promise<void> {
    try {
      await discardConsoleDocument(this.tabId, id);
    } catch {
      // An ended connection already released its results.
    }
  }

  private resultsFor(id: string | undefined): DocumentResults | undefined {
    return id === undefined ? this.current : this.documents.get(id);
  }

  private updateResults(id: string | undefined, change: Partial<DocumentResults>, sessionChange?: Partial<ConsoleState>) {
    if (id !== undefined) {
      const previous = this.documents.get(id);
      if (!previous) return;
      this.documents.set(id, { ...previous, ...change });
    }
    if (id === this.document) this.update({ ...change, ...sessionChange });
    else if (sessionChange) this.update(sessionChange);
  }

  async open(readOnly: ReadOnlyMode, password?: string): Promise<void> {
    this.readOnly = readOnly;
    const generation = ++this.generation;
    const results = this.document === undefined ? emptyDocument() : emptyDocument(this.current.preview);
    this.documents.clear();
    if (this.document !== undefined) this.documents.set(this.document, results);
    this.pending = null;
    this.current = { ...initialState(), ...results };
    this.update({});
    const events = new Channel<ConsoleEvent>();
    events.onmessage = (event) => {
      if (generation !== this.generation) return;
      if (event.kind === "ended") this.update({ status: "ended", message: event.message });
    };
    let answer;
    try {
      answer = await openConsole(this.tabId, this.databaseId, readOnly, events, this.expectedRevision, password);
    } catch (error) {
      if (generation !== this.generation) return;
      const message = sentence(error);
      if (readOnly === "standard" && message === PASSWORD_REQUIRED) this.update({ status: "password_required" });
      else this.update({ status: "error", message });
      return;
    }
    if (generation !== this.generation) return;
    if (answer.kind === "lock_unsupported") {
      this.update({ status: "lock_unsupported", message: answer.message });
      return;
    }
    const { kind: _kind, ...opened } = answer;
    this.update({ status: "open", opened });
    await this.loadSchema(generation);
  }

  async refreshSchema(): Promise<void> {
    await this.loadSchema(this.generation);
  }

  private async loadSchema(generation: number): Promise<void> {
    try {
      const schema = await readSchema(this.tabId);
      if (generation === this.generation) this.update({ schema, schemaError: null });
    } catch (error) {
      if (generation === this.generation) this.update({ schemaError: sentence(error) });
    }
  }

  browse(schema: string, relation: string): Promise<void> {
    const quote = (identifier: string) => '"' + identifier.replace(/"/g, '""') + '"';
    const text = `SELECT * FROM ${quote(schema)}.${quote(relation)} LIMIT ${PAGE_ROWS};`;
    return this.run([{ text, from: 0, to: text.length }], { schema, relation });
  }

  async run(statements: StatementRange[], preview: TablePreview | null = null): Promise<void> {
    if (statements.length === 0 || this.current.running || this.current.status !== "open") return;
    const generation = this.generation;
    const run = ++this.runs;
    const document = this.document;
    const pending = { document, discarded: false };
    this.pending = pending;
    const results: ResultTab[] = statements.map((statement, index) => ({
      key: `run-${run}-${index + 1}`,
      title: preview ? "Preview" : `Result ${index + 1}`,
      statement,
      run: null,
      page: [],
      offset: 0,
    }));
    this.updateResults(document, { preview, results: [...results], messages: [], activeResult: results[0].key }, { running: true });
    try {
      for (let index = 0; index < results.length; index++) {
        if (this.current.status !== "open" || pending.discarded) break;
        const answer = await runStatement(this.tabId, results[index].statement.text, index === 0, document);
        if (generation !== this.generation || pending.discarded) return;
        const tab: ResultTab = { ...results[index], run: answer, page: answer.kind === "rows" ? answer.first_page : [] };
        results[index] = tab;
        const line = this.lineFor(tab.title, answer);
        const messages = this.resultsFor(document)?.messages ?? [];
        this.updateResults(document, { results: [...results], messages: line ? [...messages, line] : messages });
        if (answer.kind === "failed" || answer.kind === "canceled") break;
      }
    } catch (error) {
      if (generation !== this.generation) return;
      const text = sentence(error);
      if (text === ENDED_SENTENCE) this.update({ status: "ended", message: text });
      else this.updateResults(document, { messages: [...(this.resultsFor(document)?.messages ?? []), text], activeResult: "messages" });
    } finally {
      if (generation === this.generation) {
        if (pending.discarded && document !== undefined) await this.discard(document);
        if (generation === this.generation) {
          this.pending = null;
          this.update({ running: false });
        }
      }
    }
  }

  private lineFor(title: string, answer: ConsoleRun): string | null {
    switch (answer.kind) {
      case "rows":
        return null;
      case "done":
        return `${answer.command_tag} · ${answer.elapsed_ms} ms`;
      case "failed":
        return `${title} · ${answer.sqlstate ? `${answer.sqlstate} ` : ""}${answer.message}`;
      case "canceled":
        return `${title} · Canceled`;
    }
  }

  async cancel(): Promise<void> {
    if (!this.current.running) return;
    const generation = this.generation;
    const document = this.pending?.document;
    try {
      await cancelStatement(this.tabId);
    } catch (error) {
      if (generation === this.generation) this.updateResults(document, { messages: [...(this.resultsFor(document)?.messages ?? []), sentence(error)], activeResult: "messages" });
    }
  }

  /** Shows the result tab `key`, or the messages for "messages". Any other key changes nothing. */
  showResult(key: string): void {
    if (key === this.current.activeResult) return;
    if (key !== "messages" && !this.current.results.some((result) => result.key === key)) return;
    this.updateResults(this.document, { activeResult: key });
  }

  async showPage(key: string, offset: number): Promise<void> {
    const tab = this.current.results.find((result) => result.key === key);
    if (!tab || tab.run?.kind !== "rows") return;
    const generation = this.generation;
    const document = this.document;
    const current = () => generation === this.generation ? this.resultsFor(document) : undefined;
    try {
      const page = await resultPage(this.tabId, tab.run.result_id, offset);
      const results = current()?.results;
      if (!results?.some((result) => result.key === key)) return;
      this.updateResults(document, {
        results: results.map((result) => (result.key === key ? { ...result, page, offset } : result)),
      });
    } catch (error) {
      const results = current();
      if (results?.results.some((result) => result.key === key)) {
        this.updateResults(document, { messages: [...results.messages, sentence(error)], activeResult: "messages" });
      }
    }
  }

  async reconnect(): Promise<void> {
    const generation = ++this.generation;
    try {
      await closeConsole(this.tabId);
    } catch {
      // A session that is already gone needs no closing.
    }
    if (generation !== this.generation) return;
    await this.open(this.readOnly);
  }

  async close(): Promise<void> {
    this.generation++;
    try {
      await closeConsole(this.tabId);
    } catch {
      // A session that is already gone needs no closing.
    }
  }
}
