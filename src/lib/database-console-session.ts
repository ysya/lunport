import { Channel } from "@tauri-apps/api/core";
import type { ConsoleEvent } from "@/bindings/ConsoleEvent";
import type { ConsoleOpened } from "@/bindings/ConsoleOpened";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import type { SchemaTree } from "@/bindings/SchemaTree";
import {
  cancelStatement,
  closeConsole,
  openConsole,
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

export type ConsoleState = {
  status: "opening" | "open" | "lock_unsupported" | "ended" | "error";
  /** The sentence for lock_unsupported, ended and error. */
  message: string | null;
  opened: ConsoleOpened | null;
  running: boolean;
  results: ResultTab[];
  /** Lines such as `Result 2 · 42P01 relation "nope" does not exist` or `SET · 3 ms`. */
  messages: string[];
  /** A ResultTab key or "messages". */
  activeResult: string | null;
  schema: SchemaTree | null;
  schemaError: string | null;
};

const ENDED_SENTENCE = "The connection ended. Reconnect to go on.";

const initialState = (): ConsoleState => ({
  status: "opening",
  message: null,
  opened: null,
  running: false,
  results: [],
  messages: [],
  activeResult: null,
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

  constructor(
    private readonly tabId: string,
    private readonly databaseId: string,
  ) {}

  get state(): ConsoleState {
    return this.current;
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

  async open(readOnly: ReadOnlyMode): Promise<void> {
    this.readOnly = readOnly;
    const generation = ++this.generation;
    this.current = initialState();
    this.update({});
    const events = new Channel<ConsoleEvent>();
    events.onmessage = (event) => {
      if (generation !== this.generation) return;
      if (event.kind === "ended") this.update({ status: "ended", message: event.message });
    };
    let answer;
    try {
      answer = await openConsole(this.tabId, this.databaseId, readOnly, events);
    } catch (error) {
      if (generation !== this.generation) return;
      this.update({ status: "error", message: sentence(error) });
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

  async run(statements: StatementRange[]): Promise<void> {
    if (statements.length === 0 || this.current.running || this.current.status !== "open") return;
    const generation = this.generation;
    const run = ++this.runs;
    const results: ResultTab[] = statements.map((statement, index) => ({
      key: `run-${run}-${index + 1}`,
      title: `Result ${index + 1}`,
      statement,
      run: null,
      page: [],
      offset: 0,
    }));
    this.update({ running: true, results: [...results], messages: [], activeResult: results[0].key });
    for (let index = 0; index < results.length; index++) {
      if (this.current.status !== "open") break;
      let answer: ConsoleRun;
      try {
        answer = await runStatement(this.tabId, results[index].statement.text, index === 0);
      } catch (error) {
        if (generation !== this.generation) return;
        const text = sentence(error);
        if (text === ENDED_SENTENCE) this.update({ status: "ended", message: text, running: false });
        else this.update({ running: false, messages: [...this.current.messages, text], activeResult: "messages" });
        return;
      }
      if (generation !== this.generation) return;
      const tab: ResultTab = { ...results[index], run: answer, page: answer.kind === "rows" ? answer.first_page : [] };
      results[index] = tab;
      const line = this.lineFor(tab.title, answer);
      this.update({
        results: [...results],
        messages: line ? [...this.current.messages, line] : this.current.messages,
      });
      if (answer.kind === "failed" || answer.kind === "canceled") break;
    }
    this.update({ running: false });
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
    try {
      await cancelStatement(this.tabId);
    } catch (error) {
      if (generation === this.generation) this.update({ messages: [...this.current.messages, sentence(error)], activeResult: "messages" });
    }
  }

  /** Shows the result tab `key`, or the messages for "messages". Any other key changes nothing. */
  showResult(key: string): void {
    if (key === this.current.activeResult) return;
    if (key !== "messages" && !this.current.results.some((result) => result.key === key)) return;
    this.update({ activeResult: key });
  }

  async showPage(key: string, offset: number): Promise<void> {
    const tab = this.current.results.find((result) => result.key === key);
    if (!tab || tab.run?.kind !== "rows") return;
    const generation = this.generation;
    try {
      const page = await resultPage(this.tabId, tab.run.result_id, offset);
      if (generation !== this.generation) return;
      this.update({
        results: this.current.results.map((result) => (result.key === key ? { ...result, page, offset } : result)),
      });
    } catch (error) {
      if (generation === this.generation) this.update({ messages: [...this.current.messages, sentence(error)], activeResult: "messages" });
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
