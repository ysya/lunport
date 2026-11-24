import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsoleEvent } from "@/bindings/ConsoleEvent";
import type { ConsoleOpen } from "@/bindings/ConsoleOpen";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { SchemaTree } from "@/bindings/SchemaTree";

type FakeChannel = { onmessage: (event: ConsoleEvent) => void };
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), channels: [] as FakeChannel[] }));
vi.mock("@/lib/ipc", () => ({ tauriInvoke: mocks.invoke }));
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    onmessage = () => {};
    constructor() {
      mocks.channels.push(this);
    }
  },
}));
import { ConsoleSession } from "./database-console-session";

const opened: ConsoleOpen = { kind: "opened", read_only: "locked", iam_user: "frank@example.com", server_version: "16.3" };
const tree: SchemaTree = { schemas: [], truncated: false };
const rows = (resultId: number): ConsoleRun => ({
  kind: "rows",
  result_id: resultId,
  columns: [],
  row_count: 1,
  truncated: null,
  elapsed_ms: 4,
  first_page: [["1"]],
});
const statement = (text: string, from = 0) => ({ from, to: from + text.length, text });
const calls = (name: string) => mocks.invoke.mock.calls.filter(([command]) => command === name);

function route(handlers: Record<string, (args: Record<string, unknown>) => unknown>) {
  mocks.invoke.mockImplementation((name: string, args: Record<string, unknown>) => {
    const handler = handlers[name];
    return handler ? Promise.resolve().then(() => handler(args)) : Promise.resolve(undefined);
  });
}

beforeEach(() => {
  mocks.invoke.mockReset();
  mocks.channels.length = 0;
});

describe("ConsoleSession", () => {
  it("open_reads_the_schema_once_open", async () => {
    route({ database_console_open: () => opened, database_console_schema: () => tree });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    expect(session.state.status).toBe("open");
    expect(session.state.opened?.iam_user).toBe("frank@example.com");
    expect(calls("database_console_open")[0][1]).toMatchObject({ id: "tab-1", databaseId: "db-1", readOnly: "locked" });
    expect(calls("database_console_schema")).toEqual([["database_console_schema", { id: "tab-1" }]]);
    expect(session.state.schema).toEqual(tree);
  });

  it("lock_unsupported_waits_for_the_person", async () => {
    route({ database_console_open: () => ({ kind: "lock_unsupported", message: "This instance cannot lock a session." }) });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    expect(session.state.status).toBe("lock_unsupported");
    expect(session.state.message).toBe("This instance cannot lock a session.");
    expect(calls("database_console_open")).toHaveLength(1);
    expect(calls("database_console_schema")).toHaveLength(0);
  });

  it("an_open_that_rejects_shows_its_sentence", async () => {
    route({
      database_console_open: () => {
        throw "Sign-in to Cloud SQL timed out.";
      },
    });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    expect(session.state.status).toBe("error");
    expect(session.state.message).toBe("Sign-in to Cloud SQL timed out.");
  });

  it("run_makes_one_result_tab_per_statement_and_passes_fresh_first", async () => {
    let next = 0;
    route({ database_console_open: () => opened, database_console_schema: () => tree, database_console_run: () => rows(++next) });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SELECT 1;"), statement("SELECT 2;", 10)]);
    expect(calls("database_console_run").map(([, args]) => args)).toEqual([
      { id: "tab-1", sql: "SELECT 1;", fresh: true },
      { id: "tab-1", sql: "SELECT 2;", fresh: false },
    ]);
    expect(session.state.results).toHaveLength(2);
    expect(session.state.results[0].page).toEqual([["1"]]);
    expect(session.state.running).toBe(false);
    expect(session.state.activeResult).toBe(session.state.results[0].key);
  });

  it("a_failed_statement_stops_the_run", async () => {
    const answers: ConsoleRun[] = [
      rows(1),
      { kind: "failed", message: 'relation "nope" does not exist', sqlstate: "42P01", position: 15, elapsed_ms: 2 },
    ];
    route({ database_console_open: () => opened, database_console_schema: () => tree, database_console_run: () => answers.shift() });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SELECT 1;"), statement("SELECT * FROM nope;", 10), statement("SELECT 3;", 30)]);
    expect(calls("database_console_run")).toHaveLength(2);
    expect(session.state.results.map((tab) => tab.run?.kind ?? null)).toEqual(["rows", "failed", null]);
    expect(session.state.messages).toEqual(['Result 2 · 42P01 relation "nope" does not exist']);
    expect(session.state.running).toBe(false);
  });

  it("a_canceled_statement_stops_the_run", async () => {
    const answers: ConsoleRun[] = [{ kind: "canceled", elapsed_ms: 9 }];
    route({ database_console_open: () => opened, database_console_schema: () => tree, database_console_run: () => answers.shift() });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SELECT pg_sleep(60);"), statement("SELECT 2;", 30)]);
    expect(calls("database_console_run")).toHaveLength(1);
    expect(session.state.results[1].run).toBeNull();
    expect(session.state.messages).toEqual(["Result 1 · Canceled"]);
  });

  it("a_command_without_rows_reports_its_tag", async () => {
    route({
      database_console_open: () => opened,
      database_console_schema: () => tree,
      database_console_run: () => ({ kind: "done", command_tag: "SET", elapsed_ms: 3 }),
    });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SET search_path = audit;")]);
    expect(session.state.messages).toEqual(["SET · 3 ms"]);
  });

  it("ended_event_marks_the_tab_ended", async () => {
    route({ database_console_open: () => opened, database_console_schema: () => tree });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    mocks.channels[0].onmessage({ kind: "ended", message: "The connection ended." });
    expect(session.state.status).toBe("ended");
    expect(session.state.message).toBe("The connection ended.");
  });

  it("a_run_on_a_dead_session_marks_the_tab_ended", async () => {
    route({
      database_console_open: () => opened,
      database_console_schema: () => tree,
      database_console_run: () => {
        throw "The connection ended. Reconnect to go on.";
      },
    });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SELECT 1;")]);
    expect(session.state.status).toBe("ended");
    expect(session.state.message).toBe("The connection ended. Reconnect to go on.");
    expect(session.state.running).toBe(false);
  });

  it("a_refused_cancel_goes_to_messages_and_the_run_goes_on", async () => {
    let finish: (run: ConsoleRun) => void = () => {};
    route({
      database_console_open: () => opened,
      database_console_schema: () => tree,
      database_console_run: () => new Promise<ConsoleRun>((resolve) => (finish = resolve)),
      database_console_cancel: () => {
        throw "Lunport could not reach Cloud SQL to cancel the query. It goes on running; close the tab to end the session.";
      },
    });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    const running = session.run([statement("SELECT pg_sleep(5);")]);
    await vi.waitFor(() => expect(calls("database_console_run")).toHaveLength(1));
    await session.cancel();
    expect(session.state.running).toBe(true);
    expect(session.state.messages).toEqual([
      "Lunport could not reach Cloud SQL to cancel the query. It goes on running; close the tab to end the session.",
    ]);
    finish(rows(1));
    await running;
    expect(session.state.running).toBe(false);
    expect(session.state.results[0].run?.kind).toBe("rows");
  });

  it("show_page_asks_for_200_from_the_offset", async () => {
    route({
      database_console_open: () => opened,
      database_console_schema: () => tree,
      database_console_run: () => rows(7),
      database_console_page: () => [["201"]],
    });
    const session = new ConsoleSession("tab-1", "db-1");
    await session.open("locked");
    await session.run([statement("SELECT 1;")]);
    const key = session.state.results[0].key;
    await session.showPage(key, 200);
    expect(calls("database_console_page")).toEqual([["database_console_page", { id: "tab-1", resultId: 7, offset: 200 }]]);
    expect(session.state.results[0]).toMatchObject({ offset: 200, page: [["201"]] });
  });

  it("a_superseded_open_is_ignored", async () => {
    const openers: { resolve: (value: ConsoleOpen) => void; reject: (reason: string) => void }[] = [];
    route({
      database_console_open: () => new Promise<ConsoleOpen>((resolve, reject) => openers.push({ resolve, reject })),
      database_console_schema: () => tree,
    });
    const session = new ConsoleSession("tab-1", "db-1");
    const first = session.open("locked");
    await vi.waitFor(() => expect(openers).toHaveLength(1));
    const reconnect = session.reconnect();
    await vi.waitFor(() => expect(openers).toHaveLength(2));
    openers[1].resolve(opened);
    await reconnect;
    expect(session.state.status).toBe("open");
    mocks.channels[0].onmessage({ kind: "ended", message: "The connection ended." });
    openers[0].reject("This console is closed. Open it again from Databases.");
    await first;
    expect(session.state.status).toBe("open");
    expect(session.state.message).toBeNull();
    expect(calls("database_console_close")).toHaveLength(1);
    expect(calls("database_console_open")[1][1]).toMatchObject({ readOnly: "locked" });
  });

  it("subscribers_hear_every_change_until_they_leave", async () => {
    route({ database_console_open: () => opened, database_console_schema: () => tree });
    const session = new ConsoleSession("tab-1", "db-1");
    const listener = vi.fn();
    const leave = session.subscribe(listener);
    await session.open("locked");
    expect(listener).toHaveBeenCalled();
    leave();
    listener.mockClear();
    mocks.channels[0].onmessage({ kind: "ended", message: "The connection ended." });
    expect(listener).not.toHaveBeenCalled();
  });
});
