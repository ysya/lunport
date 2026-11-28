import type { Channel } from "@tauri-apps/api/core";
import type { ConsoleEvent } from "@/bindings/ConsoleEvent";
import type { ConsoleOpen } from "@/bindings/ConsoleOpen";
import type { ConsoleRun } from "@/bindings/ConsoleRun";
import type { ExportFormat } from "@/bindings/ExportFormat";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import type { SchemaTree } from "@/bindings/SchemaTree";
import { tauriInvoke } from "@/lib/ipc";

/** Rows the backend answers per page. */
export const PAGE_ROWS = 200;
/** Most statements one Run all may start. */
export const MAX_RUN_ALL = 50;

export const POSTGRES_CONNECTION_CHANGED = "The PostgreSQL connection changed. Reopen it from Databases.";

export function openConsole(id: string, databaseId: string, readOnly: ReadOnlyMode, events: Channel<ConsoleEvent>, expectedRevision?: string, password?: string): Promise<ConsoleOpen> {
  return tauriInvoke<ConsoleOpen>("database_console_open", { id, databaseId, readOnly, events, ...(expectedRevision === undefined ? {} : { expectedRevision }), ...(password === undefined ? {} : { password }) });
}

export function closeConsole(id: string): Promise<void> {
  return tauriInvoke<void>("database_console_close", { id });
}

export function runStatement(id: string, sql: string, fresh: boolean, document?: string): Promise<ConsoleRun> {
  return tauriInvoke<ConsoleRun>("database_console_run", { id, sql, fresh, ...(document === undefined ? {} : { document }) });
}

export function discardConsoleDocument(id: string, document: string): Promise<void> {
  return tauriInvoke<void>("database_console_discard_document", { id, document });
}

export function resultPage(id: string, resultId: number, offset: number): Promise<(string | null)[][]> {
  return tauriInvoke<(string | null)[][]>("database_console_page", { id, resultId, offset });
}

export function cancelStatement(id: string): Promise<void> {
  return tauriInvoke<void>("database_console_cancel", { id });
}

export function readSchema(id: string): Promise<SchemaTree> {
  return tauriInvoke<SchemaTree>("database_console_schema", { id });
}

export function exportResult(id: string, resultId: number, format: ExportFormat, path: string): Promise<void> {
  return tauriInvoke<void>("database_console_export", { id, resultId, format, path });
}
