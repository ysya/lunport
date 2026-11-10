import { tauriInvoke } from "./ipc";
import type { SavedDatabase } from "@/bindings/SavedDatabase";
import type { DatabaseView } from "@/bindings/DatabaseView";
import type { DatabaseLive } from "@/bindings/DatabaseLive";
import type { DatabasePhase } from "@/bindings/DatabasePhase";
export type { SavedDatabase, DatabaseView, DatabaseLive, DatabasePhase };

export const databasesKey = ["databases"] as const;
export const listDatabases = () => tauriInvoke<DatabaseView[]>("databases_list");
/** Saves the database (a new one when its id is empty) and answers it as the list shows it from then on: pass that as the next `expected`. */
export const saveDatabase = (database: SavedDatabase, expected: SavedDatabase | null) => tauriInvoke<SavedDatabase>("databases_save", { database, expected });
export const deleteDatabase = (expected: SavedDatabase) => tauriInvoke<void>("databases_delete", { expected });
/** The password apps sign in to the database's local port with; the first ask makes it, so it is there before the database starts. */
export const databasePassword = (id: string) => tauriInvoke<string>("databases_port_password", { id });
/** Replaces the port's password and answers the new one. Connections that are open go on; new ones need it. */
export const rotateDatabasePassword = (id: string) => tauriInvoke<string>("databases_rotate_port_password", { id });

/** A database to fill in: PostgreSQL over the public address, labelled dev, offered on no local port. */
export function newDatabase(): SavedDatabase {
  return {
    id: "",
    name: "",
    engine: "postgres",
    project: "",
    region: "",
    instance: "",
    environment: "dev",
    network: "public",
    account: null,
    default_database: "postgres",
    pam: null,
    local_port: null,
  };
}

/** What Cloud SQL calls the instance: `project:region:instance`. */
export function connectionName(d: SavedDatabase): string {
  return `${d.project}:${d.region}:${d.instance}`;
}

/** The three parts of a pasted connection name, each trimmed, or null when the text is not exactly three parts with something in each. Their values are judged when the database is saved. */
export function parseConnectionName(text: string): { project: string; region: string; instance: string } | null {
  const parts = text.split(":").map((part) => part.trim());
  if (parts.length !== 3 || parts.some((part) => part === "")) return null;
  const [project, region, instance] = parts;
  return { project, region, instance };
}
