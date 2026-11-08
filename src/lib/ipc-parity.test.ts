import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/*
 * The WebView calls the backend by command name (`tauriInvoke("records_status")`), and
 * nothing checks those names before runtime: a command that lost its place in the
 * `generate_handler!` list of src-tauri/src/lib.rs still compiles, and the button that
 * calls it fails only when someone presses it. This test reads the backend's command
 * list and the frontend's sources, so that a frontend reference to a command the backend
 * no longer registers fails `pnpm test` instead.
 */

const LIB_RS = "src-tauri/src/lib.rs";
const THIS_FILE = "src/lib/ipc-parity.test.ts";

function sourceFiles(dir: string, keep: (name: string) => boolean): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path, keep);
    return keep(name) ? [path] : [];
  });
}

/** The commands `lib.rs` registers: the last path segment of every entry of the `generate_handler!` list. */
function registeredCommands(): Set<string> {
  const source = readFileSync(LIB_RS, "utf8");
  const start = source.indexOf("generate_handler![");
  const end = source.indexOf("])", start);
  if (start < 0 || end < 0) throw new Error(`${LIB_RS}: cannot find the \`generate_handler![ … ])\` list; update ${THIS_FILE}.`);
  const names = new Set<string>();
  for (const raw of source.slice(start + "generate_handler![".length, end).split("\n")) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line || line.startsWith("#[")) continue;
    for (const entry of line.split(",")) {
      const path = entry.trim();
      if (path) names.add(path.split("::").pop()!);
    }
  }
  return names;
}

/** Every `#[tauri::command]` function in the backend, registered or not. */
function definedCommands(): Set<string> {
  const names = new Set<string>();
  for (const file of sourceFiles("src-tauri/src", (name) => name.endsWith(".rs"))) {
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      if (!/^\s*#\[tauri::command/.test(line)) return;
      const declaration = lines.slice(i + 1, i + 5).find((l) => /\bfn\s+[a-z_][a-z0-9_]*/.test(l));
      const name = declaration && /\bfn\s+([a-z_][a-z0-9_]*)/.exec(declaration)?.[1];
      if (name) names.add(name);
    });
  }
  return names;
}

const FRONTEND = sourceFiles("src", (name) => /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) && name !== "ipc-parity.test.ts");

/** `file:line` of every string literal in the frontend that equals one of `names`. */
function references(names: Set<string>): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const file of FRONTEND) {
    readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      for (const match of line.matchAll(/"([a-z][a-z0-9_]*)"/g)) {
        if (!names.has(match[1])) continue;
        found.set(match[1], [...(found.get(match[1]) ?? []), `${file}:${i + 1}`]);
      }
    });
  }
  return found;
}

describe("frontend command names against the backend's registered commands", () => {
  const registered = registeredCommands();
  const defined = definedCommands();

  it("reads a plausible command list from lib.rs", () => {
    expect(registered.size).toBeGreaterThan(100);
    expect([...registered].filter((name) => !defined.has(name)), "registered but never defined").toEqual([]);
  });

  it("every backend command the frontend names is registered", () => {
    const unregistered = new Set([...defined].filter((name) => !registered.has(name)));
    const stale = [...references(unregistered)].map(([name, where]) => `${name} <- ${where.join(", ")}`).sort();
    expect(stale, "frontend references to commands lib.rs no longer registers").toEqual([]);
  });

  it("every direct invoke names a registered command", () => {
    const unknown: string[] = [];
    for (const file of FRONTEND) {
      readFileSync(file, "utf8").split("\n").forEach((line, i) => {
        for (const match of line.matchAll(/\b(?:tauriInvoke|invoke)(?:<[^>]*>)?\(\s*"([a-z][a-z0-9_]*)"/g)) {
          if (!registered.has(match[1])) unknown.push(`${match[1]} <- ${file}:${i + 1}`);
        }
      });
    }
    expect(unknown.sort(), "invoked command names lib.rs does not register").toEqual([]);
  });
});
