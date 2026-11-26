import { useEffect, useRef, type MutableRefObject } from "react";
import { basicSetup, EditorView } from "codemirror";
import { PostgreSQL, sql } from "@codemirror/lang-sql";
import { Compartment, Prec } from "@codemirror/state";
import { keymap } from "@codemirror/view";
import type { SchemaTree } from "@/bindings/SchemaTree";
import { completionNamespace } from "@/lib/schema-completion";

const language = (tree: SchemaTree | null) =>
  sql({ dialect: PostgreSQL, schema: completionNamespace(tree ?? { schemas: [], truncated: false }), defaultSchema: "public", upperCaseKeywords: true });

/**
 * The console's SQL editor. Mod-Enter runs, Shift-Mod-Enter runs all, and Escape cancels while a statement runs. Escape is bound below
 * autocompletion's keymap, so an open completion list closes first. Keys the editor does not bind, such as the workspace's ⌘W and
 * Ctrl+Tab, pass through. The editor is made once; completion follows `schema` without remaking it.
 */
export function SqlEditor({ viewRef, schema, running, hidden, onRun, onCancel }: {
  viewRef: MutableRefObject<EditorView | null>;
  schema: SchemaTree | null;
  running: boolean;
  hidden: boolean;
  onRun: (all: boolean) => void;
  onCancel: () => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const completion = useRef(new Compartment());
  const latest = useRef({ running, onRun, onCancel });
  latest.current = { running, onRun, onCancel };
  const firstSchema = useRef(schema);

  useEffect(() => {
    if (!host.current) return;
    const view = new EditorView({
      parent: host.current,
      extensions: [
        Prec.highest(keymap.of([
          { key: "Mod-Enter", run: () => { latest.current.onRun(false); return true; } },
          { key: "Shift-Mod-Enter", run: () => { latest.current.onRun(true); return true; } },
        ])),
        basicSetup,
        Prec.high(keymap.of([
          { key: "Escape", run: () => { if (!latest.current.running) return false; latest.current.onCancel(); return true; } },
        ])),
        completion.current.of(language(firstSchema.current)),
        EditorView.contentAttributes.of({ "aria-label": "SQL" }),
      ],
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      if (viewRef.current === view) viewRef.current = null;
    };
  }, [viewRef]);

  useEffect(() => {
    const view = viewRef.current;
    if (!view || schema === firstSchema.current) return;
    firstSchema.current = schema;
    view.dispatch({ effects: completion.current.reconfigure(language(schema)) });
  }, [schema, viewRef]);

  return <div ref={host} className="console-editor" hidden={hidden} />;
}
