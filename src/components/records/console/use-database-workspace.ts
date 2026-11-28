import { useCallback, useEffect, useState } from "react";
import { useTerminalStore, type SessionTab } from "@/stores/terminals";
import type { ConsoleSession, TablePreview } from "@/lib/database-console-session";

export type RelationDocument = TablePreview & { id: string; sessionId: string };
type Documents = { relations: RelationDocument[]; selected: Record<string, string | undefined> };
export const SQL_DOCUMENT = "sql";

export function useDatabaseWorkspace(tabs: SessionTab[]) {
  const [documents, setDocuments] = useState<Documents>({ relations: [], selected: {} });
  const [sources, setSources] = useState(new Map<string, ConsoleSession>());
  const [collapsed, setCollapsed] = useState(false);

  const register = useCallback((id: string, session: ConsoleSession) => {
    setSources((current) => new Map(current).set(id, session));
    return () => setSources((current) => {
      if (current.get(id) !== session) return current;
      const next = new Map(current);
      next.delete(id);
      return next;
    });
  }, []);

  useEffect(() => {
    const live = new Set(tabs.map((tab) => tab.id));
    setDocuments((current) => {
      const relations = current.relations.filter((doc) => live.has(doc.sessionId));
      if (relations.length === current.relations.length && Object.keys(current.selected).every((id) => live.has(id))) return current;
      const selected = Object.fromEntries(Object.entries(current.selected).filter(([id]) => live.has(id)));
      return { relations, selected };
    });
  }, [tabs]);

  function openQuery(id: string) {
    setDocuments((current) => current.selected[id]
      ? { ...current, selected: { ...current.selected, [id]: undefined } }
      : current);
    useTerminalStore.getState().activate(id);
  }

  function browse(sessionId: string, schema: string, relation: string) {
    if (!useTerminalStore.getState().tabs.some((tab) => tab.id === sessionId && tab.kind === "database")) return;
    const id = crypto.randomUUID();
    setDocuments((current) => {
      const existing = current.relations.find((doc) => doc.sessionId === sessionId && doc.schema === schema && doc.relation === relation);
      return {
        relations: existing ? current.relations : [...current.relations, { id, sessionId, schema, relation }],
        selected: { ...current.selected, [sessionId]: existing?.id ?? id },
      };
    });
    useTerminalStore.getState().activate(sessionId);
  }

  function findView(id: string | null) {
    return documents.relations.find((doc) => doc.id === id);
  }

  function activateView(id: string | null) {
    const doc = findView(id);
    if (doc) {
      setDocuments((current) => ({ ...current, selected: { ...current.selected, [doc.sessionId]: doc.id } }));
      useTerminalStore.getState().activate(doc.sessionId);
    } else if (id && tabs.some((tab) => tab.id === id && tab.kind === "database")) openQuery(id);
    else useTerminalStore.getState().activate(id);
  }

  function closeView(doc: RelationDocument) {
    setDocuments((current) => {
      const active = current.selected[doc.sessionId] === doc.id;
      const next = current.relations.filter((candidate) => candidate.id !== doc.id);
      return { relations: next, selected: active ? { ...current.selected, [doc.sessionId]: undefined } : current.selected };
    });
    sources.get(doc.sessionId)?.closeDocument(doc.id);
  }

  return { ...documents, sources, register, collapsed, setCollapsed, openQuery, browse, findView, activateView, closeView };
}
