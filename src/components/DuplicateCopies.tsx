import { TriangleAlert } from "lucide-react";

import { useHostsQuery } from "@/lib/queries";
import { useFileLabels, useShadowedCopies, useSpaceFiles } from "@/lib/sync-labels";
import { copiesNote, type CopiesNote, type NameCopy } from "@/lib/sync-sidebar";
import { basename } from "@/lib/utils";

const NO_HOSTS: never[] = [];

/**
 * Shown in the editor pane in place of the editor when the selected name has several copies,
 * one of them in a synced space (`ambiguousNames`): the editor, rename, move, remove and
 * duplicate all find a host by its name, so they would act on the first copy ssh happens to
 * be loaded with, not on the one the user clicked. Read-only: it says where the copies are,
 * how ssh combines them, and what changes a copy — the sidebar's fixes where the sidebar has
 * them for that copy, editing its file otherwise.
 */
export function DuplicateCopies({ alias, copies }: { alias: string; copies: NameCopy[] }) {
  const data = useHostsQuery().data;
  const labels = useFileLabels(data?.files ?? NO_HOSTS);
  const shadows = useShadowedCopies(data?.hosts ?? NO_HOSTS);
  // Until the sync overview is read nothing is known about which copy is synced (`ambiguousNames` fails closed).
  const spacesKnown = useSpaceFiles() !== undefined;
  return <CopiesPanel note={copiesNote(alias, copies, (file) => labels.get(file) ?? basename(file), shadows, spacesKnown)} />;
}

/** The explanation itself (exported for the markup tests). */
export function CopiesPanel({ note }: { note: CopiesNote }) {
  return (
    <div className="space-y-4" role="note">
      <div className="flex items-start gap-2.5">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
        <h2 className="text-[0.9375rem] font-semibold tracking-tight">{note.title}</h2>
      </div>
      {note.unknown && <p className="text-sm">{note.unknown}</p>}
      {note.groups.map((group) => {
        const items = group.copies.map((copy, i) => (
          <li key={`${copy.file}-${i}`}>
            <span className="font-medium">{copy.label}</span>
            {copy.detail && <span className="text-muted-foreground"> — {copy.detail}</span>}
            <div className="font-mono text-xs break-all text-muted-foreground select-text">{copy.file}</div>
            {copy.how && <div className="text-xs text-muted-foreground">{copy.how}</div>}
          </li>
        ));
        return (
          <div key={group.heading} className="space-y-1.5">
            <p className="text-sm text-muted-foreground">{group.heading}</p>
            {group.ordered ? (
              <ol className="list-decimal space-y-1.5 pl-5 text-sm">{items}</ol>
            ) : (
              <ul className="list-disc space-y-1.5 pl-5 text-sm">{items}</ul>
            )}
          </div>
        );
      })}
      <p className="text-sm">{note.combine}</p>
      <p className="text-sm text-muted-foreground">{note.fix}</p>
    </div>
  );
}
