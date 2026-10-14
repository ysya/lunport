import { useState } from "react";
import { ChevronDown, ChevronRight, Folder, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SEARCH_INPUT_ID } from "@/lib/app-shortcuts";
import { useSettingsStore } from "@/stores/settings";
import { Input } from "@/components/ui/input";
import type { HostScope, RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { scopeLabel } from "./operations";
import {
  buildRecordTree,
  selectGroup as uniqueGroup,
  type GroupNode,
} from "./group-tree";
export const readinessLabel = {
  ready: "Ready",
  needs_key: "Needs key",
  key_conflict: "Key conflict",
  needs_review: "Needs review",
};
export function RecordHostList({
  overview,
  selectedId,
  selectedGroupId = null,
  select,
  selectGroup,
  selectScope,
  create,
  createGroup,
  disabled = false,
}: {
  overview: RecordOverview;
  selectedId: string | null;
  selectedGroupId?: string | null;
  select: (id: string) => void;
  selectGroup?: (id: string) => void;
  selectScope?: (scope: HostScope) => void;
  create?: () => void;
  createGroup?: () => void;
  disabled?: boolean;
}) {
  const showTags = useSettingsStore((state) => state.showHostTags);
  const [search, setSearch] = useState(""),
    [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const roots = buildRecordTree(overview, search);
  const counts = new Map<string, number>();
  for (const host of overview.hosts)
    counts.set(host.id, (counts.get(host.id) ?? 0) + 1);
  const hostRow = (host: RecordHostView, index: number) => {
    const ambiguous = (counts.get(host.id) ?? 0) > 1;
    return (
      <button
        key={`${host.id}:${index}`}
        type="button"
        className={cn(
          "w-full rounded-md px-3 py-2 text-left hover:bg-accent",
          selectedId === host.id && !ambiguous && "bg-accent",
        )}
        aria-pressed={selectedId === host.id && !ambiguous}
        disabled={disabled || ambiguous}
        onClick={() => select(host.id)}
      >
        <span className="block truncate text-sm font-medium">
          {revealHidden(host.payload.alias)}
        </span>
        {showTags && host.payload.tags.length > 0 && (
          <span className="block truncate text-xs text-muted-foreground">
            {revealHidden(host.payload.tags.join(" · "))}
          </span>
        )}
        <span className="block truncate text-xs text-muted-foreground">
          {revealHidden(host.payload.hostname)} ·{" "}
          {revealHidden(scopeLabel(overview, host.scope))}
        </span>
        <span className="text-xs text-muted-foreground">
          {ambiguous
            ? "Conflicting host ID"
            : host.group_error
              ? "Needs review"
              : readinessLabel[host.readiness.kind]}
        </span>
        {host.group_error && (
          <span className="block break-words text-xs text-destructive">
            {revealHidden(host.group_error)}
          </span>
        )}
      </button>
    );
  };
  const groupRow = (node: GroupNode): React.ReactNode => {
    const open = !!search || !collapsed.has(node.group.id);
    return (
      <div key={node.group.id}>
        <div className="flex items-center gap-1">
          <button
            type="button"
            aria-label={`${open ? "Collapse" : "Expand"} ${revealHidden(node.group.payload.name)}`}
            aria-expanded={open}
            className="rounded p-1 hover:bg-accent"
            disabled={disabled}
            onClick={() =>
              setCollapsed((current) => {
                const next = new Set(current);
                if (open) next.add(node.group.id);
                else next.delete(node.group.id);
                return next;
              })
            }
          >
            {open ? (
              <ChevronDown className="size-3.5" />
            ) : (
              <ChevronRight className="size-3.5" />
            )}
          </button>
          <button
            type="button"
            aria-pressed={selectedGroupId === node.group.id}
            className={cn(
              "flex min-w-0 flex-1 items-center gap-1.5 rounded-md py-2 pr-2 text-left text-sm hover:bg-accent",
              selectedGroupId === node.group.id && "bg-accent",
            )}
            disabled={disabled || !selectGroup}
            onClick={() => selectGroup?.(node.group.id)}
          >
            <Folder className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="truncate">
              {revealHidden(node.group.payload.name)}
            </span>
          </button>
        </div>
        {open && (
          <div className="ml-3 border-l pl-1">
            {node.children.map(groupRow)}
            {node.hosts.map(hostRow)}
          </div>
        )}
      </div>
    );
  };
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-3 border-b p-3">
        <h2 className="text-sm font-semibold">Hosts</h2>
        <div className="flex flex-wrap gap-1">
          {create && (
            <Button
              size="sm"
              variant="ghost"
              disabled={disabled}
              onClick={create}
            >
              <Plus className="size-3.5" /> New host
            </Button>
          )}
          {createGroup && (
            <Button
              size="sm"
              variant="ghost"
              disabled={disabled}
              onClick={createGroup}
            >
              <Folder className="size-3.5" /> New group
            </Button>
          )}
        </div>
        <Input
          id={SEARCH_INPUT_ID}
          aria-label="Search hosts"
          placeholder="Search hosts or Groups…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-2">
        {!overview.hosts.length && !overview.groups.length && (
          <p className="p-3 text-sm text-muted-foreground">
            No hosts yet. Add a host or import a configuration.
          </p>
        )}
        {!roots.length && (
          <p className="p-3 text-sm text-muted-foreground">
            No matching hosts or Groups
          </p>
        )}
        {roots.map((root, index) => (
          <section key={index}>
            <button
              type="button"
              className="w-full rounded px-2 py-2 text-left text-xs font-semibold text-muted-foreground hover:bg-accent"
              disabled={disabled || !selectScope}
              onClick={() => selectScope?.(root.scope)}
            >
              {revealHidden(root.label)}
            </button>
            {root.groups.map(groupRow)}
            {root.diagnostics.map(({ group, error }, at) => (
              <button
                key={`${group.id}:${at}`}
                type="button"
                className="w-full rounded-md px-3 py-2 text-left hover:bg-accent"
                disabled={
                  disabled ||
                  !selectGroup ||
                  !uniqueGroup(overview.groups, group.id)
                }
                aria-pressed={
                  !!uniqueGroup(overview.groups, group.id) &&
                  selectedGroupId === group.id
                }
                onClick={() => selectGroup?.(group.id)}
              >
                <span className="block truncate text-sm">
                  {revealHidden(group.payload.name)}
                </span>
                <span className="block break-words text-xs text-destructive">
                  {revealHidden(error)}
                </span>
              </button>
            ))}
            {root.ungrouped.length > 0 && (
              <div>
                <h3 className="px-3 py-1 text-xs font-medium text-muted-foreground">
                  Ungrouped
                </h3>
                {root.ungrouped.map(hostRow)}
              </div>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}
