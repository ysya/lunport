import {
  Clock3,
  Cloud,
  Folder,
  FolderOpen,
  Hash,
  KeyRound,
  Layers3,
  Plus,
  Settings2,
  Upload,
  AlertCircle,
  Server,
} from "lucide-react";
import type { RecordOverview } from "@/lib/records";
import { cn } from "@/lib/utils";
import { revealHidden } from "@/lib/sync-approvals";
import { buildRecordTree, affectedRecords, type GroupNode } from "./group-tree";
import { libraryHosts, type LibraryFilter } from "./library-view";

export type WorkspacePanel = "hosts" | "keys" | "account" | "import";
export function LibraryNavigation({
  overview,
  panel,
  filter,
  navigate,
  changeFilter,
  createGroup,
  settings,
}: {
  overview: RecordOverview;
  panel: WorkspacePanel;
  filter: LibraryFilter;
  navigate: (panel: WorkspacePanel) => void;
  changeFilter: (filter: LibraryFilter) => void;
  createGroup: () => void;
  settings: () => void;
}) {
  const choose = (next: LibraryFilter) => {
    changeFilter(next);
    navigate("hosts");
  };
  const row = (
    label: string,
    icon: React.ReactNode,
    active: boolean,
    action: () => void,
    count?: number,
  ) => (
    <button
      type="button"
      className={cn("library-nav-item", active && "is-active")}
      aria-current={active ? "page" : undefined}
      onClick={action}
      aria-label={label}
      title={label}
    >
      {icon}
      <span className="library-nav-label truncate">{label}</span>
      {count !== undefined && (
        <span className="library-nav-count">{count}</span>
      )}
    </button>
  );
  const groupRow = (node: GroupNode, depth = 0): React.ReactNode => (
    <div
      key={node.group.id}
      style={{ paddingLeft: depth ? "0.65rem" : undefined }}
    >
      {row(
        revealHidden(node.group.payload.name),
        <Folder className="size-4" />,
        panel === "hosts" &&
          filter.kind === "group" &&
          filter.id === node.group.id,
        () => choose({ kind: "group", id: node.group.id }),
        affectedRecords(overview, node.group).hosts,
      )}
      {node.children.map((child) => groupRow(child, depth + 1))}
    </div>
  );
  const groups = buildRecordTree(overview)
    .flatMap((root) => root.groups)
    .sort((a, b) => a.group.payload.name.localeCompare(b.group.payload.name));
  const tags = [
    ...new Set(overview.hosts.flatMap((h) => h.payload.tags)),
  ].sort();
  const attention = libraryHosts(
    overview,
    { kind: "attention" },
    "",
    {},
  ).length;
  return (
    <aside className="library-navigation" aria-label="Library navigation">
      <div className="library-brand">
        <span className="library-brand-icon">
          <Layers3 className="size-5" />
        </span>
        <span className="library-nav-label">
          <strong>My library</strong>
          <span>Your SSH workspace</span>
        </span>
      </div>
      <nav aria-label="Workspace sections" className="space-y-1">
        {row(
          "All hosts",
          <Server className="size-4" />,
          panel === "hosts" && filter.kind === "all",
          () => choose({ kind: "all" }),
          overview.hosts.length,
        )}
        {row(
          "Recent",
          <Clock3 className="size-4" />,
          panel === "hosts" && filter.kind === "recent",
          () => choose({ kind: "recent" }),
        )}
        {row(
          "Needs attention",
          <AlertCircle className="size-4" />,
          panel === "hosts" && filter.kind === "attention",
          () => choose({ kind: "attention" }),
          attention || undefined,
        )}
        {row("Keys", <KeyRound className="size-4" />, panel === "keys", () =>
          navigate("keys"),
        )}
      </nav>
      <div className="library-nav-collections min-h-0 flex-1 overflow-y-auto">
        <div className="library-nav-heading">
          <span>Groups</span>
          <button
            type="button"
            aria-label="New group"
            title="New group"
            onClick={createGroup}
          >
            <Plus className="size-3.5" />
          </button>
        </div>
        <nav aria-label="Groups" className="space-y-0.5">
          {groups.map((node) => groupRow(node))}
          {row(
            "Ungrouped",
            <FolderOpen className="size-4" />,
            panel === "hosts" && filter.kind === "ungrouped",
            () => choose({ kind: "ungrouped" }),
          )}
        </nav>
        {!!tags.length && (
          <>
            <div className="library-nav-heading mt-5">Tags</div>
            <nav aria-label="Tags" className="space-y-0.5">
              {tags.map((tag) => (
                <div key={tag}>
                  {row(
                    revealHidden(tag),
                    <Hash className="size-3.5" />,
                    panel === "hosts" &&
                      filter.kind === "tag" &&
                      filter.id === tag,
                    () => choose({ kind: "tag", id: tag }),
                  )}
                </div>
              ))}
            </nav>
          </>
        )}
      </div>
      <nav aria-label="Library tools" className="library-nav-tools space-y-1">
        {row(
          "Import hosts",
          <Upload className="size-4" />,
          panel === "import",
          () => navigate("import"),
        )}
        {row("Sync", <Cloud className="size-4" />, panel === "account", () =>
          navigate("account"),
        )}
        {row("Settings", <Settings2 className="size-4" />, false, settings)}
      </nav>
    </aside>
  );
}
