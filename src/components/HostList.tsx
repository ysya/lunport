import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  Search,
  ServerOff,
  Server,
  Globe,
  ChevronRight,
  FileText,
  Play,
  SlidersHorizontal,
  Pencil,
  Plus,
  Upload,
  Tags,
  MoreHorizontal,
  FolderInput,
  Trash2,
  X,
} from "lucide-react";

import type { HostSummary } from "@/bindings/HostSummary";
import { useUiStore } from "@/stores/ui";
import {
  useConnect,
  useHostsQuery,
  useMoveHost,
  useRemoveHost,
  useReorderHosts,
  useSetTags,
  useTerminals,
} from "@/lib/queries";
import { rangeBetween } from "@/lib/selection-range";
import { useSettingsStore } from "@/stores/settings";
import { effectiveNewTab, resolveTerminal } from "@/lib/settings-logic";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AddHostDialog } from "@/components/AddHostDialog";
import { FileViewDialog } from "@/components/FileViewDialog";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { cn, basename } from "@/lib/utils";
import { isWildcardOnly, labelsFor, secondaryLine, shortLabels } from "@/lib/host-display";
import { hostMatches, parseQuery } from "@/lib/host-filter";
import { toast } from "sonner";
import { buildNewOrder } from "@/lib/reorder";
import { SEARCH_INPUT_ID } from "@/lib/app-shortcuts";

/** Sentinel Select value for the "All files" scope (Radix items can't be empty). */
const ALL_FILES = "__all__";

/**
 * How long a single click on a group header waits before toggling collapse —
 * just past the double-click window, so a rename double-click never toggles.
 */
const COLLAPSE_CLICK_DELAY_MS = 250;

/** Dotted-quad IPv4 (e.g. 10.0.0.5) — these are servers, not "web" hosts. */
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
/** A hostname that ends in a DNS-style label, e.g. example.com / corp.internal. */
const DOMAIN_RE = /\.[a-z]{2,}$/i;

/**
 * Pick a leading anchor glyph for a row: a globe for hosts that resolve to a
 * DNS domain (alias or hostname like `github.com` / `corp.internal`), a server
 * for IPs and bare names. Monochrome + muted — a left anchor so the list isn't
 * a wall of text.
 */
function HostGlyph({ host }: { host: HostSummary }) {
  const target = (host.hostname?.trim() || host.alias).trim();
  const isDomain = !IPV4_RE.test(target) && DOMAIN_RE.test(target);
  const Icon = isDomain ? Globe : Server;
  return (
    <Icon
      className="size-3.5 shrink-0 text-muted-foreground/70 group-aria-[current=true]:text-primary/80"
      aria-hidden
    />
  );
}


interface HostRowProps {
  host: HostSummary;
  active: boolean;
  /** Staggered enter-animation delay, e.g. "44ms". */
  delay: string;
  /** Wildcard-defaults rows are de-emphasized and not connectable. */
  variant: "host" | "defaults";
  /** Receives the click event so the list can route ⌘/Shift to multi-select. */
  onSelect: (e: ReactMouseEvent<HTMLButtonElement>) => void;
  /** Multi-select membership — adds the checked-row tint. */
  checked?: boolean;
  /** Omitted for defaults rows — connecting to `Host *` is meaningless. */
  onConnect?: () => void;
  /** Right-click "Deploy key…". Omitted = no context menu (defaults rows). */
  onDeployKey?: () => void;
  /** Render tag chips after the alias (file grouping only — tag groups ARE the tag). */
  showTags?: boolean;
  /** Other loaded files as "Move to file" targets (empty = hide the submenu). */
  moveTargets?: { file: string; label: string }[];
  onMoveTo?: (file: string) => void;
  /** Opens the shared remove-confirmation dialog (owned by HostList). */
  onRemove?: () => void;
  /** Row can be drag-reordered (within its source file). Off while searching. */
  draggable?: boolean;
  /** True while THIS row is the drag source — rendered semi-transparent. */
  dragging?: boolean;
  /** Insertion indicator: a 2px accent line above/below this row. */
  indicator?: "before" | "after" | null;
  onDragStart?: (e: DragEvent<HTMLElement>) => void;
  onDragOver?: (e: DragEvent<HTMLElement>) => void;
  onDrop?: (e: DragEvent<HTMLElement>) => void;
  onDragEnd?: () => void;
}

/**
 * Compact single-line row (~28px): glyph + alias + right-aligned mono
 * secondary (`user@hostname`). Selection stays the ONE quiet cue — an inset
 * accent-tinted pill. Tags are no longer shown per-row (still searchable and
 * visible in the editor).
 */
function HostRow({
  host,
  active,
  delay,
  variant,
  onSelect,
  checked,
  onConnect,
  onDeployKey,
  showTags,
  moveTargets = [],
  onMoveTo,
  onRemove,
  draggable,
  dragging,
  indicator,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
}: HostRowProps) {
  const secondary = secondaryLine(host);
  const isDefaults = variant === "defaults";
  const row = (
    <li
      className="animate-row-enter group/row relative"
      style={{ animationDelay: delay }}
      // Drop targeting lives on the <li> so the whole row (incl. the Play
      // overlay's footprint) maps to an insertion gap.
      onDragOver={onDragOver}
      onDrop={onDrop}
    >
      <button
        type="button"
        onClick={onSelect}
        // Dragging starts ONLY from the row body — the Play overlay is a
        // sibling, so grabbing it never moves the row. Native HTML5 DnD has
        // its own movement threshold, so plain clicks still just select.
        draggable={draggable || undefined}
        onDragStart={onDragStart}
        onDragEnd={onDragEnd}
        aria-current={active ? "true" : undefined}
        className={cn(
          "group flex h-7 w-full items-center gap-2 rounded-[6px] pr-2 pl-2 text-left select-none",
          "transition-[background-color,padding] duration-100",
          "hover:bg-muted/70 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
          // Reserve room for the overlay buttons (⋯ + Play) while visible so the
          // right-aligned secondary slides clear instead of colliding with them.
          onConnect &&
            (onDeployKey
              ? "group-hover/row:pr-14 [&:has(~button:focus-visible)]:pr-14 [&:has(~[data-state=open])]:pr-14"
              : "group-hover/row:pr-8 [&:has(~button:focus-visible)]:pr-8"),
          draggable && "active:cursor-grabbing",
          dragging && "opacity-40",
          active && "bg-primary/12 hover:bg-primary/15",
          checked && "bg-primary/8 ring-1 ring-inset ring-primary/30",
        )}
      >
        {isDefaults ? (
          <SlidersHorizontal
            className="size-3.5 shrink-0 text-muted-foreground/60 group-aria-[current=true]:text-primary/80"
            aria-hidden
          />
        ) : (
          <HostGlyph host={host} />
        )}
        <span
          className={cn(
            "min-w-0 flex-1 truncate text-[0.8125rem] leading-7",
            isDefaults
              ? "font-normal text-muted-foreground"
              : cn("font-medium", active ? "text-foreground" : "text-foreground/90"),
          )}
          title={
            showTags && host.tags.length > 0
              ? `${host.alias} — tags: ${host.tags.join(", ")}`
              : undefined
          }
        >
          {host.alias}
        </span>
        {showTags && host.tags.length > 0 && (
          <span className="flex shrink-0 items-center gap-1" aria-hidden>
            {host.tags.slice(0, 2).map((t) => (
              <span
                key={t}
                className="max-w-16 truncate rounded bg-muted px-1 font-mono text-[0.625rem] leading-4 text-muted-foreground"
              >
                {t}
              </span>
            ))}
            {host.tags.length > 2 && (
              <span className="font-mono text-[0.625rem] text-muted-foreground/70">
                +{host.tags.length - 2}
              </span>
            )}
          </span>
        )}
        {secondary && (
          <span
            className={cn(
              "max-w-[55%] truncate text-right font-mono text-[0.6875rem]",
              isDefaults ? "text-muted-foreground/60" : "text-muted-foreground",
            )}
          >
            {secondary}
          </span>
        )}
      </button>
      {/*
       * Connect affordance — overlays the row's right edge, hidden until the
       * row is hovered/focused (or the button itself is focused for keyboard
       * users). Stops propagation so it never also selects the row.
       */}
      {onDeployKey && (
        /* Hover ⋯ — the same actions as the right-click menu, but visible. */
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label={`Actions for ${host.alias}`}
              title="Actions"
              onClick={(e) => e.stopPropagation()}
              className="absolute inset-y-0 right-7 my-auto size-6 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover/row:opacity-100 data-[state=open]:opacity-100"
            >
              <MoreHorizontal className="size-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {onConnect && (
              <DropdownMenuItem onSelect={onConnect}>
                <Play className="size-3.5" />
                Connect
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onSelect={onDeployKey}>
              <Upload className="size-3.5" />
              Deploy key…
            </DropdownMenuItem>
            {onMoveTo && moveTargets.length > 0 && (
              <DropdownMenuSub>
                <DropdownMenuSubTrigger>
                  <FolderInput className="size-3.5" />
                  Move to file
                </DropdownMenuSubTrigger>
                <DropdownMenuSubContent>
                  {moveTargets.map((t) => (
                    <DropdownMenuItem key={t.file} onSelect={() => onMoveTo(t.file)}>
                      {t.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuSubContent>
              </DropdownMenuSub>
            )}
            {onRemove && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={onRemove}>
                  <Trash2 className="size-3.5" />
                  Remove…
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {onConnect && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={`Connect to ${host.alias}`}
          title={`Connect to ${host.alias}`}
          onClick={(e) => {
            e.stopPropagation();
            onConnect();
          }}
          // Centered via auto margins, NOT translate: the Button's global
          // `active:translate-y-px` would override a translate-based centering
          // on mousedown, teleporting the button out from under the cursor so
          // the click never lands (mouseup retargets to the row).
          className="absolute inset-y-0 right-1 my-auto size-6 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover/row:opacity-100"
        >
          <Play className="size-3.5" />
        </Button>
      )}
      {/* 2px accent insertion line in the gap above/below this row. */}
      {indicator && (
        <div
          aria-hidden
          className={cn(
            "pointer-events-none absolute inset-x-1 z-10 h-0.5 rounded-full bg-primary",
            indicator === "before" ? "-top-px" : "-bottom-px",
          )}
        />
      )}
    </li>
  );

  if (!onDeployKey) return row;

  // Mirrors the ⋯ dropdown above — keep both item lists in the same order.
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{row}</ContextMenuTrigger>
      <ContextMenuContent>
        {onConnect && (
          <ContextMenuItem onSelect={onConnect}>
            <Play className="size-3.5" />
            Connect
          </ContextMenuItem>
        )}
        <ContextMenuItem onSelect={onDeployKey}>
          <Upload className="size-3.5" />
          Deploy key…
        </ContextMenuItem>
        {onMoveTo && moveTargets.length > 0 && (
          <ContextMenuSub>
            <ContextMenuSubTrigger>
              <FolderInput className="size-3.5" />
              Move to file
            </ContextMenuSubTrigger>
            <ContextMenuSubContent>
              {moveTargets.map((t) => (
                <ContextMenuItem key={t.file} onSelect={() => onMoveTo(t.file)}>
                  {t.label}
                </ContextMenuItem>
              ))}
            </ContextMenuSubContent>
          </ContextMenuSub>
        )}
        {onRemove && (
          <>
            <ContextMenuSeparator />
            <ContextMenuItem variant="destructive" onSelect={onRemove}>
              <Trash2 className="size-3.5" />
              Remove…
            </ContextMenuItem>
          </>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}

/** Tiny muted subheader marking the wildcard-defaults group atop each file section. */
function DefaultsLabel() {
  return (
    <div className="px-2 pt-1 pb-0.5 text-[0.625rem] font-medium tracking-[0.1em] text-muted-foreground/60 uppercase select-none">
      Defaults
    </div>
  );
}

export interface HostListProps {
  hosts: HostSummary[];
  isLoading?: boolean;
}

export function HostList({ hosts, isLoading }: HostListProps) {
  const search = useUiStore((s) => s.search);
  const setSearch = useUiStore((s) => s.setSearch);
  const selectedAlias = useUiStore((s) => s.selectedAlias);
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const collapsedGroups = useUiStore((s) => s.collapsedGroups);
  const toggleGroup = useUiStore((s) => s.toggleGroup);
  const fileScope = useUiStore((s) => s.fileScope);
  const setFileScope = useUiStore((s) => s.setFileScope);
  const groupMode = useUiStore((s) => s.groupMode);
  const setGroupMode = useUiStore((s) => s.setGroupMode);
  const setAddHostOpen = useUiStore((s) => s.setAddHostOpen);
  const setAddHostTargetFile = useUiStore((s) => s.setAddHostTargetFile);
  const setDeployKeyAlias = useUiStore((s) => s.setDeployKeyAlias);
  const terminalId = useSettingsStore((s) => s.terminalId);
  const hostTerminals = useSettingsStore((s) => s.hostTerminals);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const showHostTags = useSettingsStore((s) => s.showHostTags);
  const setFileAlias = useSettingsStore((s) => s.setFileAlias);
  const terminals = useTerminals();
  const connect = useConnect();
  const reorderHosts = useReorderHosts();
  const moveHost = useMoveHost();
  const removeHost = useRemoveHost();
  const setTags = useSetTags();
  // Row-menu remove confirmation — one dialog shared by every row.
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);

  // ── Multi-select ──────────────────────────────────────────────────────────
  // Checked aliases are independent of the editor's single selection: ⌘-click
  // toggles, Shift-click ranges from the last plain/⌘ click, plain click and
  // Esc clear. Batch actions live in the sticky footer below the list.
  const [checkedAliases, setCheckedAliases] = useState<Set<string>>(new Set());
  const [selectionAnchor, setSelectionAnchor] = useState<string | null>(null);
  const [batchRemoveOpen, setBatchRemoveOpen] = useState(false);
  const [tagDraft, setTagDraft] = useState<string | null>(null); // null = input closed

  const clearChecked = () => {
    setCheckedAliases(new Set());
    setBatchRemoveOpen(false);
    setTagDraft(null);
  };

  useEffect(() => {
    if (checkedAliases.size === 0) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") clearChecked();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [checkedAliases.size]);

  // ALL loaded source files (same cache entry App reads) — drives the scope
  // Select even for files that currently have zero hosts.
  const { data } = useHostsQuery();
  const files = useMemo(() => data?.files ?? [], [data]);
  // Auto heuristic over the FULL file set (the "clear back to this" baseline)…
  const autoLabels = useMemo(() => shortLabels(files), [files]);
  // …overlaid with the user's per-file display aliases (an override wins).
  const labels = useMemo(() => labelsFor(files, fileAliases), [files, fileAliases]);
  // "Move to file" targets per SOURCE file (a host's own file never appears).
  // Keyed by source_file, not section — tag-mode sections aren't files.
  const moveTargetsByFile = useMemo(
    () =>
      new Map(
        files.map((src) => [
          src,
          files
            .filter((f) => f !== src)
            .map((f) => ({ file: f, label: labels.get(f) ?? basename(f) })),
        ]),
      ),
    [files, labels],
  );

  const moveTo = (alias: string, targetFile: string) =>
    moveHost.mutate(
      { alias, targetFile },
      {
        onSuccess: () =>
          toast.success(
            `Moved ${alias} → ${labels.get(targetFile) ?? basename(targetFile)}`,
          ),
      },
    );

  // Inline group-label rename (double-click a header) — transient local state.
  const [editingFile, setEditingFile] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  // Raw-file viewer dialog: the loaded file currently shown (null = closed).
  const [viewFile, setViewFile] = useState<string | null>(null);
  // Pending single-click collapse toggle, deferred past the double-click
  // window so a rename double-click never toggles the group.
  const collapseTimer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (collapseTimer.current !== null) window.clearTimeout(collapseTimer.current);
    },
    [],
  );

  const cancelPendingCollapse = () => {
    if (collapseTimer.current !== null) {
      window.clearTimeout(collapseTimer.current);
      collapseTimer.current = null;
    }
  };

  /** Header click: keyboard activation toggles at once; mouse clicks wait out a possible double-click. */
  const headerClick = (file: string, detail: number) => {
    if (detail > 1) return; // second click of a double-click — rename handles it
    if (detail === 0) {
      // Keyboard (Enter/Space) — can't become a double-click, toggle now.
      toggleGroup(file);
      return;
    }
    cancelPendingCollapse();
    collapseTimer.current = window.setTimeout(() => {
      collapseTimer.current = null;
      toggleGroup(file);
    }, COLLAPSE_CLICK_DELAY_MS);
  };

  const beginEdit = (file: string) => {
    cancelPendingCollapse();
    setDraft(labels.get(file) ?? basename(file));
    setEditingFile(file);
  };

  /** Enter: trimmed value saves; empty — or identical to the AUTO label — clears the override. */
  const commitEdit = (file: string) => {
    const trimmed = draft.trim();
    const auto = autoLabels.get(file) ?? basename(file);
    setFileAlias(file, trimmed === "" || trimmed === auto ? null : trimmed);
    setEditingFile(null);
  };

  // If the scoped file vanished after a reload, fall back to All gracefully.
  useEffect(() => {
    if (data && fileScope && !data.files.includes(fileScope)) setFileScope(null);
  }, [data, fileScope, setFileScope]);
  const scope = fileScope && files.includes(fileScope) ? fileScope : null;

  const sections = useMemo(() => {
    const q = parseQuery(search);
    const scoped = scope ? hosts.filter((h) => h.source_file === scope) : hosts;
    const filtered = scoped.filter((h) => hostMatches(h, q));

    if (groupMode === "tag") {
      // Gmail-label model: a host appears under EVERY tag it carries; untagged
      // hosts pool at the bottom. Wildcard defaults are config structure, not
      // hosts — they only exist in the file view.
      const byTag = new Map<string, HostSummary[]>();
      const untagged: HostSummary[] = [];
      for (const h of filtered) {
        if (isWildcardOnly(h)) continue;
        if (h.tags.length === 0) {
          untagged.push(h);
          continue;
        }
        for (const t of h.tags) {
          const bucket = byTag.get(t);
          if (bucket) bucket.push(h);
          else byTag.set(t, [h]);
        }
      }
      const tagSections = [...byTag.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([tag, tagHosts]) => ({
          kind: "tag" as const,
          // Prefixed collapse/React key — never collides with a file path.
          file: `tag:${tag}`,
          name: tag,
          hosts: tagHosts,
          defaults: [] as HostSummary[],
        }));
      if (untagged.length > 0) {
        tagSections.push({
          kind: "tag" as const,
          file: "tag:",
          name: "Untagged",
          hosts: untagged,
          defaults: [],
        });
      }
      return tagSections;
    }

    // Group by source_file, preserving first-appearance order. A single-file
    // scope yields ONE headerless section (flat list).
    const byFile = new Map<string, HostSummary[]>();
    for (const h of filtered) {
      const bucket = byFile.get(h.source_file);
      if (bucket) bucket.push(h);
      else byFile.set(h.source_file, [h]);
    }
    if (scope && !byFile.has(scope)) byFile.set(scope, []);

    return [...byFile.entries()].map(([file, fileHosts]) => ({
      kind: "file" as const,
      file,
      // null name = flat list without a group header (single-file scope).
      name: scope ? null : (labels.get(file) ?? basename(file)),
      hosts: fileHosts.filter((h) => !isWildcardOnly(h)),
      // Wildcard-only blocks (`*`, `*.web`) are config DEFAULTS, not hosts —
      // demoted to a footer and excluded from every user-facing count.
      defaults: fileHosts.filter((h) => isWildcardOnly(h)),
    }));
  }, [hosts, search, scope, labels, groupMode]);

  // Render-order aliases — the coordinate system for Shift-click ranges.
  const visibleAliases = useMemo(
    () => sections.flatMap((s) => s.hosts.map((h) => h.alias)),
    [sections],
  );

  const rowClick =
    (alias: string) => (e: ReactMouseEvent<HTMLButtonElement>) => {
      if (e.metaKey || e.ctrlKey) {
        setCheckedAliases((prev) => {
          const next = new Set(prev);
          if (next.has(alias)) next.delete(alias);
          else next.add(alias);
          return next;
        });
        setSelectionAnchor(alias);
        return;
      }
      if (e.shiftKey) {
        setCheckedAliases(
          new Set(rangeBetween(visibleAliases, selectionAnchor, alias)),
        );
        return;
      }
      clearChecked();
      setSelectionAnchor(alias);
      setSelectedAlias(alias);
    };

  const batchMove = async (targetFile: string) => {
    const targets = [...checkedAliases];
    let moved = 0;
    for (const alias of targets) {
      const h = hosts.find((x) => x.alias === alias);
      if (!h || h.source_file === targetFile) continue;
      try {
        await moveHost.mutateAsync({ alias, targetFile });
        moved += 1;
      } catch {
        // Per-host failures already toast via the mutation; keep going.
      }
    }
    toast.success(
      `Moved ${moved}/${targets.length} → ${labels.get(targetFile) ?? basename(targetFile)}`,
    );
    clearChecked();
  };

  const batchTag = async (tag: string) => {
    const t = tag.trim();
    if (t === "") return;
    const targets = [...checkedAliases];
    let tagged = 0;
    for (const alias of targets) {
      const h = hosts.find((x) => x.alias === alias);
      if (!h || h.tags.includes(t)) continue;
      try {
        await setTags.mutateAsync({ alias, tags: [...h.tags, t] });
        tagged += 1;
      } catch {
        // Toasted by the mutation.
      }
    }
    toast.success(`Tagged ${tagged}/${targets.length} with #${t}`);
    clearChecked();
  };

  const batchRemove = async () => {
    const targets = [...checkedAliases];
    setBatchRemoveOpen(false);
    let removed = 0;
    for (const alias of targets) {
      try {
        await removeHost.mutateAsync({ alias });
        removed += 1;
        if (selectedAlias === alias) setSelectedAlias(null);
      } catch {
        // Toasted by the mutation.
      }
    }
    toast.success(`Removed ${removed}/${targets.length} hosts`);
    clearChecked();
  };

  // "N hosts" reflects the scoped + filtered CONNECTABLE count (no wildcards).
  const hostCount = sections.reduce((n, s) => n + s.hosts.length, 0);
  const visibleRows = sections.reduce((n, s) => n + s.hosts.length + s.defaults.length, 0);
  // When a search is active, force-expand all groups so results are never hidden.
  const searchActive = search.trim().length > 0;

  // ── Drag-to-reorder (within ONE source file) ──────────────────────────────
  // `drag` is the source row; `dropGap` the insertion gap, both as indices into
  // that file's CONCRETE host list (`section.hosts` — wildcard DEFAULTS rows
  // are pinned and excluded). A filtered list's order is meaningless to
  // persist, so dragging is disabled entirely while searching — and in tag
  // view, where list position has no file position to map back to.
  const canReorder = !searchActive && groupMode === "file";
  const [drag, setDrag] = useState<{ file: string; index: number; alias: string } | null>(
    null,
  );
  const [dropGap, setDropGap] = useState<{ file: string; index: number } | null>(null);
  // Cross-file drag target: the whole group highlights (the move appends at the
  // file's end — there is no meaningful insertion position to point at).
  const [dropFile, setDropFile] = useState<string | null>(null);

  const clearDrag = () => {
    setDrag(null);
    setDropGap(null);
    setDropFile(null);
  };

  /** The insertion gap (0..n) a pointer position maps to: above or below row `index`. */
  const gapFor = (e: DragEvent<HTMLElement>, index: number) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return e.clientY < rect.top + rect.height / 2 ? index : index + 1;
  };

  const rowDragStart =
    (file: string, index: number, alias: string) => (e: DragEvent<HTMLElement>) => {
      e.dataTransfer.effectAllowed = "move";
      // Some WebViews won't start a drag without data; the source row itself is
      // tracked in React state, not in the dataTransfer payload.
      e.dataTransfer.setData("text/plain", "");
      setDrag({ file, index, alias });
    };

  /** Container-level cross-file drop: dragging onto ANOTHER file group moves the host there. */
  const groupDragOver = (section: { kind: string; file: string }) => (e: DragEvent<HTMLElement>) => {
    if (!drag || section.kind !== "file") return;
    if (drag.file === section.file) {
      if (dropFile !== null) setDropFile(null);
      return; // row handlers own same-file insertion gaps
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    if (dropFile !== section.file) setDropFile(section.file);
  };

  const groupDrop = (section: { kind: string; file: string }) => (e: DragEvent<HTMLElement>) => {
    if (!drag || section.kind !== "file" || drag.file === section.file) return;
    e.preventDefault();
    const alias = drag.alias;
    const target = section.file;
    clearDrag();
    moveTo(alias, target);
  };

  const rowDragOver = (file: string, index: number) => (e: DragEvent<HTMLElement>) => {
    if (!drag) return;
    if (drag.file !== file) {
      // Cross-group target: NOT preventDefault'ed → native no-drop cursor.
      setDropGap(null);
      return;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    const gap = gapFor(e, index);
    // The gaps hugging the source row are no-ops — show no indicator there.
    const next =
      gap === drag.index || gap === drag.index + 1 ? null : { file, index: gap };
    setDropGap((prev) =>
      prev?.file === next?.file && prev?.index === next?.index ? prev : next,
    );
  };

  const rowDrop = (file: string, index: number) => (e: DragEvent<HTMLElement>) => {
    if (!drag || drag.file !== file) return;
    e.preventDefault();
    const gap = gapFor(e, index);
    clearDrag();
    if (gap === drag.index || gap === drag.index + 1) return; // dropped in place
    // Full document-order host list of the file (incl. wildcard DEFAULTS) —
    // the backend order must be exhaustive or unnamed blocks sink to the end.
    const fileHosts = hosts.filter((h) => h.source_file === file);
    reorderHosts.mutate({ file, order: buildNewOrder(fileHosts, drag.index, gap) });
  };

  const connectTo = (alias: string) => {
    // Per-host terminal override wins; new-tab gating follows the RESOLVED terminal.
    const resolved = resolveTerminal(alias, hostTerminals, terminalId);
    connect.mutate({
      alias,
      terminalOverride: resolved,
      newTab: effectiveNewTab(newTabConnect, resolved, terminals.data ?? []),
    });
  };

  // A running index across all rows so the staggered enter animation reads as a
  // single cascade rather than restarting per group.
  let rowIndex = -1;
  const nextDelay = () => {
    rowIndex += 1;
    return `${Math.min(rowIndex, 16) * 22}ms`;
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-1.5 border-b p-2">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            id={SEARCH_INPUT_ID}
            type="search"
            placeholder="Search…  #tag @user"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search hosts"
            className="h-7 pl-8 text-sm"
          />
        </div>
        {/* File-scope switcher: All files, or exactly one loaded config file. */}
        <div className="flex items-center gap-1.5">
          <Select
            value={scope ?? ALL_FILES}
            onValueChange={(v) => setFileScope(v === ALL_FILES ? null : v)}
          >
            <SelectTrigger
              size="sm"
              aria-label="File scope"
              title={scope ?? "All files"}
              className="h-6 min-w-0 flex-1 border-none bg-transparent px-1.5 text-xs text-muted-foreground shadow-none hover:bg-muted/60 hover:text-foreground dark:bg-transparent dark:hover:bg-muted/60"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_FILES} className="text-xs">
                All files
              </SelectItem>
              {files.map((f) => (
                <SelectItem key={f} value={f} title={f} className="font-mono text-xs">
                  {labels.get(f) ?? basename(f)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {scope && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-6 shrink-0 text-muted-foreground"
              aria-label={`View file ${scope}`}
              title={`View file — ${scope}`}
              onClick={() => setViewFile(scope)}
            >
              <FileText className="size-3.5" />
            </Button>
          )}
          {/* Grouping dimension: by source file (default) or by tag. */}
          <div
            role="group"
            aria-label="Group hosts by"
            className="flex shrink-0 items-center gap-0.5"
          >
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-pressed={groupMode === "file"}
              title="Group by file"
              onClick={() => setGroupMode("file")}
              className={cn(
                "size-6 text-muted-foreground",
                groupMode === "file" && "bg-muted/70 text-foreground",
              )}
            >
              <FileText className="size-3.5" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-pressed={groupMode === "tag"}
              title="Group by tag"
              onClick={() => setGroupMode("tag")}
              className={cn(
                "size-6 text-muted-foreground",
                groupMode === "tag" && "bg-muted/70 text-foreground",
              )}
            >
              <Tags className="size-3.5" />
            </Button>
          </div>
          <span className="shrink-0 pr-1 font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
            {isLoading ? "…" : `${hostCount} ${hostCount === 1 ? "host" : "hosts"}`}
          </span>
        </div>
      </div>

      {/*
       * Plain overflow scroller (NOT Radix ScrollArea): its viewport wraps
       * children in a `display: table` div that breaks `position: sticky`,
       * which the group headers rely on. macOS overlay scrollbars keep this
       * visually identical.
       */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="p-1.5 pt-0">
          {isLoading ? (
            <HostListSkeleton />
          ) : visibleRows === 0 ? (
            hosts.length === 0 ? (
              <EmptyHosts />
            ) : searchActive ? (
              <p className="px-2 py-10 text-center text-sm text-muted-foreground">
                No hosts match{" "}
                <span className="font-mono text-foreground">“{search.trim()}”</span>.
              </p>
            ) : (
              <p className="px-2 py-10 text-center text-sm text-muted-foreground">
                No hosts in{" "}
                <span className="font-mono text-foreground">
                  {scope ? (labels.get(scope) ?? basename(scope)) : "this file"}
                </span>
                .
              </p>
            )
          ) : (
            sections.map((section) => {
              const isCollapsed =
                section.name !== null &&
                !searchActive &&
                collapsedGroups.includes(section.file);
              const alias = fileAliases[section.file];
              const isEditing = editingFile === section.file;
              return (
                <div
                  key={section.file}
                  className={cn(
                    "mb-3 rounded-md transition-shadow last:mb-0",
                    dropFile === section.file && "bg-primary/5 ring-1 ring-primary/40",
                  )}
                  onDragOver={groupDragOver(section)}
                  onDrop={groupDrop(section)}
                >
                  {section.name !== null && section.kind === "tag" && (
                    /* Tag headers only collapse — no rename, no file menu. */
                    <button
                      type="button"
                      onClick={() => toggleGroup(section.file)}
                      className="sidebar-sticky-header sticky top-0 z-10 flex w-full items-center justify-between rounded-sm px-2 py-1.5 select-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none cursor-default"
                      aria-expanded={!isCollapsed}
                    >
                      <span className="flex min-w-0 items-center gap-1">
                        <ChevronRight
                          className={cn(
                            "size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
                            !isCollapsed && "rotate-90",
                          )}
                          aria-hidden
                        />
                        <span className="truncate text-[0.6875rem] font-semibold tracking-[0.08em] text-muted-foreground uppercase">
                          {section.name}
                        </span>
                      </span>
                      <span className="font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                        {section.hosts.length}
                      </span>
                    </button>
                  )}
                  {section.name !== null &&
                    section.kind === "file" &&
                    (isEditing ? (
                      /*
                       * Inline rename: the header's label swaps for a tiny mono
                       * input pre-filled with the CURRENT display label. Enter
                       * saves (empty or auto-identical clears the override),
                       * Esc/blur cancels. A div, not the collapse button —
                       * collapse is suspended while editing.
                       */
                      <div className="sidebar-sticky-header sticky top-0 z-10 flex w-full items-center justify-between rounded-sm px-2 py-1 select-none">
                        <span className="flex min-w-0 flex-1 items-center gap-1">
                          <ChevronRight
                            className={cn(
                              "size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
                              !isCollapsed && "rotate-90",
                            )}
                            aria-hidden
                          />
                          <Input
                            autoFocus
                            value={draft}
                            onChange={(e) => setDraft(e.target.value)}
                            onFocus={(e) => e.currentTarget.select()}
                            onBlur={() => setEditingFile(null)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                commitEdit(section.file);
                              } else if (e.key === "Escape") {
                                e.stopPropagation();
                                setEditingFile(null);
                              }
                            }}
                            aria-label={`Display name for ${section.file} — press Enter to save, or clear the field to restore the automatic label`}
                            title="Enter saves · Esc cancels · empty restores the automatic label"
                            className="h-5 min-w-0 flex-1 rounded-sm px-1 text-[0.6875rem] font-mono md:text-[0.6875rem]"
                          />
                        </span>
                        <span className="pl-2 font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                          {section.hosts.length}
                        </span>
                      </div>
                    ) : (
                      /*
                       * The sticky/relative wrapper lets the View-file button sit
                       * as a SIBLING overlay (never nested in the header button),
                       * so collapse single-click and rename double-click are
                       * completely untouched by it.
                       */
                      <ContextMenu>
                        <ContextMenuTrigger asChild>
                          <div className="group/header sidebar-sticky-header sticky top-0 z-10 rounded-sm">
                            <button
                              type="button"
                              onClick={(e) => headerClick(section.file, e.detail)}
                              onDoubleClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                beginEdit(section.file);
                              }}
                              className="flex w-full items-center justify-between rounded-sm px-2 py-1.5 select-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none cursor-default"
                              title={
                                alias
                                  ? `${alias} — ${section.file} (double-click to rename)`
                                  : `${section.file} (double-click to rename)`
                              }
                              aria-expanded={!isCollapsed}
                            >
                              <span className="flex min-w-0 items-center gap-1">
                                <ChevronRight
                                  className={cn(
                                    "size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
                                    !isCollapsed && "rotate-90",
                                  )}
                                  aria-hidden
                                />
                                <span className="truncate text-[0.6875rem] font-semibold tracking-[0.08em] text-muted-foreground uppercase">
                                  {section.name}
                                </span>
                              </span>
                              <span className="font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                                {section.hosts.length}
                              </span>
                            </button>
                            {/* Raw-file viewer — revealed on header hover, next to the count. */}
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              aria-label={`View file ${section.file}`}
                              title={`View file — ${section.file}`}
                              onClick={() => setViewFile(section.file)}
                              onDoubleClick={(e) => e.stopPropagation()}
                              // inset-y centering (no translate) — see the row Play
                              // button for why translate-based centering breaks clicks.
                              className="absolute inset-y-0 right-6 my-auto size-5 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover/header:opacity-100"
                            >
                              <FileText className="size-3" />
                            </Button>
                          </div>
                        </ContextMenuTrigger>
                        <ContextMenuContent>
                          <ContextMenuItem
                            onSelect={() => {
                              setAddHostTargetFile(section.file);
                              setAddHostOpen(true);
                            }}
                          >
                            <Plus />
                            New host in this file
                          </ContextMenuItem>
                          <ContextMenuSeparator />
                          <ContextMenuItem onSelect={() => setViewFile(section.file)}>
                            <FileText />
                            View file
                          </ContextMenuItem>
                          <ContextMenuItem onSelect={() => beginEdit(section.file)}>
                            <Pencil />
                            Rename label
                          </ContextMenuItem>
                        </ContextMenuContent>
                      </ContextMenu>
                    ))}
                  {!isCollapsed && (
                    <>
                      {section.defaults.length > 0 && (
                        <>
                          <DefaultsLabel />
                          <ul className="space-y-px">
                            {section.defaults.map((host) => (
                              <HostRow
                                key={`${host.source_file}::${host.alias}`}
                                host={host}
                                active={host.alias === selectedAlias}
                                delay={nextDelay()}
                                variant="defaults"
                                onSelect={() => setSelectedAlias(host.alias)}
                                onDragOver={() => setDropGap(null)}
                              />
                            ))}
                          </ul>
                        </>
                      )}
                      {section.hosts.length > 0 && (
                        <ul
                          className={cn(
                            "space-y-px",
                            section.defaults.length > 0 && "mt-1.5",
                          )}
                        >
                          {section.hosts.map((host, i) => (
                            <HostRow
                              key={`${host.source_file}::${host.alias}`}
                              host={host}
                              active={host.alias === selectedAlias}
                              delay={nextDelay()}
                              variant="host"
                              onSelect={rowClick(host.alias)}
                              checked={checkedAliases.has(host.alias)}
                              onConnect={() => connectTo(host.alias)}
                              onDeployKey={() => setDeployKeyAlias(host.alias)}
                              moveTargets={moveTargetsByFile.get(host.source_file) ?? []}
                              onMoveTo={(f) => moveTo(host.alias, f)}
                              onRemove={() => setRemoveTarget(host.alias)}
                              showTags={showHostTags && groupMode === "file"}
                              // Draggable when reordering OR a cross-file move
                              // is possible (single-host files can drag out).
                              draggable={
                                canReorder && (section.hosts.length > 1 || files.length > 1)
                              }
                              dragging={drag?.file === section.file && drag.index === i}
                              indicator={
                                dropGap?.file === section.file
                                  ? dropGap.index === i
                                    ? "before"
                                    : dropGap.index === i + 1 &&
                                        i === section.hosts.length - 1
                                      ? "after"
                                      : null
                                  : null
                              }
                              onDragStart={rowDragStart(section.file, i, host.alias)}
                              onDragOver={rowDragOver(section.file, i)}
                              onDrop={rowDrop(section.file, i)}
                              onDragEnd={clearDrag}
                            />
                          ))}
                        </ul>
                      )}
                    </>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Raw config-file viewer (read-only, lazy fetch while open). */}
      {/* Batch action bar — appears while any rows are checked (⌘/Shift-click). */}
      {checkedAliases.size > 0 && (
        <div className="shrink-0 space-y-1.5 border-t bg-background p-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground select-none">
              {checkedAliases.size} selected
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-5 text-muted-foreground"
              aria-label="Clear selection"
              title="Clear selection (Esc)"
              onClick={clearChecked}
            >
              <X className="size-3.5" />
            </Button>
          </div>
          {tagDraft !== null ? (
            <div className="flex items-center gap-1.5">
              <Input
                autoFocus
                value={tagDraft}
                onChange={(e) => setTagDraft(e.target.value)}
                placeholder="tag name"
                aria-label="Tag to add to the selected hosts"
                className="h-7 flex-1 font-mono text-sm"
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void batchTag(tagDraft);
                  } else if (e.key === "Escape") {
                    e.stopPropagation();
                    setTagDraft(null);
                  }
                }}
              />
              <Button
                type="button"
                size="sm"
                className="h-7"
                disabled={tagDraft.trim() === "" || setTags.isPending}
                onClick={() => void batchTag(tagDraft)}
              >
                Apply
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-7 flex-1"
                    disabled={files.length < 2 || moveHost.isPending}
                  >
                    <FolderInput className="size-3.5" /> Move to
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  {files.map((f) => (
                    <DropdownMenuItem key={f} onSelect={() => void batchMove(f)}>
                      {labels.get(f) ?? basename(f)}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 flex-1"
                onClick={() => setTagDraft("")}
              >
                <Tags className="size-3.5" /> Add tag
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 flex-1 text-destructive hover:text-destructive"
                disabled={removeHost.isPending}
                onClick={() => setBatchRemoveOpen(true)}
              >
                <Trash2 className="size-3.5" /> Remove…
              </Button>
            </div>
          )}
        </div>
      )}

      <FileViewDialog
        path={viewFile}
        label={viewFile ? (labels.get(viewFile) ?? basename(viewFile)) : undefined}
        onOpenChange={(open) => {
          if (!open) setViewFile(null);
        }}
      />

      {/* Batch Remove… confirmation. */}
      <AlertDialog open={batchRemoveOpen} onOpenChange={setBatchRemoveOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Remove {checkedAliases.size}{" "}
              {checkedAliases.size === 1 ? "host" : "hosts"}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-mono">
                {[...checkedAliases].slice(0, 5).join(", ")}
                {checkedAliases.size > 5 ? ", …" : ""}
              </span>{" "}
              — deletes each Host block from its config file. Backups are
              written first.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => void batchRemove()}>
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Row-menu Remove… confirmation. Backend writes a backup before the edit. */}
      <AlertDialog
        open={removeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRemoveTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Remove <span className="font-mono">{removeTarget}</span>?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Deletes this Host block from its config file. A backup is written
              first, so it can be restored from Backup history.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                const alias = removeTarget;
                if (alias === null) return;
                setRemoveTarget(null);
                removeHost.mutate(
                  { alias },
                  {
                    onSuccess: () => {
                      toast.success(`Removed ${alias}`);
                      if (selectedAlias === alias) setSelectedAlias(null);
                    },
                  },
                );
              }}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** Skeleton placeholder rows while the host list loads. */
function HostListSkeleton() {
  return (
    <div className="space-y-4 pt-1.5" aria-hidden>
      {[0, 1].map((g) => (
        <div key={g}>
          <Skeleton className="mx-2 mb-2 h-3 w-20" />
          <div className="space-y-px">
            {[0, 1, 2].map((r) => (
              <div key={r} className="flex h-7 items-center gap-2 px-2">
                <Skeleton className="size-3.5 shrink-0 rounded" />
                <Skeleton className="h-3 w-2/5" />
                <Skeleton className="ml-auto h-2.5 w-1/3" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/** Friendly empty state when no hosts exist at all. */
function EmptyHosts() {
  return (
    <div className="flex flex-col items-center gap-3 px-4 py-12 text-center select-none">
      <div className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground ring-1 ring-border">
        <ServerOff className="size-5" />
      </div>
      <div className="space-y-0.5">
        <p className="text-sm font-medium">No hosts yet</p>
        <p className="text-xs text-muted-foreground">
          Add your first SSH host to get started.
        </p>
      </div>
      <AddHostDialog variant="labeled" />
    </div>
  );
}

export default HostList;
