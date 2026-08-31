import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  useForm,
  useFieldArray,
  useWatch,
  Controller,
  type Control,
  type Resolver,
} from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import {
  Trash2,
  Plus,
  MoreVertical,
  RotateCcw,
  Save,
  Copy,
  CopyPlus,
  Check,
  ChevronDown,
  FolderInput,
  TerminalSquare,
  Pencil,
  X,
  Eye,
  Upload,
  KeyRound,
  FolderOpen,
} from "lucide-react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";

import type { HostDetail } from "@/bindings/HostDetail";
import type { HostOption } from "@/bindings/HostOption";
import {
  FIELD_DEFS,
  FIRST_CLASS_KEYS,
  computeChanges,
  type FieldDef,
} from "@/lib/hostFields";
import {
  useHostDetail,
  useHostsQuery,
  usePlatform,
  useSaveHost,
  useSetTags,
  useSetOptionEnabled,
  useRemoveHost,
  useRenameHost,
  useMoveHost,
  useDuplicateHost,
  useConnect,
  useTerminals,
  useHasHostPassword,
  useRevealHostPassword,
  useSetHostPassword,
  useDeleteHostPassword,
  useKeys,
  useKeyHygiene,
} from "@/lib/queries";
import { toTildeSshPath } from "@/lib/identity-file";
import { useUiStore } from "@/stores/ui";
import { useSettingsStore } from "@/stores/settings";
import { effectiveNewTab, resolveTerminal } from "@/lib/settings-logic";
import { isWildcardOnly, labelsFor } from "@/lib/host-display";
import { basename, cn } from "@/lib/utils";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Section, SettingsGroup } from "@/components/settings-primitives";
import { HostIntelligence } from "@/components/HostIntelligence";

const GROUPS = ["Connection", "Authentication", "Forwarding", "Reliability"] as const;

const formSchema = z.object({
  firstClass: z.record(z.string(), z.string()),
  advanced: z.array(
    z.object({
      keyword: z.string(),
      value: z.string(),
    }),
  ),
});

type FormValues = z.infer<typeof formSchema>;

/**
 * `zodResolver` is still used for runtime validation, but its TS overloads are
 * skewed against the installed zod 4.4.x core (a known `version.minor` literal
 * mismatch in @hookform/resolvers 5.4.0). We narrow the result back to the
 * precise `Resolver<FormValues>` so the form stays fully typed.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const formResolver = zodResolver(formSchema as any) as Resolver<FormValues>;

/** Build the form's default values from a host detail's *enabled* options only. */
function buildDefaults(detail: HostDetail): FormValues {
  const enabledOpts = detail.options.filter((o) => o.enabled);

  const firstClass: Record<string, string> = {};
  for (const def of FIELD_DEFS) {
    const key = def.keyword.toLowerCase();
    const match = enabledOpts.find((o) => o.keyword.toLowerCase() === key);
    firstClass[key] = match ? match.value : "";
  }

  const advanced = enabledOpts
    .filter((o) => !FIRST_CLASS_KEYS.has(o.keyword.toLowerCase()))
    .map((o) => ({ keyword: o.keyword, value: o.value }));

  return { firstClass, advanced };
}

export interface HostEditorProps {
  alias: string;
}

export function HostEditor({ alias }: HostEditorProps) {
  const { data: detail, isLoading, isError } = useHostDetail(alias);
  const platform = usePlatform();
  const isMac = platform.data === "macos";

  const saveHost = useSaveHost();
  const setTags = useSetTags();
  const setOptionEnabled = useSetOptionEnabled();
  const removeHost = useRemoveHost();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);

  if (isLoading) {
    return <HostEditorSkeleton />;
  }
  if (isError || !detail) {
    return (
      <p className="text-sm text-muted-foreground">
        Could not load host <code className="font-mono">{alias}</code>.
      </p>
    );
  }

  return (
    <HostEditorForm
      key={detail.alias}
      detail={detail}
      isMac={isMac}
      saving={saveHost.isPending}
      onSave={(changes) =>
        saveHost.mutate(
          { alias: detail.alias, changes },
          { onSuccess: () => toast.success(`Saved ${detail.alias}`) },
        )
      }
      onSetTags={(tags) =>
        setTags.mutate(
          { alias: detail.alias, tags },
          { onSuccess: () => toast.success(`Updated tags for ${detail.alias}`) },
        )
      }
      onEnableOption={(keyword, index) =>
        setOptionEnabled.mutate(
          { alias: detail.alias, keyword, index, enabled: true },
          { onSuccess: () => toast.success(`Enabled ${keyword}`) },
        )
      }
      onRemove={() =>
        removeHost.mutate(
          { alias: detail.alias },
          {
            onSuccess: () => {
              setSelectedAlias(null);
              toast.success(`Removed ${detail.alias}`);
            },
          },
        )
      }
      removing={removeHost.isPending}
    />
  );
}

interface HostEditorFormProps {
  detail: HostDetail;
  isMac: boolean;
  saving: boolean;
  removing: boolean;
  onSave: (changes: ReturnType<typeof computeChanges>) => void;
  onSetTags: (tags: string[]) => void;
  /** `index` is the option's position in `HostDetail.options` (document order). */
  onEnableOption: (keyword: string, index: number) => void;
  onRemove: () => void;
}

function HostEditorForm({
  detail,
  isMac,
  saving,
  removing,
  onSave,
  onSetTags,
  onEnableOption,
  onRemove,
}: HostEditorFormProps) {
  const enabledOpts = useMemo(
    () => detail.options.filter((o) => o.enabled),
    [detail],
  );
  // Disabled rows keep their ORIGINAL index into detail.options: the backend
  // addresses the line by that index (a filtered-array index would be wrong).
  const disabledOpts = useMemo(
    () =>
      detail.options
        .map((option, index) => ({ option, index }))
        .filter(({ option }) => !option.enabled),
    [detail],
  );

  const defaults = useMemo(() => buildDefaults(detail), [detail]);

  const {
    control,
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { isDirty },
  } = useForm<FormValues>({
    resolver: formResolver,
    defaultValues: defaults,
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: "advanced",
  });

  // Re-seed the form whenever the underlying detail changes (re-select, save,
  // toggling a disabled option back on, etc.).
  useEffect(() => {
    reset(defaults);
  }, [defaults, reset]);

  // Tags side-form state (independent of the option form).
  const [tags, setTagsValue] = useState(detail.tags.join(", "));
  useEffect(() => {
    setTagsValue(detail.tags.join(", "));
  }, [detail]);

  const onSubmit = handleSubmit((values) => {
    const desired: { keyword: string; value: string }[] = [];

    for (const def of FIELD_DEFS) {
      const raw = values.firstClass[def.keyword.toLowerCase()] ?? "";
      const value = raw.trim();
      if (value !== "") desired.push({ keyword: def.keyword, value });
    }
    for (const entry of values.advanced) {
      const keyword = entry.keyword.trim();
      if (keyword !== "") desired.push({ keyword, value: entry.value });
    }

    const changes = computeChanges(enabledOpts, desired);
    if (changes.length === 0) {
      toast("No changes to save");
      return;
    }
    onSave(changes);
  });

  return (
    <div className="space-y-6">
      {/*
       * Editor header — alias as the host identity with patterns/source below.
       */}
      <div className="group flex items-start justify-between gap-3 select-none">
        <HostHeaderTitle detail={detail} />
        <HostActions detail={detail} removing={removing} onRemove={onRemove} />
      </div>

      {/*
       * Single stacked column: grouped sections followed by the config preview.
       */}
      <div className="space-y-6">
          <form onSubmit={onSubmit} id="host-editor-form" className="space-y-6">
        {GROUPS.map((g) => {
          const defs = FIELD_DEFS.filter((d) => d.group === g).filter(
            (d) => !d.macOnly || isMac,
          );
          if (defs.length === 0) return null;
          return (
            <Section key={g} title={g}>
              <SettingsGroup>
                {defs.map((def) => (
                  <FieldControl
                    key={def.keyword}
                    def={def}
                    control={control}
                    register={register}
                    setValue={setValue}
                  />
                ))}
              </SettingsGroup>
            </Section>
          );
        })}

        {/* Advanced — raw keyword/value pairs. */}
        <Section
          title="Advanced"
          action={
            <Button
              type="button"
              variant="ghost"
              size="xs"
              className="h-6 -mr-1 text-muted-foreground"
              onClick={() => append({ keyword: "", value: "" })}
            >
              <Plus className="size-3.5" /> Add option
            </Button>
          }
        >
          {fields.length === 0 ? (
            <SettingsGroup>
              <p className="px-3 py-2.5 text-sm text-muted-foreground">
                No advanced options. Add raw keyword/value pairs.
              </p>
            </SettingsGroup>
          ) : (
            <SettingsGroup>
              {fields.map((field, index) => (
                <div key={field.id} className="flex items-center gap-2 px-3 py-1.5">
                  <Input
                    className="h-7 flex-1 border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
                    placeholder="Keyword"
                    aria-label="Keyword"
                    {...register(`advanced.${index}.keyword` as const)}
                  />
                  <Input
                    className="h-7 flex-[2] border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
                    placeholder="Value"
                    aria-label="Value"
                    {...register(`advanced.${index}.value` as const)}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-7 shrink-0 text-muted-foreground"
                    aria-label="Remove option"
                    onClick={() => remove(index)}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              ))}
            </SettingsGroup>
          )}
        </Section>
          </form>

          {/* Tags — settings-style inset row: label left, value (mono) right. */}
          <Section title="Tags">
            <SettingsGroup>
              <div className="flex items-center justify-between gap-4 px-3 py-2">
                <Label htmlFor="host-tags" className="shrink-0 text-sm font-normal text-muted-foreground">
                  Tags
                </Label>
                <div className="flex max-w-[62%] flex-1 items-center gap-1.5">
                  <Input
                    id="host-tags"
                    value={tags}
                    onChange={(e) => setTagsValue(e.target.value)}
                    placeholder="comma, separated"
                    className="h-7 border-0 bg-transparent px-2 text-right font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
                  />
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="h-7 shrink-0"
                    onClick={() =>
                      onSetTags(
                        tags
                          .split(",")
                          .map((t) => t.trim())
                          .filter(Boolean),
                      )
                    }
                  >
                    Apply
                  </Button>
                </div>
              </div>
            </SettingsGroup>
          </Section>

          {disabledOpts.length > 0 && (
            <Section
              title="Disabled options"
              description="Commented-out lines. Toggle on to re-enable, then edit above."
            >
              <SettingsGroup>
                {disabledOpts.map(({ option, index }) => (
                  <DisabledOptionRow
                    key={`${option.keyword}-${index}`}
                    option={option}
                    onEnable={() => onEnableOption(option.keyword, index)}
                  />
                ))}
              </SettingsGroup>
            </Section>
          )}

          {/* Keychain-backed password — not an ssh_config field, saved on its own. */}
          {!isWildcardOnly(detail) && <HostPasswordSection alias={detail.alias} />}

          {/* Read-only per-host intelligence: key hygiene, ProxyJump chain, ssh -G. */}
          <HostIntelligence alias={detail.alias} />

          {/* Config preview — always-visible at the bottom of the column. */}
          <ConfigInspector alias={detail.alias} control={control} />
        </div>

      {/* Sticky save bar: appears only when the option form is dirty. */}
      {isDirty && (
        <div className="animate-save-bar fixed inset-x-0 bottom-0 left-64 z-30 border-t bg-background/85 backdrop-blur-md">
          <div className="flex items-center justify-between gap-3 px-6 py-2.5 select-none">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="size-1.5 rounded-full bg-primary" aria-hidden />
              Unsaved changes
            </span>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7"
                onClick={() => reset(defaults)}
                disabled={saving}
              >
                <RotateCcw className="size-4" /> Discard
              </Button>
              <Button type="submit" size="sm" className="h-7" form="host-editor-form" disabled={!isDirty || saving}>
                <Save className="size-4" /> {saving ? "Saving…" : "Save"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** Radix items can't carry an empty value — sentinel for "no per-host override". */
const APP_DEFAULT_TERMINAL = "__app_default__";

/**
 * Editor header actions: a split Connect control (main button launches with the
 * RESOLVED terminal — per-host override, else the global preference; the
 * chevron edits the override) plus the ⋯ menu (Duplicate / Move to file /
 * Remove). Owns its own mutations so the form component stays presentational.
 */
function HostActions({
  detail,
  removing,
  onRemove,
}: {
  detail: HostDetail;
  removing: boolean;
  onRemove: () => void;
}) {
  const connect = useConnect();
  const moveHost = useMoveHost();
  const duplicateHost = useDuplicateHost();
  const terminals = useTerminals();
  const { data } = useHostsQuery();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const setDeployKeyAlias = useUiStore((s) => s.setDeployKeyAlias);
  // With an IdentityFile already configured the host is presumably keyed —
  // deploy demotes from a headline button to a ⋯ menu item ("deploy another").
  const hygiene = useKeyHygiene(detail.alias);
  const deployable = !isWildcardOnly(detail);
  const hasExplicitKey = hygiene.data?.explicit === true;
  const terminalId = useSettingsStore((s) => s.terminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const hostTerminals = useSettingsStore((s) => s.hostTerminals);
  const setHostTerminal = useSettingsStore((s) => s.setHostTerminal);
  const fileAliases = useSettingsStore((s) => s.fileAliases);

  // Move targets: every OTHER loaded file, shown under its sidebar display label.
  const files = useMemo(() => data?.files ?? [], [data]);
  const labels = useMemo(() => labelsFor(files, fileAliases), [files, fileAliases]);
  const otherFiles = files.filter((f) => f !== detail.source_file);
  const labelOf = (f: string) => labels.get(f) ?? basename(f);

  // New-tab gating must follow the terminal that will ACTUALLY launch.
  const resolved = resolveTerminal(detail.alias, hostTerminals, terminalId);
  const onConnect = () =>
    connect.mutate({
      alias: detail.alias,
      terminalOverride: resolved,
      newTab: effectiveNewTab(newTabConnect, resolved, terminals.data ?? []),
    });

  // The duplicate prompt lives OUTSIDE the dropdown (the menu unmounts on select).
  const [dupOpen, setDupOpen] = useState(false);
  const [dupAlias, setDupAlias] = useState("");

  const submitDuplicate = (e: React.FormEvent) => {
    e.preventDefault();
    const newAlias = dupAlias.trim();
    if (newAlias === "" || duplicateHost.isPending) return;
    duplicateHost.mutate(
      { alias: detail.alias, newAlias },
      {
        onSuccess: () => {
          setDupOpen(false);
          setSelectedAlias(newAlias);
          toast.success(`Duplicated as ${newAlias}`);
        },
        // Validation/collision errors surface via the mutation's error toast;
        // the dialog stays open so the alias can be corrected.
      },
    );
  };

  return (
    <div className="flex shrink-0 items-center gap-1.5">
      {/* Split Connect: main action + per-host terminal picker. */}
      <div className="flex items-center">
        <Button
          type="button"
          size="sm"
          className="h-7 rounded-r-none"
          onClick={onConnect}
          disabled={connect.isPending}
        >
          <TerminalSquare className="size-4" /> Connect
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              size="icon"
              className="h-7 w-5 rounded-l-none border-l border-primary-foreground/25 px-0"
              aria-label="Choose terminal for this host"
            >
              <ChevronDown className="size-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
              Open connection in
            </DropdownMenuLabel>
            <DropdownMenuRadioGroup
              value={hostTerminals[detail.alias] ?? APP_DEFAULT_TERMINAL}
              onValueChange={(v) =>
                setHostTerminal(detail.alias, v === APP_DEFAULT_TERMINAL ? null : v)
              }
            >
              <DropdownMenuRadioItem value={APP_DEFAULT_TERMINAL}>
                App default
              </DropdownMenuRadioItem>
              {(terminals.data ?? []).map((t) => (
                <DropdownMenuRadioItem key={t.id} value={t.id}>
                  {t.label}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Visible per-host deploy entry — but only while the host has no
          IdentityFile yet. Once keyed, deploying again is a rare action and
          lives in the ⋯ menu instead of shouting from the header. */}
      {deployable && hygiene.isSuccess && !hasExplicitKey && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7"
          onClick={() => setDeployKeyAlias(detail.alias)}
        >
          <Upload className="size-4" /> Deploy key
        </Button>
      )}

      <AlertDialog>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Host actions"
              disabled={removing}
            >
              <MoreVertical className="size-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            {deployable && hasExplicitKey && (
              <DropdownMenuItem onSelect={() => setDeployKeyAlias(detail.alias)}>
                <Upload className="size-4" /> Deploy another key…
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              onSelect={() => {
                setDupAlias(`${detail.alias}-copy`);
                setDupOpen(true);
              }}
            >
              <CopyPlus className="size-4" /> Duplicate host…
            </DropdownMenuItem>
            {otherFiles.length > 0 && (
              <DropdownMenuSub>
                <DropdownMenuSubTrigger>
                  <FolderInput className="size-4 text-muted-foreground" /> Move to file
                </DropdownMenuSubTrigger>
                <DropdownMenuSubContent className="max-w-64">
                  {otherFiles.map((f) => (
                    <DropdownMenuItem
                      key={f}
                      title={f}
                      disabled={moveHost.isPending}
                      onSelect={() =>
                        moveHost.mutate(
                          { alias: detail.alias, targetFile: f },
                          {
                            onSuccess: () =>
                              toast.success(`Moved ${detail.alias} to ${labelOf(f)}`),
                          },
                        )
                      }
                    >
                      <span className="truncate font-mono text-xs">{labelOf(f)}</span>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuSubContent>
              </DropdownMenuSub>
            )}
            <DropdownMenuSeparator />
            <AlertDialogTrigger asChild>
              <DropdownMenuItem variant="destructive">
                <Trash2 className="size-4" /> Remove host
              </DropdownMenuItem>
            </AlertDialogTrigger>
          </DropdownMenuContent>
        </DropdownMenu>

        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Remove “<span className="font-mono">{detail.alias}</span>”?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This deletes the host block from{" "}
              <span className="font-mono">{basename(detail.source_file)}</span>.
              This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={onRemove}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Duplicate prompt — minimal: one alias field, prefilled `<alias>-copy`. */}
      <Dialog open={dupOpen} onOpenChange={setDupOpen}>
        <DialogContent className="sm:max-w-sm">
          <form onSubmit={submitDuplicate}>
            <DialogHeader>
              <DialogTitle>
                Duplicate “<span className="font-mono">{detail.alias}</span>”
              </DialogTitle>
              <DialogDescription>
                Copies the whole block within{" "}
                <span className="font-mono">{basename(detail.source_file)}</span> — only
                the alias changes.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5 py-4">
              <Label htmlFor="duplicate-alias">New alias</Label>
              <Input
                id="duplicate-alias"
                autoFocus
                value={dupAlias}
                onChange={(e) => setDupAlias(e.target.value)}
                className="font-mono"
              />
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </DialogClose>
              <Button
                type="submit"
                disabled={dupAlias.trim() === "" || duplicateHost.isPending}
              >
                {duplicateHost.isPending ? "Duplicating…" : "Duplicate"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Editor header identity block: alias title + patterns/source line, with a
 * quiet inline-rename mode. The pencil (revealed on header hover, always
 * keyboard-reachable) swaps the title for a single mono input holding the FULL
 * `Host` pattern list space-separated. Enter = commit, Esc = cancel; ✓/✕ for
 * the mouse. On success the selection follows the new first pattern.
 */
function HostHeaderTitle({ detail }: { detail: HostDetail }) {
  const renameHost = useRenameHost();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const pending = renameHost.isPending;

  const copySshName = async () => {
    try {
      await navigator.clipboard.writeText(detail.alias);
      toast.success(`Copied ${detail.alias}`);
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  const startEdit = () => {
    setValue(detail.patterns.join(" "));
    setEditing(true);
  };

  const commit = () => {
    const patterns = value.split(/\s+/).filter(Boolean);
    // Empty or unchanged input is a silent cancel — nothing to write.
    if (patterns.length === 0 || patterns.join(" ") === detail.patterns.join(" ")) {
      setEditing(false);
      return;
    }
    renameHost.mutate(
      { alias: detail.alias, patterns },
      {
        onSuccess: () => {
          setEditing(false);
          setSelectedAlias(patterns[0]);
          toast.success(`Renamed to ${patterns[0]}`);
        },
        // Validation/collision errors surface via the mutation's error toast;
        // stay in edit mode so the input can be corrected.
      },
    );
  };

  if (editing) {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-1.5">
        <Input
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            } else if (e.key === "Escape") {
              e.preventDefault();
              setEditing(false);
            }
          }}
          disabled={pending}
          aria-label="Host patterns"
          placeholder="alias [more patterns…]"
          className="h-7 max-w-md flex-1 px-2 font-mono text-sm"
        />
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-7 shrink-0 text-muted-foreground"
          aria-label="Apply rename"
          onClick={commit}
          disabled={pending}
        >
          <Check className="size-4" />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-7 shrink-0 text-muted-foreground"
          aria-label="Cancel rename"
          onClick={() => setEditing(false)}
          disabled={pending}
        >
          <X className="size-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-1">
      <div className="flex items-center gap-0.5">
        <h2 className="truncate text-[0.9375rem] font-semibold tracking-tight">
          {detail.alias}
        </h2>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-6 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
          aria-label={`Copy SSH name ${detail.alias}`}
          title="Copy SSH name"
          onClick={() => void copySshName()}
        >
          <Copy className="size-3.5" />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-6 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
          aria-label="Rename host"
          onClick={startEdit}
        >
          <Pencil className="size-3.5" />
        </Button>
      </div>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <span className="font-mono select-text">{detail.patterns.join(", ")}</span>
        <span className="text-muted-foreground/40">·</span>
        <Badge
          variant="outline"
          className="border-border font-mono text-[0.65rem] font-normal text-muted-foreground"
          title={detail.source_file}
        >
          {basename(detail.source_file)}
        </Badge>
      </div>
    </div>
  );
}

/** Skeleton placeholder shown while a host's detail loads. */
function HostEditorSkeleton() {
  return (
    <div className="space-y-6" aria-hidden>
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-3 w-64" />
      </div>
      <div>
        <Skeleton className="h-9 w-full" />
      </div>
      <Skeleton className="h-8 w-72" />
      <div className="space-y-5">
        {[0, 1, 2].map((i) => (
          <div key={i} className="space-y-1.5">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-9 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

// Radix Select cannot use "" as an item value, so the "unset" choice uses a sentinel that
// maps back to "" (which clears the field → the directive line is removed on save).
const UNSET = "__unset__";

/**
 * A single settings row: label on the LEFT (system font, muted), control area
 * on the RIGHT (right-aligned, value in mono), compact fixed height. Used for
 * every editor field.
 */
function SettingsRow({
  id,
  label,
  children,
}: {
  id?: string;
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-9 items-center justify-between gap-4 px-3 py-1.5">
      <Label htmlFor={id} className="shrink-0 text-sm font-normal text-muted-foreground">
        {label}
      </Label>
      <div className="flex min-w-0 max-w-[62%] flex-1 items-center justify-end">
        {children}
      </div>
    </div>
  );
}

interface FieldControlProps {
  def: FieldDef;
  control: ReturnType<typeof useForm<FormValues>>["control"];
  register: ReturnType<typeof useForm<FormValues>>["register"];
  setValue: ReturnType<typeof useForm<FormValues>>["setValue"];
}

function FieldControl({ def, control, register, setValue }: FieldControlProps) {
  const name = `firstClass.${def.keyword.toLowerCase()}` as const;
  const id = `field-${def.keyword.toLowerCase()}`;

  if (def.kind === "toggle") {
    return (
      <SettingsRow id={id} label={def.label}>
        <Controller
          control={control}
          name={name}
          render={({ field }) => (
            <Switch
              id={id}
              checked={field.value === "yes"}
              onCheckedChange={(checked) => field.onChange(checked ? "yes" : "")}
            />
          )}
        />
      </SettingsRow>
    );
  }

  if (def.kind === "select") {
    return (
      <SettingsRow id={id} label={def.label}>
        <Controller
          control={control}
          name={name}
          render={({ field }) => (
            <Select
              value={field.value ? field.value : UNSET}
              onValueChange={(v) => field.onChange(v === UNSET ? "" : v)}
            >
              <SelectTrigger id={id} size="sm" className="h-7 w-auto min-w-28 gap-1.5 border-0 bg-transparent font-mono shadow-none focus-visible:ring-0 dark:bg-transparent">
                <SelectValue placeholder="—" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={UNSET} className="font-sans text-muted-foreground">
                  (unset)
                </SelectItem>
                {(def.options ?? []).map((opt) => (
                  <SelectItem key={opt} value={opt} className="font-mono">
                    {opt}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        />
      </SettingsRow>
    );
  }

  // IdentityFile gets picker affordances: detected ~/.ssh keys + a file dialog.
  if (def.keyword === "IdentityFile") {
    return (
      <SettingsRow id={id} label={def.label}>
        <IdentityFileControl id={id} name={name} register={register} setValue={setValue} />
      </SettingsRow>
    );
  }

  // text | number
  return (
    <SettingsRow id={id} label={def.label}>
      <Input
        id={id}
        type={def.kind === "number" ? "number" : "text"}
        className="h-7 border-0 bg-transparent px-2 text-right font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
        {...register(name)}
      />
    </SettingsRow>
  );
}

/**
 * IdentityFile input with two pick affordances: a dropdown of the private keys
 * detected in ~/.ssh (fetched lazily when the menu opens) and a native file
 * dialog for anything else. Both write through setValue so the form dirties
 * and saves exactly like hand-typed text; paths under ~/.ssh are written in
 * their `~` form, matching ssh_config convention.
 */
function IdentityFileControl({
  id,
  name,
  register,
  setValue,
}: {
  id: string;
  name: `firstClass.${string}`;
  register: ReturnType<typeof useForm<FormValues>>["register"];
  setValue: ReturnType<typeof useForm<FormValues>>["setValue"];
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const keysQ = useKeys({ enabled: menuOpen });
  const pick = (value: string) =>
    setValue(name, value, { shouldDirty: true, shouldTouch: true });

  const browse = async () => {
    const picked = await openFileDialog({
      multiple: false,
      directory: false,
      title: "Choose an identity file",
    });
    if (typeof picked === "string") pick(toTildeSshPath(picked));
  };

  return (
    <div className="flex min-w-0 flex-1 items-center justify-end gap-0.5">
      <Input
        id={id}
        type="text"
        className="h-7 border-0 bg-transparent px-2 text-right font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
        {...register(name)}
      />
      <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
        <DropdownMenuTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-6 shrink-0 text-muted-foreground hover:text-foreground"
            aria-label="Pick a detected key"
            title="Pick a key from ~/.ssh"
          >
            <KeyRound className="size-3.5" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
            Keys in ~/.ssh
          </DropdownMenuLabel>
          {keysQ.isLoading ? (
            <DropdownMenuItem disabled>Scanning…</DropdownMenuItem>
          ) : (keysQ.data ?? []).length === 0 ? (
            <DropdownMenuItem disabled>No keys found</DropdownMenuItem>
          ) : (
            (keysQ.data ?? []).map((k) => (
              <DropdownMenuItem
                key={k.private_path}
                className="font-mono"
                onSelect={() => pick(toTildeSshPath(k.private_path))}
              >
                {k.name}
              </DropdownMenuItem>
            ))
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-6 shrink-0 text-muted-foreground hover:text-foreground"
        aria-label="Browse for an identity file"
        title="Browse…"
        onClick={browse}
      >
        <FolderOpen className="size-3.5" />
      </Button>
    </div>
  );
}

interface DisabledOptionRowProps {
  option: HostOption;
  onEnable: () => void;
}

function DisabledOptionRow({ option, onEnable }: DisabledOptionRowProps) {
  return (
    <div className="flex min-h-9 items-center justify-between gap-3 px-3 py-1.5">
      <span className="truncate font-mono text-sm text-muted-foreground">
        {option.keyword} {option.value}
      </span>
      <Switch
        checked={false}
        onCheckedChange={() => onEnable()}
        aria-label={`Enable ${option.keyword}`}
      />
    </div>
  );
}

/**
 * This host's password, stored in the operating-system keychain.
 *
 * Deliberately NOT an ssh config field — it never touches any config file and
 * takes no part in the form's save flow. ssh_config has no password directive;
 * one written there would make ssh reject the file for every host.
 */
function HostPasswordSection({ alias }: { alias: string }) {
  const [draft, setDraft] = useState("");
  const [revealed, setRevealed] = useState(false);
  const has = useHasHostPassword(alias);
  const reveal = useRevealHostPassword();
  const save = useSetHostPassword();
  const remove = useDeleteHostPassword();

  // Clear the draft when switching hosts so A's password can't land on B.
  useEffect(() => {
    setDraft("");
    setRevealed(false);
  }, [alias]);

  const saved = has.data === true;

  const copySaved = () =>
    reveal.mutate(
      { alias },
      {
        onSuccess: async (pw) => {
          if (pw === null) return;
          try {
            await navigator.clipboard.writeText(pw);
            toast.success("Password copied");
          } catch {
            toast.error("Clipboard unavailable");
          }
        },
      },
    );

  return (
    <Section
      title="Password"
      description="Stored in your operating system's keychain — never written to ~/.ssh/config. Connect auto-fills it once the host key is trusted (not for ProxyJump or 2FA hosts)."
    >
      <SettingsGroup>
        <div className="flex items-center gap-1.5 px-3 py-2">
          <Input
            type={revealed ? "text" : "password"}
            autoComplete="off"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={saved ? "Saved — press Show to view" : "Set a password"}
            aria-label={`Password for ${alias}`}
            className="h-7 flex-1 border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
          />
          {saved && (
            <>
              <Badge variant="secondary" className="shrink-0 select-none">
                Saved
              </Badge>
              <Button
                type="button"
                variant="ghost"
                size="xs"
                className="h-7 shrink-0 text-muted-foreground"
                disabled={reveal.isPending}
                onClick={() =>
                  reveal.mutate(
                    { alias },
                    {
                      onSuccess: (pw) => {
                        if (pw !== null) {
                          setDraft(pw);
                          setRevealed(true);
                        }
                      },
                    },
                  )
                }
              >
                <Eye className="size-3.5" /> Show
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-7 shrink-0 text-muted-foreground"
                aria-label="Copy password"
                disabled={reveal.isPending}
                onClick={copySaved}
              >
                <Copy className="size-4" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-7 shrink-0 text-muted-foreground"
                aria-label="Delete password"
                disabled={remove.isPending}
                onClick={() =>
                  remove.mutate(
                    { alias },
                    {
                      onSuccess: () => {
                        toast.success("Password deleted");
                        setDraft("");
                        setRevealed(false);
                      },
                    },
                  )
                }
              >
                <Trash2 className="size-4" />
              </Button>
            </>
          )}
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="h-7 shrink-0"
            disabled={draft.trim() === "" || save.isPending}
            onClick={() =>
              save.mutate(
                { alias, password: draft },
                {
                  onSuccess: () => {
                    toast.success("Password saved");
                    setDraft("");
                    setRevealed(false);
                  },
                },
              )
            }
          >
            Save
          </Button>
        </div>
      </SettingsGroup>
    </Section>
  );
}

/**
 * Build the `ssh_config` Host block these form values represent: first-class
 * fields (with values, in FIELD_DEFS order) followed by advanced entries — the
 * same rendering ssh would see. Used only for the read-only preview signature.
 */
function buildConfigText(alias: string, values: FormValues): string {
  const lines: string[] = [`Host ${alias}`];
  for (const def of FIELD_DEFS) {
    const raw = values.firstClass?.[def.keyword.toLowerCase()] ?? "";
    const v = raw.trim();
    if (v !== "") lines.push(`    ${def.keyword} ${v}`);
  }
  for (const entry of values.advanced ?? []) {
    const keyword = entry.keyword.trim();
    if (keyword !== "") lines.push(`    ${keyword} ${entry.value.trim()}`);
  }
  return lines.join("\n");
}

/**
 * The ssh_config inspector — the terminal-DNA signature, always-visible at the
 * bottom of the single-column editor. Renders the Host block client-side from
 * the current form values (read-only, mono) and exposes a Copy action.
 */
function ConfigInspector({
  alias,
  control,
}: {
  alias: string;
  control: Control<FormValues>;
}) {
  const values = useWatch({ control }) as FormValues;
  const text = useMemo(() => buildConfigText(alias, values), [alias, values]);
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast("Copied");
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      toast.error("Couldn't copy to clipboard");
    }
  };

  return (
    <Section
      title="ssh_config"
      action={
        <Button
          type="button"
          variant="ghost"
          size="xs"
          className="h-6 -mr-1 gap-1.5 text-muted-foreground"
          onClick={onCopy}
          aria-label="Copy ssh_config block"
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      }
    >
      <div className="settings-group">
        {/* Body — the live Host block. Mono, muted, selectable (it's a value). */}
        <pre
          className={cn(
            "overflow-x-auto px-3.5 py-3 font-mono text-xs leading-relaxed text-muted-foreground",
            "whitespace-pre select-text",
          )}
        >
          {text}
        </pre>
      </div>
    </Section>
  );
}

export default HostEditor;
