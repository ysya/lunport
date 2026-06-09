import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useForm, useFieldArray, Controller, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { Trash2, Plus, MoreVertical, RotateCcw, Save } from "lucide-react";

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
  usePlatform,
  useSaveHost,
  useSetTags,
  useSetOptionEnabled,
  useRemoveHost,
} from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { basename } from "@/lib/utils";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

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
      onEnableOption={(keyword) =>
        setOptionEnabled.mutate(
          { alias: detail.alias, keyword, enabled: true },
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
  onEnableOption: (keyword: string) => void;
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
  const disabledOpts = useMemo(
    () => detail.options.filter((o) => !o.enabled),
    [detail],
  );

  const defaults = useMemo(() => buildDefaults(detail), [detail]);

  const {
    control,
    register,
    handleSubmit,
    reset,
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
    <div className="space-y-5">
      {/* Editor header: alias in mono + patterns + source + remove menu. */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-1.5">
          <h2 className="truncate font-mono text-xl font-semibold tracking-tight">
            {detail.alias}
          </h2>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span className="font-mono">{detail.patterns.join(", ")}</span>
            <span className="text-muted-foreground/40">·</span>
            <Badge
              variant="secondary"
              className="font-mono text-[0.65rem] font-normal text-muted-foreground"
              title={detail.source_file}
            >
              {basename(detail.source_file)}
            </Badge>
          </div>
        </div>

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
            <DropdownMenuContent align="end" className="w-40">
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
      </div>

      {/* Tags — settings-style inset row: label left, control right. */}
      <SettingsGroup>
        <div className="flex items-center justify-between gap-4 px-3 py-2">
          <Label htmlFor="host-tags" className="shrink-0 text-sm font-normal">
            Tags
          </Label>
          <div className="flex max-w-[60%] flex-1 items-center gap-1.5">
            <Input
              id="host-tags"
              value={tags}
              onChange={(e) => setTagsValue(e.target.value)}
              placeholder="comma, separated"
              className="h-7 border-0 bg-transparent px-2 text-right font-mono text-sm shadow-none focus-visible:bg-muted/50 focus-visible:ring-0 dark:bg-transparent"
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

      <form onSubmit={onSubmit} id="host-editor-form" className="space-y-3">
        <Tabs defaultValue="Connection" className="w-full">
          <TabsList variant="line" className="w-full justify-start">
            {GROUPS.map((g) => (
              <TabsTrigger key={g} value={g}>
                {g}
              </TabsTrigger>
            ))}
            <TabsTrigger value="Advanced">Advanced</TabsTrigger>
          </TabsList>

          {GROUPS.map((g) => (
            <TabsContent key={g} value={g} className="pt-3">
              <SettingsGroup>
                {FIELD_DEFS.filter((d) => d.group === g)
                  .filter((d) => !d.macOnly || isMac)
                  .map((def) => (
                    <FieldControl key={def.keyword} def={def} control={control} register={register} />
                  ))}
              </SettingsGroup>
            </TabsContent>
          ))}

          <TabsContent value="Advanced" className="space-y-2 pt-3">
            {fields.length === 0 ? (
              <p className="px-1 text-sm text-muted-foreground">
                No advanced options. Add raw keyword/value pairs below.
              </p>
            ) : (
              <SettingsGroup>
                {fields.map((field, index) => (
                  <div key={field.id} className="flex items-center gap-2 px-3 py-1.5">
                    <Input
                      className="h-7 flex-1 border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/50 focus-visible:ring-0 dark:bg-transparent"
                      placeholder="Keyword"
                      aria-label="Keyword"
                      {...register(`advanced.${index}.keyword` as const)}
                    />
                    <Input
                      className="h-7 flex-[2] border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/50 focus-visible:ring-0 dark:bg-transparent"
                      placeholder="Value"
                      aria-label="Value"
                      {...register(`advanced.${index}.value` as const)}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="size-7 shrink-0"
                      aria-label="Remove option"
                      onClick={() => remove(index)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ))}
              </SettingsGroup>
            )}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7"
              onClick={() => append({ keyword: "", value: "" })}
            >
              <Plus className="size-4" /> Add option
            </Button>
          </TabsContent>
        </Tabs>
      </form>

      {disabledOpts.length > 0 && (
        <div className="space-y-2">
          <div className="space-y-0.5 px-1">
            <h3 className="text-sm font-medium text-muted-foreground">Disabled options</h3>
            <p className="text-xs text-muted-foreground">
              Commented-out lines. Toggle on to re-enable, then edit above.
            </p>
          </div>
          <SettingsGroup>
            {disabledOpts.map((o, i) => (
              <DisabledOptionRow
                key={`${o.keyword}-${i}`}
                option={o}
                onEnable={() => onEnableOption(o.keyword)}
              />
            ))}
          </SettingsGroup>
        </div>
      )}

      {/* Sticky save bar: appears only when the option form is dirty. */}
      {isDirty && (
        <div className="animate-save-bar fixed inset-x-0 bottom-0 z-30 border-t bg-background/85 backdrop-blur-md">
          <div className="mx-auto flex max-w-2xl items-center justify-between gap-3 px-5 py-2.5">
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
 * macOS System-Settings-style grouped inset container: a rounded card whose
 * direct children are separated by hairline dividers (see `.settings-group` in
 * index.css). Each child is expected to be a single row.
 */
function SettingsGroup({ children }: { children: ReactNode }) {
  return <div className="settings-group">{children}</div>;
}

/**
 * A single settings row: label on the LEFT, control area on the RIGHT
 * (right-aligned), compact fixed height. Used for every editor field.
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
      <Label htmlFor={id} className="shrink-0 font-mono text-sm font-normal">
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
}

function FieldControl({ def, control, register }: FieldControlProps) {
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

  // text | number
  return (
    <SettingsRow id={id} label={def.label}>
      <Input
        id={id}
        type={def.kind === "number" ? "number" : "text"}
        className="h-7 border-0 bg-transparent px-2 text-right font-mono text-sm shadow-none focus-visible:bg-muted/50 focus-visible:ring-0 dark:bg-transparent"
        {...register(name)}
      />
    </SettingsRow>
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

export default HostEditor;
