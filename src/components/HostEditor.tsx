import { useEffect, useMemo, useState } from "react";
import { useForm, useFieldArray, Controller, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { Trash2, Plus } from "lucide-react";

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
  useSetGroup,
  useSetTags,
  useSetOptionEnabled,
  useRemoveHost,
} from "@/lib/queries";
import { useUiStore } from "@/stores/ui";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
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
  const setGroup = useSetGroup();
  const setTags = useSetTags();
  const setOptionEnabled = useSetOptionEnabled();
  const removeHost = useRemoveHost();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading host…</p>;
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
      onSave={(changes) => saveHost.mutate({ alias: detail.alias, changes })}
      onSetGroup={(group) => setGroup.mutate({ alias: detail.alias, group })}
      onSetTags={(tags) => setTags.mutate({ alias: detail.alias, tags })}
      onEnableOption={(keyword) =>
        setOptionEnabled.mutate({ alias: detail.alias, keyword, enabled: true })
      }
      onRemove={() =>
        removeHost.mutate(
          { alias: detail.alias },
          { onSuccess: () => setSelectedAlias(null) },
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
  onSetGroup: (group: string | null) => void;
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
  onSetGroup,
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

  // Group / tags side-form state (independent of the option form).
  const [group, setGroupValue] = useState(detail.group ?? "");
  const [tags, setTagsValue] = useState(detail.tags.join(", "));
  useEffect(() => {
    setGroupValue(detail.group ?? "");
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
      <div className="space-y-1">
        <h2 className="text-lg font-semibold">{detail.alias}</h2>
        <p className="text-xs text-muted-foreground">
          {detail.patterns.join(", ")} ·{" "}
          <span className="font-mono">{detail.source_file}</span>
        </p>
      </div>

      {/* Group / tags */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="host-group">Group</Label>
          <div className="flex gap-2">
            <Input
              id="host-group"
              value={group}
              onChange={(e) => setGroupValue(e.target.value)}
              placeholder="Ungrouped"
            />
            <Button
              type="button"
              variant="secondary"
              onClick={() => onSetGroup(group.trim() || null)}
            >
              Apply
            </Button>
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="host-tags">Tags</Label>
          <div className="flex gap-2">
            <Input
              id="host-tags"
              value={tags}
              onChange={(e) => setTagsValue(e.target.value)}
              placeholder="comma, separated"
            />
            <Button
              type="button"
              variant="secondary"
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
      </div>

      <Separator />

      <form onSubmit={onSubmit} className="space-y-4">
        <Tabs defaultValue="Connection">
          <TabsList>
            {GROUPS.map((g) => (
              <TabsTrigger key={g} value={g}>
                {g}
              </TabsTrigger>
            ))}
            <TabsTrigger value="Advanced">Advanced</TabsTrigger>
          </TabsList>

          {GROUPS.map((g) => (
            <TabsContent key={g} value={g} className="space-y-4 pt-2">
              {FIELD_DEFS.filter((d) => d.group === g)
                .filter((d) => !d.macOnly || isMac)
                .map((def) => (
                  <FieldControl key={def.keyword} def={def} control={control} register={register} />
                ))}
            </TabsContent>
          ))}

          <TabsContent value="Advanced" className="space-y-3 pt-2">
            {fields.length === 0 && (
              <p className="text-sm text-muted-foreground">No advanced options.</p>
            )}
            {fields.map((field, index) => (
              <div key={field.id} className="flex items-center gap-2">
                <Input
                  className="flex-1"
                  placeholder="Keyword"
                  aria-label="Keyword"
                  {...register(`advanced.${index}.keyword` as const)}
                />
                <Input
                  className="flex-[2]"
                  placeholder="Value"
                  aria-label="Value"
                  {...register(`advanced.${index}.value` as const)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label="Remove option"
                  onClick={() => remove(index)}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => append({ keyword: "", value: "" })}
            >
              <Plus className="size-4" /> Add option
            </Button>
          </TabsContent>
        </Tabs>

        <div className="flex items-center gap-2">
          <Button type="submit" disabled={!isDirty || saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>

      {disabledOpts.length > 0 && (
        <>
          <Separator />
          <div className="space-y-2">
            <h3 className="text-sm font-medium">Disabled options</h3>
            <p className="text-xs text-muted-foreground">
              Commented-out lines. Toggle on to re-enable, then edit above.
            </p>
            <ul className="space-y-1.5">
              {disabledOpts.map((o, i) => (
                <DisabledOptionRow
                  key={`${o.keyword}-${i}`}
                  option={o}
                  onEnable={() => onEnableOption(o.keyword)}
                />
              ))}
            </ul>
          </div>
        </>
      )}

      <Separator />

      <AlertDialog>
        <AlertDialogTrigger asChild>
          <Button type="button" variant="destructive" disabled={removing}>
            <Trash2 className="size-4" /> Remove host
          </Button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove “{detail.alias}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes the host block from{" "}
              <span className="font-mono">{detail.source_file}</span>. This cannot
              be undone.
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
      <div className="flex items-center justify-between gap-4">
        <Label htmlFor={id}>{def.label}</Label>
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
      </div>
    );
  }

  if (def.kind === "select") {
    return (
      <div className="space-y-1.5">
        <Label htmlFor={id}>{def.label}</Label>
        <Controller
          control={control}
          name={name}
          render={({ field }) => (
            <Select
              value={field.value || undefined}
              onValueChange={field.onChange}
            >
              <SelectTrigger id={id} className="w-full">
                <SelectValue placeholder="—" />
              </SelectTrigger>
              <SelectContent>
                {(def.options ?? []).map((opt) => (
                  <SelectItem key={opt} value={opt}>
                    {opt}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        />
      </div>
    );
  }

  // text | number
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{def.label}</Label>
      <Input
        id={id}
        type={def.kind === "number" ? "number" : "text"}
        {...register(name)}
      />
    </div>
  );
}

interface DisabledOptionRowProps {
  option: HostOption;
  onEnable: () => void;
}

function DisabledOptionRow({ option, onEnable }: DisabledOptionRowProps) {
  return (
    <li className="flex items-center justify-between gap-3 rounded-md border px-3 py-1.5">
      <span className="truncate font-mono text-sm text-muted-foreground">
        {option.keyword} {option.value}
      </span>
      <Switch
        checked={false}
        onCheckedChange={() => onEnable()}
        aria-label={`Enable ${option.keyword}`}
      />
    </li>
  );
}

export default HostEditor;
