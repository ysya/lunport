import { useState } from "react";
import {
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  ChevronDown,
  Upload,
} from "lucide-react";

import {
  useKeyHygiene,
  useJumpChain,
  useEffectiveConfig,
} from "@/lib/queries";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";
import { Section, SettingsGroup } from "@/components/settings-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * Read-only per-host intelligence: key hygiene, the ProxyJump chain, and the
 * resolved (`ssh -G`) effective config. All driven by the selected alias.
 */
export function HostIntelligence({ alias }: { alias: string }) {
  return (
    <>
      <KeyHygieneSection alias={alias} />
      <JumpChainSection alias={alias} />
      <EffectiveConfigSection alias={alias} />
    </>
  );
}

function KeyHygieneSection({ alias }: { alias: string }) {
  const { data, isLoading } = useKeyHygiene(alias);
  const setDeployKeyAlias = useUiStore((s) => s.setDeployKeyAlias);

  return (
    <Section
      title="Key hygiene"
      action={
        data ? (
          <div className="flex items-center gap-1.5 pb-1">
            <Button
              type="button"
              variant="ghost"
              size="xs"
              className="h-6 text-muted-foreground"
              onClick={() => setDeployKeyAlias(alias)}
            >
              <Upload className="size-3.5" /> Deploy key…
            </Button>
            {data.identities_only ? (
              <Badge
                variant="outline"
                className="border-border font-mono text-[0.65rem] font-normal text-muted-foreground"
                title="IdentitiesOnly yes — ssh offers only these keys"
              >
                IdentitiesOnly
              </Badge>
            ) : null}
            <Badge
              variant="outline"
              className="border-border font-mono text-[0.65rem] font-normal text-muted-foreground"
              title={
                data.explicit
                  ? "IdentityFile is set explicitly for this host"
                  : "No explicit IdentityFile — ssh falls back to its default keys"
              }
            >
              {data.explicit ? "explicit" : "default"}
            </Badge>
          </div>
        ) : undefined
      }
    >
      <SettingsGroup>
        {isLoading ? (
          <p className="px-3 py-2.5 text-sm text-muted-foreground">Checking keys…</p>
        ) : !data || data.identity_files.length === 0 ? (
          <div className="flex min-h-9 items-center gap-2 px-3 py-2 text-sm text-muted-foreground">
            <KeyRound className="size-4 shrink-0 opacity-60" />
            <span>Uses default keys</span>
          </div>
        ) : (
          data.identity_files.map((f, i) => (
            <div
              key={`${f.path}-${i}`}
              className="flex min-h-9 items-center justify-between gap-3 px-3 py-1.5"
            >
              <span className="truncate font-mono text-sm" title={f.path}>
                {f.path}
              </span>
              {f.exists ? (
                <span
                  className="flex shrink-0 items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400"
                  title="Key file present"
                >
                  <CheckCircle2 className="size-4" />
                  present
                </span>
              ) : (
                <span
                  className="flex shrink-0 items-center gap-1 text-xs text-amber-600 dark:text-amber-400"
                  title="Key file missing on disk"
                >
                  <AlertTriangle className="size-4" />
                  missing
                </span>
              )}
            </div>
          ))
        )}
      </SettingsGroup>
    </Section>
  );
}

function JumpChainSection({ alias }: { alias: string }) {
  const { data } = useJumpChain(alias);
  if (!data || data.length === 0) return null;

  return (
    <Section title="ProxyJump chain">
      <SettingsGroup>
        <div className="flex flex-wrap items-center gap-1.5 px-3 py-2.5">
          {data.map((node, i) => (
            <span key={`${node.name}-${i}`} className="flex items-center gap-1.5">
              {i > 0 && (
                <ChevronRight className="size-3.5 shrink-0 text-muted-foreground/50" aria-hidden />
              )}
              {node.defined ? (
                <span className="rounded-md bg-muted px-2 py-0.5 font-mono text-xs ring-1 ring-border">
                  {node.name}
                </span>
              ) : (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="rounded-md bg-amber-500/10 px-2 py-0.5 font-mono text-xs text-amber-600 ring-1 ring-amber-500/30 dark:text-amber-400">
                      {node.name}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>not defined in your config</TooltipContent>
                </Tooltip>
              )}
            </span>
          ))}
        </div>
      </SettingsGroup>
    </Section>
  );
}

function EffectiveConfigSection({ alias }: { alias: string }) {
  const [open, setOpen] = useState(false);
  // Lazy: only run `ssh -G` once the section is expanded.
  const { data, isLoading } = useEffectiveConfig(alias, { enabled: open });

  return (
    <Section
      title="Effective config"
      action={
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex h-6 -mr-1 items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          aria-expanded={open}
        >
          {open ? (
            <ChevronDown className="size-3.5" />
          ) : (
            <ChevronRight className="size-3.5" />
          )}
          {open ? "Hide" : "Resolve"}
        </button>
      }
    >
      {open && (
        <SettingsGroup>
          {isLoading ? (
            <p className="px-3 py-2.5 text-sm text-muted-foreground">
              Resolving with <span className="font-mono">ssh -G</span>…
            </p>
          ) : !data || data.length === 0 ? (
            <p className="px-3 py-2.5 text-sm text-muted-foreground">No resolved values.</p>
          ) : (
            <div className="max-h-72 overflow-y-auto">
              <pre
                className={cn(
                  "px-3.5 py-3 font-mono text-xs leading-relaxed text-muted-foreground",
                  "whitespace-pre select-text",
                )}
              >
                {data
                  .map(([k, v]) => `${k.padEnd(22)} ${v}`)
                  .join("\n")}
              </pre>
            </div>
          )}
        </SettingsGroup>
      )}
    </Section>
  );
}

export default HostIntelligence;
