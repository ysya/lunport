import { useMemo, useState } from "react";
import { ArrowLeft, Copy, KeyRound, Send } from "lucide-react";
import { toast } from "sonner";

import type { KeyInfo } from "@/bindings/KeyInfo";
import {
  useAgentStatus,
  useDeployKey,
  useGenerateKey,
  useGenerateKeyInTerminal,
  useHostsQuery,
  useKeys,
  useReadPublicKey,
} from "@/lib/queries";
import { useSettingsStore } from "@/stores/settings";
import { isWildcardOnly } from "@/lib/host-display";
import { cn } from "@/lib/utils";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/** New-key name rule — mirrors the backend gate (`^[A-Za-z0-9][A-Za-z0-9._-]*$`, no `.pub`). */
const KEY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Toolbar button + a dialog managing ~/.ssh keys: list, copy, deploy, generate. */
export function KeysDialog() {
  const [open, setOpen] = useState(false);
  // When set, the dialog shows the host picker to deploy THIS key's .pub.
  const [deployFor, setDeployFor] = useState<KeyInfo | null>(null);

  // Lazy: shell out to ssh-keygen / ssh-add only while the dialog is open.
  const keysQ = useKeys({ enabled: open });
  const agentQ = useAgentStatus({ enabled: open });
  const readPublic = useReadPublicKey();
  const deploy = useDeployKey();
  const terminalId = useSettingsStore((s) => s.terminalId);
  const { data: configData } = useHostsQuery();

  // Deploy targets: real hosts only — wildcard blocks (`Host *`) are defaults.
  const hosts = useMemo(
    () => (configData?.hosts ?? []).filter((h) => !isWildcardOnly(h)),
    [configData],
  );

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) setDeployFor(null);
  };

  const copyPublicKey = (key: KeyInfo) => {
    if (!key.public_path) return;
    readPublic.mutate(
      { path: key.public_path },
      {
        onSuccess: async (text) => {
          try {
            await navigator.clipboard.writeText(text);
            toast.success(`Copied ${key.name}.pub`);
          } catch {
            toast.error("Clipboard unavailable");
          }
        },
      },
    );
  };

  const deployTo = (alias: string) => {
    if (!deployFor?.public_path) return;
    deploy.mutate(
      { alias, publicPath: deployFor.public_path, terminalOverride: terminalId },
      {
        onSuccess: () => {
          toast.success("Opening terminal…", {
            description: `ssh-copy-id ${deployFor.name}.pub → ${alias}`,
          });
          setDeployFor(null);
        },
      },
    );
  };

  const keys = keysQ.data ?? [];

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DialogTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="SSH keys"
            >
              <KeyRound className="size-4" />
            </Button>
          </DialogTrigger>
        </TooltipTrigger>
        <TooltipContent>SSH keys</TooltipContent>
      </Tooltip>

      <DialogContent className="sm:max-w-lg">
        {deployFor ? (
          <>
            <DialogHeader>
              <DialogTitle>
                Deploy <span className="font-mono">{deployFor.name}.pub</span>
              </DialogTitle>
              <DialogDescription>
                Pick a host — <span className="font-mono">ssh-copy-id</span> runs in your
                terminal and will ask for the password.
              </DialogDescription>
            </DialogHeader>

            <Command className="rounded-lg border">
              <CommandInput placeholder="Search hosts…" autoFocus />
              <CommandList className="max-h-[40vh]">
                <CommandEmpty>No hosts found.</CommandEmpty>
                {hosts.map((h) => (
                  <CommandItem
                    key={`${h.source_file}::${h.alias}`}
                    value={`${h.alias} ${h.hostname ?? ""}`}
                    disabled={deploy.isPending}
                    onSelect={() => deployTo(h.alias)}
                  >
                    <span className="truncate font-mono text-sm">{h.alias}</span>
                    {h.hostname && (
                      <span className="ml-auto truncate pl-3 font-mono text-xs text-muted-foreground">
                        {h.user ? `${h.user}@` : ""}
                        {h.hostname}
                      </span>
                    )}
                  </CommandItem>
                ))}
              </CommandList>
            </Command>

            <div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7 gap-1.5 px-2 text-muted-foreground"
                onClick={() => setDeployFor(null)}
              >
                <ArrowLeft className="size-3.5" />
                Back to keys
              </Button>
            </div>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>SSH keys</DialogTitle>
              <DialogDescription>
                Keypairs in <span className="font-mono">~/.ssh</span> and the agent.
              </DialogDescription>
            </DialogHeader>

            <AgentStatusLine
              running={agentQ.data?.running ?? false}
              keyCount={agentQ.data?.key_count ?? 0}
              loading={agentQ.isLoading}
            />

            {keysQ.isLoading || keysQ.isFetching ? (
              <p className="py-6 text-center text-sm text-muted-foreground select-none">
                Scanning keys…
              </p>
            ) : keys.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground select-none">
                No keys found in <span className="font-mono">~/.ssh</span>.
              </p>
            ) : (
              <div className="-mx-1 max-h-[44vh] overflow-y-auto px-1">
                <div className="settings-group">
                  {keys.map((k) => (
                    <KeyRow
                      key={k.private_path}
                      info={k}
                      copying={readPublic.isPending}
                      onCopy={() => copyPublicKey(k)}
                      onDeploy={() => setDeployFor(k)}
                    />
                  ))}
                </div>
              </div>
            )}

            <NewKeySection existingNames={keys.map((k) => k.name)} />
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** Header line: agent dot + "agent: N keys" (mono) or "agent not running" (muted). */
function AgentStatusLine({
  running,
  keyCount,
  loading,
}: {
  running: boolean;
  keyCount: number;
  loading: boolean;
}) {
  return (
    <div className="flex items-center gap-2 select-none">
      <span
        className={cn(
          "size-1.5 shrink-0 rounded-full",
          running ? "bg-emerald-500" : "bg-muted-foreground/40",
        )}
        aria-hidden
      />
      {loading ? (
        <span className="text-xs text-muted-foreground">checking agent…</span>
      ) : running ? (
        <span className="font-mono text-xs text-muted-foreground">
          agent: {keyCount} {keyCount === 1 ? "key" : "keys"}
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">agent not running</span>
      )}
    </div>
  );
}

function KeyRow({
  info,
  copying,
  onCopy,
  onDeploy,
}: {
  info: KeyInfo;
  copying: boolean;
  onCopy: () => void;
  onDeploy: () => void;
}) {
  const hasPub = info.public_path !== null;
  return (
    <div className="group flex min-h-9 items-center gap-3 px-3 py-2">
      <KeyRound className="size-3.5 shrink-0 text-muted-foreground/70" aria-hidden />

      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-sm font-medium" title={info.private_path}>
            {info.name}
          </span>
          <Badge variant="secondary" className="h-4 shrink-0 px-1.5 font-mono text-[0.625rem]">
            {info.key_type}
            {info.bits !== null ? ` ${info.bits}` : ""}
          </Badge>
          {info.in_agent && (
            <span className="flex shrink-0 items-center gap-1 text-[0.6875rem] text-emerald-600 dark:text-emerald-500">
              <span className="size-1.5 rounded-full bg-emerald-500" aria-hidden />
              in agent
            </span>
          )}
        </div>
        {info.fingerprint_sha256 && (
          <span
            className="block truncate font-mono text-xs text-muted-foreground"
            title={info.fingerprint_sha256}
          >
            {info.fingerprint_sha256}
            {info.comment ? `  ·  ${info.comment}` : ""}
          </span>
        )}
        {!hasPub && (
          <span className="block text-xs text-amber-600 dark:text-amber-500">
            missing .pub — copy &amp; deploy unavailable
          </span>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-6 text-muted-foreground hover:text-foreground"
              aria-label={`Copy ${info.name} public key`}
              disabled={!hasPub || copying}
              onClick={onCopy}
            >
              <Copy className="size-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Copy public key</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-6 text-muted-foreground hover:text-foreground"
              aria-label={`Deploy ${info.name} to a host`}
              disabled={!hasPub}
              onClick={onDeploy}
            >
              <Send className="size-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Deploy to host…</TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
}

/** Footer: generate a new ed25519 key — instant (no passphrase) or via the terminal. */
function NewKeySection({ existingNames }: { existingNames: string[] }) {
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  const generate = useGenerateKey();
  const generateInTerminal = useGenerateKeyInTerminal();
  const terminalId = useSettingsStore((s) => s.terminalId);

  const trimmed = name.trim();
  const validName = KEY_NAME_RE.test(trimmed) && !trimmed.endsWith(".pub");
  const taken = existingNames.includes(trimmed);
  const canSubmit = validName && !taken && !generate.isPending;

  const reset = () => {
    setName("");
    setComment("");
  };

  const handleGenerate = () => {
    generate.mutate(
      { name: trimmed, comment: comment.trim() || null },
      {
        onSuccess: (key) => {
          toast.success(`Generated ${key.name}`, {
            description: key.fingerprint_sha256 ?? undefined,
          });
          reset();
        },
      },
    );
  };

  const handleGenerateInTerminal = () => {
    generateInTerminal.mutate(
      { name: trimmed, comment: comment.trim() || null, terminalOverride: terminalId },
      {
        onSuccess: () => {
          toast.success("Opening terminal…", {
            description: "ssh-keygen will ask for a passphrase there.",
          });
          reset();
        },
      },
    );
  };

  return (
    <div className="space-y-2 border-t pt-3">
      <span className="section-label px-0">New key</span>
      <div className="flex gap-2">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="id_ed25519_work"
          aria-label="New key name"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          className="h-7 flex-1 font-mono text-sm"
        />
        <Input
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Comment (optional)"
          aria-label="New key comment"
          className="h-7 flex-1 text-sm"
        />
      </div>
      {taken && (
        <p className="text-xs text-amber-600 dark:text-amber-500">
          <span className="font-mono">{trimmed}</span> already exists.
        </p>
      )}
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          className="h-7"
          disabled={!canSubmit}
          onClick={handleGenerate}
        >
          Generate
        </Button>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="h-7"
          disabled={!canSubmit || generateInTerminal.isPending}
          onClick={handleGenerateInTerminal}
        >
          Generate in Terminal…
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        “Generate” sets no passphrase — anyone with the file can use it. Use “Generate in
        Terminal…” to protect the key with a passphrase.
      </p>
    </div>
  );
}

export default KeysDialog;
