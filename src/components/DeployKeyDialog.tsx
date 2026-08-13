import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Eye,
  EyeOff,
  Loader2,
  ShieldAlert,
  TriangleAlert,
  XCircle,
} from "lucide-react";

import { useQueryClient } from "@tanstack/react-query";

import type { DeployOutcome } from "@/bindings/DeployOutcome";
import { pickDefaultPublicKey } from "@/lib/deploy-key-select";
import { identityFileAction, toTildeSshPath } from "@/lib/identity-file";
import {
  queryKeys,
  useDeployKeyDirect,
  useDeployPreflight,
  useHasHostPassword,
  useKeyHygiene,
  useKeys,
  usePrecheckHostKey,
  useRevealHostPassword,
  useSaveHost,
  useTrustHostKey,
} from "@/lib/queries";
import { useUiStore } from "@/stores/ui";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type Stage =
  | { kind: "form" }
  | { kind: "hostkey"; fingerprint: string }
  | { kind: "result"; view: ResultView };

type ResultView =
  | { kind: "outcome"; outcome: DeployOutcome }
  | { kind: "mismatch"; fingerprint: string }
  | { kind: "unavailable"; message: string };

const OUTCOME_TEXT: Record<
  DeployOutcome["kind"],
  { title: string; tone: "ok" | "err" }
> = {
  added: { title: "Key deployed", tone: "ok" },
  alreadyPresent: { title: "Key was already there — nothing added", tone: "ok" },
  wrongPassword: { title: "Wrong password", tone: "err" },
  hostKeyFailed: { title: "Host key verification failed", tone: "err" },
  unreachable: { title: "Could not reach the host", tone: "err" },
  remoteError: { title: "The remote command failed", tone: "err" },
  other: { title: "Deploy failed", tone: "err" },
};

/** Extra context under the result title, when the outcome carries any. */
function outcomeDetail(outcome: DeployOutcome): string | null {
  switch (outcome.kind) {
    case "added":
      return "You can now connect without typing a password.";
    case "remoteError":
      return `The remote script exited with code ${outcome.code}.`;
    case "other":
      return outcome.message;
    default:
      return null;
  }
}

/**
 * In-app public-key deployment, driven by `deployKeyAlias` in the ui store.
 * Three stages: form (pick key + password) → hostkey (only when the host is
 * not in known_hosts yet) → result. The flow component is keyed by alias so
 * every per-host state — including the typed password — dies with the dialog.
 */
export function DeployKeyDialog() {
  const alias = useUiStore((s) => s.deployKeyAlias);
  const setDeployKeyAlias = useUiStore((s) => s.setDeployKeyAlias);

  return (
    <Dialog
      open={alias !== null}
      onOpenChange={(next) => {
        if (!next) setDeployKeyAlias(null);
      }}
    >
      <DialogContent className="sm:max-w-md">
        {alias !== null && (
          <DeployKeyFlow
            key={alias}
            alias={alias}
            onClose={() => setDeployKeyAlias(null)}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function DeployKeyFlow({ alias, onClose }: { alias: string; onClose: () => void }) {
  const [stage, setStage] = useState<Stage>({ kind: "form" });
  const [publicPath, setPublicPath] = useState("");
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [remember, setRemember] = useState(false);
  /** Result-screen note about the host's IdentityFile (written / already set). */
  const [identityNote, setIdentityNote] = useState<string | null>(null);
  /** Pending "use this key instead" offer — the ~/.ssh value it would write. */
  const [identityOffer, setIdentityOffer] = useState<string | null>(null);

  // Only rendered while the dialog is open, so the lazy keys query can run.
  const keysQ = useKeys({ enabled: true });
  const hygiene = useKeyHygiene(alias);
  const hasPassword = useHasHostPassword(alias);
  const reveal = useRevealHostPassword();
  const preflight = useDeployPreflight();
  const precheck = usePrecheckHostKey();
  const trust = useTrustHostKey();
  const deploy = useDeployKeyDirect();
  const saveHost = useSaveHost();
  const queryClient = useQueryClient();

  // One advisory probe per dialog (the flow remounts per alias).
  const probe = preflight.mutate;
  useEffect(() => {
    probe({ alias });
  }, [probe, alias]);

  const askpassBlocked = preflight.data ? !preflight.data.askpassSupported : false;
  const keychainMissing = preflight.data ? !preflight.data.keychainAvailable : false;

  const deployable = (keysQ.data ?? []).filter((k) => k.public_path !== null);

  // Preselect once both sources have settled — seeding from keys alone would
  // lock in the single-key fallback before the host's IdentityFile arrives.
  useEffect(() => {
    if (publicPath !== "" || !keysQ.data) return;
    if (hygiene.isPending) return;
    const identityFiles = (hygiene.data?.identity_files ?? []).map((f) => f.path);
    const preset = pickDefaultPublicKey(identityFiles, keysQ.data);
    if (preset) setPublicPath(preset);
  }, [publicPath, keysQ.data, hygiene.isPending, hygiene.data]);

  const busy = precheck.isPending || trust.isPending || deploy.isPending;

  /** Write `IdentityFile <value>` to this host and reflect it on the result screen. */
  function writeIdentityFile(value: string) {
    saveHost.mutate(
      { alias, changes: [{ keyword: "IdentityFile", value, remove: false }] },
      {
        onSuccess: () => {
          setIdentityOffer(null);
          setIdentityNote(`IdentityFile ${value} written to the host config.`);
          queryClient.invalidateQueries({ queryKey: queryKeys.keyHygiene(alias) });
        },
        // Errors already toast via useSaveHost; the offer button stays usable.
      },
    );
  }

  async function runDeploy() {
    const outcome = await deploy.mutateAsync({
      alias,
      publicPath,
      password,
      remember: remember && !keychainMissing,
    });
    if (outcome.kind === "added" || outcome.kind === "alreadyPresent") {
      // The key is on the remote now — make sure ssh will actually offer it.
      const privateAbs = publicPath.replace(/\.pub$/, "");
      const value = toTildeSshPath(privateAbs);
      const existing = (hygiene.data?.identity_files ?? []).map((f) => f.path);
      switch (identityFileAction(existing, privateAbs)) {
        case "write":
          writeIdentityFile(value);
          break;
        case "already":
          setIdentityNote("The host config already points at this key.");
          break;
        case "offer":
          setIdentityOffer(value);
          break;
      }
    }
    setStage({ kind: "result", view: { kind: "outcome", outcome } });
  }

  async function handleDeploy() {
    try {
      const status = await precheck.mutateAsync({ alias });
      switch (status.kind) {
        case "trusted":
          await runDeploy();
          break;
        case "new":
          setStage({ kind: "hostkey", fingerprint: status.fingerprint });
          break;
        case "mismatch":
          setStage({
            kind: "result",
            view: { kind: "mismatch", fingerprint: status.fingerprint },
          });
          break;
        case "unavailable":
          setStage({
            kind: "result",
            view: { kind: "unavailable", message: status.message },
          });
          break;
      }
    } catch {
      // The mutation hooks already toast; stay where we are.
    }
  }

  // The backend re-scans and writes its own key line; we only pass along the
  // fingerprint the user actually confirmed, so a changed key aborts the trust.
  async function handleTrustAndContinue(fingerprint: string) {
    try {
      await trust.mutateAsync({ alias, fingerprint });
      await runDeploy();
    } catch {
      // Toasted by the hooks; keep the fingerprint on screen.
    }
  }

  if (stage.kind === "hostkey") {
    return (
      <>
        <DialogHeader>
          <DialogTitle>New host key</DialogTitle>
          <DialogDescription>
            <span className="font-mono">{alias}</span> is not in known_hosts
            yet. Continue only if this fingerprint matches the server&rsquo;s.
          </DialogDescription>
        </DialogHeader>
        <div className="rounded-md border bg-muted/40 p-3 font-mono text-xs break-all">
          {stage.fingerprint}
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => setStage({ kind: "form" })}
            disabled={busy}
          >
            Back
          </Button>
          <Button
            type="button"
            onClick={() => handleTrustAndContinue(stage.fingerprint)}
            disabled={busy}
          >
            {busy && <Loader2 className="size-4 animate-spin" />}
            Trust &amp; continue
          </Button>
        </DialogFooter>
      </>
    );
  }

  if (stage.kind === "result") {
    return (
      <ResultStage
        view={stage.view}
        identityNote={identityNote}
        identityOffer={identityOffer}
        identityWriting={saveHost.isPending}
        onWriteIdentity={writeIdentityFile}
        onRetry={() => setStage({ kind: "form" })}
        onClose={onClose}
      />
    );
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          Deploy key to <span className="font-mono">{alias}</span>
        </DialogTitle>
        <DialogDescription>
          Adds your public key to the host&rsquo;s{" "}
          <span className="font-mono">authorized_keys</span> — right from the
          app, no terminal needed.
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-4">
        {askpassBlocked && (
          <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            This machine&rsquo;s OpenSSH is older than 8.5 and cannot auto-fill
            the password. Use the terminal-based deploy from the Keys dialog
            instead.
          </p>
        )}
        {preflight.data?.passwordAuthBlocked && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
            This host&rsquo;s config sets{" "}
            <span className="font-mono">PreferredAuthentications</span> without
            password, so the password will never be used. Deploy will fail with
            &ldquo;Permission denied&rdquo;.
          </p>
        )}
        <div className="space-y-1.5">
          <Label htmlFor="deploy-key">Public key</Label>
          <Select value={publicPath} onValueChange={setPublicPath}>
            <SelectTrigger id="deploy-key" className="w-full">
              <SelectValue
                placeholder={
                  keysQ.isPending ? "Loading keys…" : "Choose a public key"
                }
              />
            </SelectTrigger>
            <SelectContent>
              {deployable.map((k) => (
                <SelectItem key={k.private_path} value={k.public_path ?? ""}>
                  <span className="font-mono">{k.name}.pub</span>
                  {k.key_type !== "unknown" && (
                    <span className="text-muted-foreground"> · {k.key_type}</span>
                  )}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {keysQ.isSuccess && deployable.length === 0 && (
            <p className="text-xs text-destructive">
              No deployable keys in ~/.ssh — generate one from the Keys dialog
              first.
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="deploy-password">SSH password</Label>
          <div className="flex gap-1.5">
            <Input
              id="deploy-password"
              type={revealed ? "text" : "password"}
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={`Password for ${alias}`}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label={revealed ? "Hide password" : "Show password"}
              onClick={() => setRevealed((r) => !r)}
            >
              {revealed ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </Button>
          </div>
          {hasPassword.data === true && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>A saved password exists for this host.</span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-6 px-2 text-xs"
                disabled={reveal.isPending}
                onClick={() =>
                  reveal.mutate(
                    { alias },
                    {
                      onSuccess: (pw) => {
                        if (pw !== null) setPassword(pw);
                      },
                    },
                  )
                }
              >
                {reveal.isPending && <Loader2 className="size-3 animate-spin" />}
                Load
              </Button>
            </div>
          )}
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            {/* Without a credential store nothing could actually be saved —
                a checkable box here would simply be lying to the user. */}
            <Checkbox
              id="deploy-remember"
              checked={keychainMissing ? false : remember}
              disabled={keychainMissing}
              onCheckedChange={(v) => setRemember(v === true)}
            />
            <Label htmlFor="deploy-remember" className="font-normal">
              Remember this host&rsquo;s password (stored in your keychain)
            </Label>
          </div>
          {keychainMissing && (
            <p className="text-xs text-muted-foreground">
              No credential store on this machine — the password will be used
              once and not saved.
            </p>
          )}
        </div>
      </div>

      <DialogFooter className="items-center gap-2 sm:justify-between">
        <p className="text-xs text-muted-foreground">
          ProxyJump hosts that also need a password are not supported.
        </p>
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={handleDeploy}
            disabled={busy || publicPath === "" || password === "" || askpassBlocked}
          >
            {busy && <Loader2 className="size-4 animate-spin" />}
            Deploy
          </Button>
        </div>
      </DialogFooter>
    </>
  );
}

function ResultStage({
  view,
  identityNote,
  identityOffer,
  identityWriting,
  onWriteIdentity,
  onRetry,
  onClose,
}: {
  view: ResultView;
  identityNote: string | null;
  identityOffer: string | null;
  identityWriting: boolean;
  onWriteIdentity: (value: string) => void;
  onRetry: () => void;
  onClose: () => void;
}) {
  if (view.kind === "mismatch") {
    return (
      <>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <ShieldAlert className="size-5 shrink-0" />
            Host key mismatch
          </DialogTitle>
          <DialogDescription>
            The server&rsquo;s key does not match the one saved in known_hosts.
            This can mean the host was reinstalled — or that something is
            intercepting the connection. Deployment was aborted; nothing was
            sent.
          </DialogDescription>
        </DialogHeader>
        <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 font-mono text-xs break-all">
          {view.fingerprint}
        </div>
        {/* Deliberately no way to continue past a mismatch. */}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </>
    );
  }

  if (view.kind === "unavailable") {
    return (
      <>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <TriangleAlert className="size-5 shrink-0 text-amber-600 dark:text-amber-400" />
            Could not check the host key
          </DialogTitle>
          <DialogDescription>{view.message}</DialogDescription>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Try the terminal-based deploy from the Keys dialog instead.
        </p>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onRetry}>
            Back
          </Button>
          <Button type="button" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </>
    );
  }

  const { outcome } = view;
  const text = OUTCOME_TEXT[outcome.kind];
  const detail = outcomeDetail(outcome);
  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2">
          {text.tone === "ok" ? (
            <CheckCircle2 className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
          ) : (
            <XCircle className="size-5 shrink-0 text-destructive" />
          )}
          {text.title}
        </DialogTitle>
        {detail && <DialogDescription>{detail}</DialogDescription>}
      </DialogHeader>
      {identityNote && (
        <p className="text-xs text-muted-foreground">{identityNote}</p>
      )}
      {identityOffer && (
        <div className="space-y-1.5 rounded-md border bg-muted/40 p-3">
          <p className="text-xs text-muted-foreground">
            This host&rsquo;s config points at a different IdentityFile. Switch
            it to the key you just deployed?
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={identityWriting}
            onClick={() => onWriteIdentity(identityOffer)}
          >
            {identityWriting && <Loader2 className="size-3.5 animate-spin" />}
            Use this key — IdentityFile{" "}
            <span className="font-mono">{identityOffer}</span>
          </Button>
        </div>
      )}
      <DialogFooter>
        {text.tone === "err" && (
          <Button type="button" variant="outline" onClick={onRetry}>
            Try again
          </Button>
        )}
        <Button type="button" onClick={onClose}>
          {text.tone === "ok" ? "Done" : "Close"}
        </Button>
      </DialogFooter>
    </>
  );
}
