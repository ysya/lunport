import { toast } from "sonner";

import type { AgentProblem } from "@/bindings/AgentProblem";
import type { MoveFailure } from "@/bindings/MoveFailure";
import { TONE_TEXT } from "@/components/sync-primitives";
import { Button } from "@/components/ui/button";
import { agentProblemText, useAgentProblem, useFixAgentInclude } from "@/lib/agent";
import { copyText } from "@/lib/clipboard";
import { plural } from "@/lib/format";
import { launchHintNeeded, moveBannerText, moveCount } from "@/lib/keychain";
import { useGitSshHint, useLaunchAtLogin, usePlatform, useTurnOnLaunchAtLogin } from "@/lib/queries";
import { useKeyMoveAllIntoVault, useSyncOverview } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

/** Why ssh can't reach SSHelter's agent (key vault spec §6, §11), with Fix when the Include line was removed. Exported for the tests. */
export function AgentProblemLine({ problem, busy, onFix }: { problem: AgentProblem; busy: boolean; onFix: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 px-1">
      {/* A failure reason can end with a long socket path: it wraps instead of pushing Fix out of the sidebar. */}
      <p className={cn("min-w-0 text-xs break-words", TONE_TEXT.error)}>{agentProblemText(problem)}</p>
      {problem.kind === "include_missing" && (
        <Button type="button" size="sm" variant="outline" className="h-7 shrink-0" disabled={busy} onClick={onFix}>
          Fix
        </Button>
      )}
    </div>
  );
}

const BANNER = "space-y-1.5 rounded-md border bg-muted/40 px-2 py-1.5";

/**
 * The banners above the Keychain's list (key vault spec §7.2), in this order and only when they apply: the agent's problem with
 * Fix (§6, §11), Move (§8), the launch hint (§5.7), the Windows Git hint (§10). No hooks: exported for the tests.
 */
export function KeychainBannersView({
  problem,
  movable,
  launchHint,
  gitHint,
  busy,
  onFix,
  onMove,
  onLaunch,
  onDismissLaunch,
  onCopyGit,
}: {
  problem: AgentProblem | null;
  /** How many keys are files for now. */
  movable: number;
  launchHint: boolean;
  gitHint: string | null;
  busy: boolean;
  onFix: () => void;
  onMove: () => void;
  onLaunch: () => void;
  onDismissLaunch: () => void;
  onCopyGit: () => void;
}) {
  if (problem === null && movable === 0 && !launchHint && gitHint === null) return null;
  return (
    <div className="shrink-0 space-y-2 border-b p-2">
      {problem && <AgentProblemLine problem={problem} busy={busy} onFix={onFix} />}
      {movable > 0 && (
        <div className="flex items-center justify-between gap-2 rounded-md border bg-muted/40 px-2 py-1.5">
          <p className="min-w-0 text-xs">{moveBannerText(movable)}</p>
          <Button type="button" size="sm" className="h-6 shrink-0 px-2 text-xs" disabled={busy} onClick={onMove}>
            Move
          </Button>
        </div>
      )}
      {launchHint && (
        <div className={BANNER}>
          <p className="text-xs">Keys in SSHelter work only while SSHelter is running.</p>
          <div className="flex flex-wrap gap-1">
            <Button type="button" size="sm" className="h-6 px-2 text-xs" disabled={busy} onClick={onLaunch}>
              Turn on launch at login
            </Button>
            <Button type="button" size="sm" variant="ghost" className="h-6 px-2 text-xs" onClick={onDismissLaunch}>
              Dismiss
            </Button>
          </div>
        </div>
      )}
      {gitHint !== null && (
        <div className={BANNER}>
          <p className="text-xs">{"Git for Windows uses its own ssh, which can't reach SSHelter's agent. Run this once:"}</p>
          <code className="block font-mono text-[0.6875rem] break-all">{gitHint}</code>
          <Button type="button" size="sm" variant="outline" className="h-6 px-2 text-xs" onClick={onCopyGit}>
            Copy
          </Button>
        </div>
      )}
    </div>
  );
}

/** This computer's banners: the store's part. A server render reads a store's initial state, so the tests use `KeychainBannersFor`. */
export function KeychainBanners() {
  const dismissed = useUiStore((s) => s.launchHintDismissed);
  const dismissLaunchHint = useUiStore((s) => s.dismissLaunchHint);
  const setMoveFailures = useUiStore((s) => s.setMoveFailures);
  const closeToTray = useSettingsStore((s) => s.closeToTray);
  return <KeychainBannersFor dismissed={dismissed} closeToTray={closeToTray} onDismissLaunch={dismissLaunchHint} onMoveFailures={setMoveFailures} />;
}

/** The banners with the data and the actions they need. Exported for the tests. */
export function KeychainBannersFor({
  dismissed,
  closeToTray,
  onDismissLaunch,
  onMoveFailures,
}: {
  dismissed: boolean;
  closeToTray: boolean;
  onDismissLaunch: () => void;
  onMoveFailures: (failures: MoveFailure[]) => void;
}) {
  const overview = useSyncOverview();
  // Not only while joined: keys kept in SSHelter after leaving the account still need the agent, launch at login and Move.
  const slots = overview.data?.key_slots ?? [];
  const anyInVault = slots.some((s) => s.in_vault);
  // SSHelter's agent matters only once a key is in SSHelter: nothing is asked before.
  const problemQuery = useAgentProblem(anyInVault);
  const fix = useFixAgentInclude();
  const move = useKeyMoveAllIntoVault();
  const launchAtLogin = useLaunchAtLogin(anyInVault && !dismissed);
  const turnOn = useTurnOnLaunchAtLogin();
  const platform = usePlatform();
  const windows = platform.data === "windows";
  const gitHintQuery = useGitSshHint(anyInVault && windows);
  const gitHint = anyInVault && windows ? (gitHintQuery.data ?? null) : null;
  const busy = fix.isPending || move.isPending || turnOn.isPending;
  const runMove = () =>
    move.mutate(undefined, {
      onSuccess: ({ failed }) => {
        onMoveFailures(failed);
        if (failed.length === 0) toast.success("Moved into SSHelter");
        else
          toast.error(`${plural(failed.length, "key")} couldn't move into SSHelter`, {
            description: failed.map((f) => `${revealHidden(f.name)}: ${revealHidden(f.message)}`).join("\n"),
          });
      },
    });
  const copyGitHint = async () => {
    if (gitHint === null) return;
    try {
      await copyText(gitHint);
      toast.success("Copied");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };
  return (
    <KeychainBannersView
      problem={anyInVault ? (problemQuery.data ?? null) : null}
      movable={moveCount(slots)}
      launchHint={launchHintNeeded({ anyInVault, launchAtLogin: launchAtLogin.data ?? null, closeToTray, dismissed })}
      gitHint={gitHint}
      busy={busy}
      onFix={() => fix.mutate()}
      onMove={runMove}
      onLaunch={() =>
        turnOn.mutate(undefined, {
          onSuccess: () => toast.success("SSHelter now opens at login and keeps running in the menu bar when its window closes."),
        })
      }
      onDismissLaunch={onDismissLaunch}
      onCopyGit={() => void copyGitHint()}
    />
  );
}
