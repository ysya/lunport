import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import {
  ArrowDownToLine,
  Check,
  CircleAlert,
  LoaderCircle,
  RotateCw,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Section,
  SettingsGroup,
  SettingsRow,
} from "@/components/settings-primitives";
import { UpdateProgress } from "@/components/UpdateProgress";
import { useIsDevelopment } from "@/lib/queries";
import { normalizeUpdateChannel } from "@/lib/settings-logic";
import {
  checkForUpdates,
  installAvailableUpdate,
  restartAfterUpdate,
  updateInProgress,
  useUpdaterState,
  type UpdaterState,
} from "@/lib/updater";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

export function openUpdates() {
  useUiStore.getState().setSettingsCategory("updates");
  useUiStore.getState().setSettingsOpen(true);
}

/** A quiet, persistent entry point for automatic discovery. Updating never opens a toast or window. */
export function UpdateIndicator() {
  const phase = useUpdaterState((state) => state.phase);
  if (phase !== "available" && !updateInProgress(phase)) return null;
  const active = phase === "installing" || phase === "restarting";
  const Icon = active
    ? LoaderCircle
    : phase === "restart_required"
      ? RotateCw
      : ArrowDownToLine;
  const label = active
    ? "Updating…"
    : phase === "restart_required"
      ? "Restart to finish"
      : "Update available";
  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-7 shrink-0 gap-1.5 text-xs text-primary"
      onClick={openUpdates}
      aria-label={`${label} — open updates`}
    >
      <Icon
        className={`size-3.5 ${active ? "motion-safe:animate-spin" : ""}`}
      />
      <span className="hidden sm:inline">{label}</span>
    </Button>
  );
}

export function UpdatesPane() {
  const state = useUpdaterState();
  const { data: development } = useIsDevelopment();
  const allowed = development === false;
  const [version, setVersion] = useState<string | null>(null);
  const channel = normalizeUpdateChannel(
    useSettingsStore((s) => s.updateChannel),
  );
  const setChannel = useSettingsStore((s) => s.setUpdateChannel);
  const automatic = useSettingsStore((s) => s.autoCheckUpdates);
  const setAutomatic = useSettingsStore((s) => s.setAutoCheckUpdates);
  useEffect(() => {
    let mounted = true;
    getVersion()
      .then((value) => {
        if (mounted) setVersion(value);
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <div className="grid size-11 shrink-0 place-items-center rounded-xl border bg-primary/5 text-primary">
          <Terminal className="size-5" />
        </div>
        <div>
          <h3 className="text-base font-semibold">SSHelter</h3>
          <p className="text-xs text-muted-foreground">
            {version
              ? `Installed version ${version}`
              : "Installed version unavailable"}
          </p>
        </div>
      </div>
      <UpdateStatusCard
        state={state}
        allowed={allowed}
        onCheck={() => void checkForUpdates({ silent: false })}
        onInstall={() => void installAvailableUpdate()}
        onRestart={() => void restartAfterUpdate()}
      />
      <Section title="Update preferences">
        <SettingsGroup>
          <SettingsRow id="set-update-channel" label="Release channel">
            <Select
              value={channel}
              disabled={!allowed || updateInProgress(state.phase)}
              onValueChange={(value) => {
                setChannel(normalizeUpdateChannel(value));
                void checkForUpdates({ silent: false });
              }}
            >
              <SelectTrigger id="set-update-channel" className="h-8 w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="stable">Stable</SelectItem>
                <SelectItem value="beta">Beta</SelectItem>
              </SelectContent>
            </Select>
          </SettingsRow>
          <SettingsRow
            id="set-auto-update"
            label="Check automatically"
            description="Check at launch and while SSHelter is running."
          >
            <Switch
              id="set-auto-update"
              disabled={!allowed}
              checked={allowed && automatic}
              onCheckedChange={setAutomatic}
            />
          </SettingsRow>
        </SettingsGroup>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
          Beta includes preview releases. Switching to Stable keeps your
          installed version until a newer stable release is available.
        </p>
      </Section>
    </div>
  );
}

export function UpdateStatusCard({
  state,
  allowed,
  onCheck,
  onInstall,
  onRestart,
}: {
  state: UpdaterState;
  allowed: boolean;
  onCheck: () => void;
  onInstall: () => void;
  onRestart: () => void;
}) {
  const { phase } = state;
  const active = updateInProgress(phase);
  const channel = state.channel === "beta" ? "Beta" : "Stable";
  const checking = phase === "checking";
  const Icon =
    checking || phase === "installing" || phase === "restarting"
      ? LoaderCircle
      : phase === "current"
        ? Check
        : phase === "error"
          ? CircleAlert
          : phase === "available"
            ? ArrowDownToLine
            : RotateCw;
  const title = !allowed
    ? "Updates are unavailable in development builds"
    : checking
      ? "Checking for updates…"
      : phase === "current"
        ? "You’re up to date"
        : phase === "available"
          ? `Version ${state.version} is available`
          : phase === "installing"
            ? (state.progress?.title ?? "Preparing update…")
            : phase === "restarting"
              ? "Update installed. Restarting…"
              : phase === "restart_required"
                ? "Restart to finish updating"
                : phase === "error"
                  ? state.errorStage === "install"
                    ? "Couldn’t install the update"
                    : "Couldn’t check for updates"
                  : "Check for a new version";
  return (
    <section
      aria-label="Software update"
      className="overflow-hidden rounded-xl border bg-muted/25"
    >
      <div className="space-y-3 p-4">
        <div className="flex items-start gap-2.5">
          <Icon
            aria-hidden="true"
            className={`mt-0.5 size-4 shrink-0 ${checking || phase === "installing" || phase === "restarting" ? "motion-safe:animate-spin" : phase === "current" ? "text-emerald-600 dark:text-emerald-400" : phase === "error" ? "text-destructive" : "text-primary"}`}
          />
          <div className="min-w-0 flex-1">
            <p role="status" className="text-sm font-medium leading-snug">
              {title}
            </p>
            {allowed && (
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {phase === "available"
                  ? "Installing restarts SSHelter and ends active SSH sessions."
                  : phase === "installing"
                    ? "You can close Settings and return to see the progress."
                    : phase === "restart_required"
                      ? "The update is installed. Restart SSHelter to use the new version."
                      : phase === "restarting"
                        ? "SSHelter will reopen shortly."
                        : phase === "error"
                          ? "Check your connection and try again."
                          : phase === "current"
                            ? `No newer release is available on the ${channel} channel.`
                            : `Looking for releases on the ${channel} channel.`}
              </p>
            )}
          </div>
        </div>
        {state.progress && phase === "installing" && (
          <UpdateProgress view={state.progress} />
        )}
        {state.error && (
          <p
            role="alert"
            className="break-words rounded-md bg-destructive/5 p-2.5 text-xs leading-relaxed text-destructive"
          >
            {state.error}
          </p>
        )}
        {allowed && !active && (
          <div className="flex flex-wrap items-center gap-2">
            {phase === "available" && (
              <Button size="sm" onClick={onInstall}>
                Install and restart
              </Button>
            )}
            <Button
              size="sm"
              variant={phase === "available" ? "outline" : "secondary"}
              disabled={checking}
              onClick={onCheck}
            >
              {checking
                ? "Checking…"
                : phase === "error"
                  ? "Try again"
                  : "Check for updates"}
            </Button>
          </div>
        )}
        {allowed && phase === "restart_required" && (
          <Button size="sm" onClick={onRestart}>
            Restart SSHelter
          </Button>
        )}
        {allowed && state.checkedAt && !checking && !active && (
          <p className="text-[11px] text-muted-foreground">
            Last checked{" "}
            {new Intl.DateTimeFormat(undefined, {
              hour: "numeric",
              minute: "2-digit",
            }).format(state.checkedAt)}{" "}
            · {channel}
          </p>
        )}
      </div>
      {phase === "available" && state.body?.trim() && (
        <details className="border-t px-4 py-3 text-xs">
          <summary className="cursor-pointer font-medium">
            What’s new in {state.version}
          </summary>
          <div className="mt-3 space-y-2 text-muted-foreground leading-relaxed">
            {state.body
              .split("\n")
              .filter((line) => line.trim())
              .map((line, index) => {
                const heading = /^#{1,6}\s/.test(line);
                return (
                  <p
                    key={index}
                    className={
                      heading ? "pt-1 font-medium text-foreground" : undefined
                    }
                  >
                    {line.replace(/^#{1,6}\s+/, "").replace(/^[-*]\s+/, "• ")}
                  </p>
                );
              })}
          </div>
        </details>
      )}
    </section>
  );
}
