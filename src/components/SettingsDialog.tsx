import { useEffect, useState } from "react";
import type { ComponentType, ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  FolderCog,
  Monitor,
  Moon,
  Settings2,
  SlidersHorizontal,
  Sun,
  SunMoon,
  TerminalSquare,
} from "lucide-react";

import { getVersion } from "@tauri-apps/api/app";
import {
  disable as autostartDisable,
  enable as autostartEnable,
  isEnabled as autostartIsEnabled,
} from "@tauri-apps/plugin-autostart";

import { useUiStore } from "@/stores/ui";
import { useSettingsStore } from "@/stores/settings";
import { useLoadConfig, usePlatform, useTerminals } from "@/lib/queries";
import { tauriInvoke } from "@/lib/ipc";
import { checkForUpdates } from "@/lib/updater";
import {
  exportSettings,
  pickSettingsImport,
  applySettingsImport,
  type SettingsEnvelope,
} from "@/lib/settings-io";
import {
  FONT_SIZE_OPTIONS,
  LINT_RULES,
  quickConnectLabel,
  terminalSupportsNewTab,
  type ThemePref,
} from "@/lib/settings-logic";
import { cn } from "@/lib/utils";

import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Section, SettingsGroup } from "@/components/settings-primitives";

/** Radix Select values must be non-empty; this sentinel round-trips to `null`. */
const TERMINAL_DEFAULT = "__default__";
/** Sentinel for "keep all backups" (backupRetention = null). */
const RETENTION_ALL = "__all__";

type CategoryId = "general" | "appearance" | "connection" | "files" | "advanced";

const CATEGORIES: { id: CategoryId; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "appearance", label: "Appearance", icon: SunMoon },
  { id: "connection", label: "Connection", icon: TerminalSquare },
  { id: "files", label: "Files & Backups", icon: FolderCog },
  { id: "advanced", label: "Advanced", icon: SlidersHorizontal },
];

/**
 * The Settings window (⌘,): a System-Settings-style sidebar + detail layout.
 * Preferences persist via `useSettingsStore` (zustand persist); the ones the
 * backend also needs (tray, close-to-tray, retention) are mirrored with
 * fire-and-forget invokes here and re-sent on launch by
 * `useSyncBackendSettings`. Open state lives in the UI store so the toolbar
 * gear, the ⌘K palette, and the ⌘, shortcut can all drive it.
 */
export function SettingsDialog() {
  const open = useUiStore((s) => s.settingsOpen);
  const setOpen = useUiStore((s) => s.setSettingsOpen);
  const [category, setCategory] = useState<CategoryId>("general");

  // Global ⌘, / Ctrl+, shortcut — the macOS-standard Preferences accelerator.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "," && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setOpen]);

  const active = CATEGORIES.find((c) => c.id === category) ?? CATEGORIES[0];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-2xl">
        <div className="flex h-[480px] max-h-[80vh]">
          {/* Sidebar — category list. */}
          <aside className="flex w-44 shrink-0 flex-col gap-0.5 border-r bg-muted/40 p-2">
            <DialogTitle className="px-2 pt-1 pb-2 text-sm font-semibold select-none">
              Settings
            </DialogTitle>
            <nav aria-label="Settings categories" className="flex flex-col gap-0.5">
              {CATEGORIES.map((c) => {
                const Icon = c.icon;
                const isActive = c.id === category;
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setCategory(c.id)}
                    aria-current={isActive ? "true" : undefined}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors select-none cursor-default",
                      "focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
                      isActive
                        ? "bg-primary/12 text-foreground"
                        : "text-muted-foreground hover:bg-muted/70 hover:text-foreground",
                    )}
                  >
                    <Icon className="size-4 shrink-0" />
                    {c.label}
                  </button>
                );
              })}
            </nav>
          </aside>

          {/* Detail pane — scrollable. */}
          <div className="flex min-w-0 flex-1 flex-col">
            <header className="shrink-0 border-b px-5 py-3 select-none">
              <h2 className="text-sm font-semibold">{active.label}</h2>
            </header>
            <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-4">
              {category === "general" && <GeneralPane />}
              {category === "appearance" && <AppearancePane />}
              {category === "connection" && <ConnectionPane />}
              {category === "files" && <FilesPane />}
              {category === "advanced" && <AdvancedPane />}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------------- */
/* Panes                                                                     */
/* ------------------------------------------------------------------------- */

function GeneralPane() {
  const trayVisible = useSettingsStore((s) => s.trayVisible);
  const setTrayVisible = useSettingsStore((s) => s.setTrayVisible);
  const closeToTray = useSettingsStore((s) => s.closeToTray);
  const setCloseToTray = useSettingsStore((s) => s.setCloseToTray);
  const globalHotkey = useSettingsStore((s) => s.globalHotkey);
  const setGlobalHotkey = useSettingsStore((s) => s.setGlobalHotkey);
  const autoCheckUpdates = useSettingsStore((s) => s.autoCheckUpdates);
  const setAutoCheckUpdates = useSettingsStore((s) => s.setAutoCheckUpdates);
  const platform = usePlatform();
  const [checking, setChecking] = useState(false);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  // Launch-at-login reflects the OS state (NOT a persisted flag): queried
  // fresh every time this pane mounts; null = still loading → switch disabled.
  const [launchAtLogin, setLaunchAtLogin] = useState<boolean | null>(null);
  // A validated-but-unconfirmed settings import (drives the overwrite AlertDialog).
  const [pendingImport, setPendingImport] = useState<SettingsEnvelope | null>(null);

  useEffect(() => {
    getVersion().then(setAppVersion).catch(() => setAppVersion(null));
    autostartIsEnabled()
      .then(setLaunchAtLogin)
      .catch((e) => {
        setLaunchAtLogin(null);
        console.warn("[settings] autostart state query failed:", e);
      });
  }, []);

  const onCheckNow = async () => {
    setChecking(true);
    try {
      await checkForUpdates({ silent: false });
    } finally {
      setChecking(false);
    }
  };

  const onTray = (visible: boolean) => {
    setTrayVisible(visible);
    tauriInvoke<void>("tray_set_visible", { visible }).catch((e) =>
      toast.error("Could not update menu bar icon", { description: String(e) }),
    );
  };
  const onCloseToTray = (enabled: boolean) => {
    setCloseToTray(enabled);
    tauriInvoke<void>("app_set_close_to_tray", { enabled }).catch((e) =>
      toast.error("Could not update close behavior", { description: String(e) }),
    );
  };

  // Optimistic toggle, then re-read the ACTUAL state — the OS is the source
  // of truth (the user can also flip this in System Settings → Login Items).
  const onLaunchAtLogin = async (enabled: boolean) => {
    const prev = launchAtLogin;
    setLaunchAtLogin(enabled);
    try {
      if (enabled) await autostartEnable();
      else await autostartDisable();
      setLaunchAtLogin(await autostartIsEnabled());
    } catch (e) {
      setLaunchAtLogin(prev);
      toast.error("Could not update launch at login", { description: String(e) });
    }
  };

  const onExport = async () => {
    try {
      const path = await exportSettings();
      if (path) toast.success("Settings exported", { description: path });
    } catch (e) {
      toast.error("Could not export settings", { description: String(e) });
    }
  };

  // Pick + validate first; the destructive overwrite waits for the AlertDialog.
  const onImport = async () => {
    try {
      const envelope = await pickSettingsImport();
      if (envelope) setPendingImport(envelope);
    } catch (e) {
      toast.error("Could not import settings", {
        description: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const confirmImport = async () => {
    const envelope = pendingImport;
    setPendingImport(null);
    if (!envelope) return;
    try {
      await applySettingsImport(envelope);
      toast.success("Settings imported");
    } catch (e) {
      toast.error("Could not apply imported settings", { description: String(e) });
    }
  };

  return (
    <>
      <Section title="Menu bar">
        <SettingsGroup>
          <SettingsRow id="set-tray" label="Show menu bar icon">
            <Switch id="set-tray" checked={trayVisible} onCheckedChange={onTray} />
          </SettingsRow>
          <SettingsRow
            id="set-close-to-tray"
            label="Keep running in menu bar when window closes"
          >
            <Switch
              id="set-close-to-tray"
              checked={closeToTray}
              onCheckedChange={onCloseToTray}
            />
          </SettingsRow>
          <SettingsRow
            id="set-launch-login"
            label="Launch at login"
            description="Reflects the system Login Items state."
          >
            <Switch
              id="set-launch-login"
              checked={launchAtLogin === true}
              disabled={launchAtLogin === null}
              onCheckedChange={onLaunchAtLogin}
            />
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Quick connect"
        description="Brings SSHelter to the front with the command palette open, from any app."
      >
        <SettingsGroup>
          <SettingsRow id="set-global-hotkey" label="Global quick-connect hotkey">
            <div className="flex items-center gap-2.5">
              <kbd className="rounded-sm border bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                {quickConnectLabel(platform.data)}
              </kbd>
              <Switch
                id="set-global-hotkey"
                checked={globalHotkey}
                onCheckedChange={setGlobalHotkey}
              />
            </div>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section title="Updates">
        <SettingsGroup>
          <SettingsRow
            id="set-auto-update"
            label="Check for updates automatically"
            description="Checks GitHub Releases shortly after launch."
          >
            <Switch
              id="set-auto-update"
              checked={autoCheckUpdates}
              onCheckedChange={setAutoCheckUpdates}
            />
          </SettingsRow>
          <SettingsRow
            label="Version"
            description={appVersion ? `SSHelter ${appVersion}` : undefined}
          >
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              onClick={onCheckNow}
              disabled={checking}
            >
              {checking ? "Checking…" : "Check now"}
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Language"
        description="More languages are planned. SSH keywords always stay in English."
      >
        <SettingsGroup>
          <SettingsRow label="Language">
            <Select value="en" disabled>
              <SelectTrigger className="h-7 w-[10rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="en">English</SelectItem>
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Data"
        description="Preferences only — your SSH config, keys, and hosts are never included."
      >
        <SettingsGroup>
          <SettingsRow
            label="Export settings"
            description="Save all preferences to a JSON file."
          >
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              onClick={onExport}
            >
              Export…
            </Button>
          </SettingsRow>
          <SettingsRow
            label="Import settings"
            description="Replace all preferences from a JSON file."
          >
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              onClick={onImport}
            >
              Import…
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      {/* Confirm-before-overwrite: the picked file is already validated. */}
      <AlertDialog
        open={pendingImport !== null}
        onOpenChange={(open) => {
          if (!open) setPendingImport(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Replace all settings?</AlertDialogTitle>
            <AlertDialogDescription>
              Importing replaces every SSHelter preference with the contents of
              the selected file. Your SSH config files are not affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmImport}>Import</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function AppearancePane() {
  const theme = useSettingsStore((s) => s.theme);
  const setTheme = useSettingsStore((s) => s.setTheme);
  const fontSize = useSettingsStore((s) => s.fontSize);
  const setFontSize = useSettingsStore((s) => s.setFontSize);
  return (
    <Section
      title="Appearance"
      description="“System” follows your OS light/dark preference. Text size scales the whole interface."
    >
      <SettingsGroup>
        <SettingsRow label="Theme">
          <ThemeSegmented value={theme} onChange={setTheme} />
        </SettingsRow>
        <SettingsRow id="set-font-size" label="Text size">
          <Select
            value={String(fontSize)}
            onValueChange={(v) => setFontSize(Number(v))}
          >
            <SelectTrigger id="set-font-size" className="h-7 w-[10rem] text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FONT_SIZE_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={String(o.value)}>
                  {o.label}
                  <span className="ml-1 font-mono text-xs text-muted-foreground">
                    {o.value}px
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
      </SettingsGroup>
    </Section>
  );
}

function ConnectionPane() {
  const terminalId = useSettingsStore((s) => s.terminalId);
  const setTerminalId = useSettingsStore((s) => s.setTerminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const setNewTabConnect = useSettingsStore((s) => s.setNewTabConnect);
  const terminals = useTerminals();

  const supportsNewTab = terminalSupportsNewTab(terminalId, terminals.data ?? []);

  return (
    <Section
      title="Connection"
      description="Where SSHelter opens a connection. “System default” uses your OS default terminal (or the first detected)."
    >
      <SettingsGroup>
        <SettingsRow label="Default terminal">
          <Select
            value={terminalId ?? TERMINAL_DEFAULT}
            onValueChange={(v) => setTerminalId(v === TERMINAL_DEFAULT ? null : v)}
          >
            <SelectTrigger className="h-7 w-[11rem] text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={TERMINAL_DEFAULT}>System default</SelectItem>
              {(terminals.data ?? []).map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow
          id="set-new-tab"
          label="Open connections in a new tab"
          description={
            supportsNewTab
              ? "Opens a tab in an existing window instead of a new window."
              : "The selected terminal doesn’t support opening new tabs."
          }
        >
          <Switch
            id="set-new-tab"
            checked={newTabConnect}
            onCheckedChange={setNewTabConnect}
            disabled={!supportsNewTab}
          />
        </SettingsRow>
      </SettingsGroup>
    </Section>
  );
}

function FilesPane() {
  const configPath = useSettingsStore((s) => s.configPath);
  const setConfigPath = useSettingsStore((s) => s.setConfigPath);
  const backupRetention = useSettingsStore((s) => s.backupRetention);
  const setBackupRetention = useSettingsStore((s) => s.setBackupRetention);

  const loadConfig = useLoadConfig();
  const queryClient = useQueryClient();

  const [draft, setDraft] = useState(configPath ?? "");
  useEffect(() => setDraft(configPath ?? ""), [configPath]);

  // Persist only on a SUCCESSFUL load so a broken path never sticks: on error
  // the old working document (and persisted path) stay intact and the
  // existing "Failed to load config" toast fires from useLoadConfig.
  const applyPath = () => {
    const next = draft.trim() === "" ? null : draft.trim();
    loadConfig.mutate(next, {
      onSuccess: () => {
        setConfigPath(next);
        queryClient.invalidateQueries({ queryKey: ["config"] });
        toast.success("Config loaded", {
          description: next ?? "~/.ssh/config",
        });
      },
    });
  };

  const onRetention = (v: string) => {
    const limit = v === RETENTION_ALL ? null : Number(v);
    setBackupRetention(limit);
    tauriInvoke<void>("config_set_backup_retention", { limit }).catch((e) =>
      toast.error("Could not update backup retention", { description: String(e) }),
    );
  };

  return (
    <>
      <Section
        title="Config file"
        description="The ssh_config file SSHelter edits. Leave empty for ~/.ssh/config."
      >
        <SettingsGroup>
          <div className="flex items-center gap-1.5 px-3 py-2">
            <Input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="~/.ssh/config"
              aria-label="Config file path"
              spellCheck={false}
              className="h-7 flex-1 border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
              onKeyDown={(e) => {
                if (e.key === "Enter") applyPath();
              }}
            />
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7 shrink-0"
              onClick={applyPath}
              disabled={loadConfig.isPending || (draft.trim() || "") === (configPath ?? "")}
            >
              {loadConfig.isPending ? "Loading…" : "Apply"}
            </Button>
          </div>
        </SettingsGroup>
      </Section>

      <Section
        title="Backups"
        description="A backup is written before every change. Older backups beyond the limit are pruned."
      >
        <SettingsGroup>
          <SettingsRow label="Backup retention">
            <Select
              value={backupRetention === null ? RETENTION_ALL : String(backupRetention)}
              onValueChange={onRetention}
            >
              <SelectTrigger className="h-7 w-[10rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">Keep last 10</SelectItem>
                <SelectItem value="20">Keep last 20</SelectItem>
                <SelectItem value="50">Keep last 50</SelectItem>
                <SelectItem value={RETENTION_ALL}>Keep all</SelectItem>
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>
    </>
  );
}

const DRIFT_INTERVALS = [15, 30, 60] as const;

function AdvancedPane() {
  const discoverKnownHosts = useSettingsStore((s) => s.discoverKnownHosts);
  const setDiscoverKnownHosts = useSettingsStore((s) => s.setDiscoverKnownHosts);
  const discoverTailscale = useSettingsStore((s) => s.discoverTailscale);
  const setDiscoverTailscale = useSettingsStore((s) => s.setDiscoverTailscale);
  const driftAutoCheck = useSettingsStore((s) => s.driftAutoCheck);
  const setDriftAutoCheck = useSettingsStore((s) => s.setDriftAutoCheck);
  const driftIntervalSec = useSettingsStore((s) => s.driftIntervalSec);
  const setDriftIntervalSec = useSettingsStore((s) => s.setDriftIntervalSec);
  const lintRules = useSettingsStore((s) => s.lintRules);
  const setLintRule = useSettingsStore((s) => s.setLintRule);

  return (
    <>
      <Section
        title="Discovery sources"
        description="Where the Discover dialog finds host candidates."
      >
        <SettingsGroup>
          <SettingsRow id="set-discover-kh" label="known_hosts" mono>
            <Switch
              id="set-discover-kh"
              checked={discoverKnownHosts}
              onCheckedChange={setDiscoverKnownHosts}
            />
          </SettingsRow>
          <SettingsRow id="set-discover-ts" label="Tailscale">
            <Switch
              id="set-discover-ts"
              checked={discoverTailscale}
              onCheckedChange={setDiscoverTailscale}
            />
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="External changes"
        description="SSHelter always re-checks when the window regains focus."
      >
        <SettingsGroup>
          <SettingsRow id="set-drift-auto" label="Check for external changes automatically">
            <Switch
              id="set-drift-auto"
              checked={driftAutoCheck}
              onCheckedChange={setDriftAutoCheck}
            />
          </SettingsRow>
          <SettingsRow label="Check every">
            <Select
              value={String(driftIntervalSec)}
              onValueChange={(v) => setDriftIntervalSec(Number(v))}
              disabled={!driftAutoCheck}
            >
              <SelectTrigger className="h-7 w-[8rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DRIFT_INTERVALS.map((sec) => (
                  <SelectItem key={sec} value={String(sec)}>
                    {sec} seconds
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Lint rules"
        description="Disabled rules are hidden from the lint report and the toolbar badge."
      >
        <SettingsGroup>
          {LINT_RULES.map((rule) => (
            <SettingsRow key={rule.id} id={`set-lint-${rule.id}`} label={rule.label}>
              <Switch
                id={`set-lint-${rule.id}`}
                checked={lintRules[rule.id] !== false}
                onCheckedChange={(v) => setLintRule(rule.id, v)}
              />
            </SettingsRow>
          ))}
        </SettingsGroup>
      </Section>
    </>
  );
}

/* ------------------------------------------------------------------------- */
/* Shared bits                                                               */
/* ------------------------------------------------------------------------- */

/**
 * A single settings row: label (plus optional muted description) on the left,
 * control on the right. `mono` renders the label in the mono face — for labels
 * that ARE technical values (e.g. `known_hosts`).
 */
function SettingsRow({
  id,
  label,
  description,
  mono,
  children,
}: {
  id?: string;
  label: string;
  description?: string;
  mono?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-9 items-center justify-between gap-4 px-3 py-2">
      <div className="min-w-0 space-y-0.5 select-none">
        <Label
          htmlFor={id}
          className={cn("text-sm font-normal", mono && "font-mono")}
        >
          {label}
        </Label>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="flex shrink-0 items-center">{children}</div>
    </div>
  );
}

const THEME_OPTIONS: { value: ThemePref; label: string; icon: typeof Sun }[] = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

/** A compact three-option segmented control for the theme preference. */
function ThemeSegmented({
  value,
  onChange,
}: {
  value: ThemePref;
  onChange: (theme: ThemePref) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className="flex items-center gap-0.5 rounded-md bg-muted p-0.5"
    >
      {THEME_OPTIONS.map((opt) => {
        const active = value === opt.value;
        const Icon = opt.icon;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.value)}
            className={cn(
              "flex items-center gap-1.5 rounded-[5px] px-2.5 py-1 text-sm transition-colors cursor-default",
              active
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="size-3.5" />
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export default SettingsDialog;
